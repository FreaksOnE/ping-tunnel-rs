use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use etherparse::Icmpv4Slice;
use etherparse::Ipv4HeaderSlice;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tun_rs::IDEAL_BATCH_SIZE;

use super::EchoMeta;
use crate::error::TransportError;

/// Largest datagram a raw IPv4 socket can deliver: the maximum IPv4 packet of
/// 65,535 bytes (header included, since raw sockets deliver the whole packet).
const READ_SCRATCH_LEN: usize = 65_535;

/// Raw ICMP socket receiver that filters by ICMP type.
///
/// Incoming packets are filtered in userspace by ICMP type only; the echo
/// identifier is reported to the caller ([`EchoMeta`]) instead of matched,
/// because NAT gateways rewrite it in transit (it is ICMP's port equivalent).
/// Stray traffic is discarded later, by the encrypted packet layers.
#[derive(Debug)]
pub struct IcmpReceiver {
    socket: Arc<AsyncFd<Socket>>,
    icmp_type: u8, // TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST
    outer_mtu: u16,
    /// Read scratch, allocated once and reused by [`IcmpReceiver::recv_many`].
    scratch: BytesMut,
}

impl IcmpReceiver {
    pub fn new(
        socket: Arc<AsyncFd<Socket>>,
        icmp_type: u8,
        outer_mtu: u16,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            socket,
            icmp_type,
            outer_mtu,
            scratch: BytesMut::zeroed(READ_SCRATCH_LEN),
        })
    }
}

/// Extracts the ICMP echo payload and header fields from one raw IPv4 datagram.
///
/// Returns the payload together with the echo identifier/sequence when the
/// IPv4 and ICMP headers parse, the ICMP type matches, and the payload is
/// non-empty. The identifier is reported, not matched: NAT gateways rewrite it
/// in transit, so filtering on the configured value would drop every packet
/// that crosses a NAT. Every rejection is logged at trace level and yields
/// `None`.
fn parse_echo(data: &[u8], expected_type: u8) -> Option<(&[u8], EchoMeta)> {
    let ip_slice = match Ipv4HeaderSlice::from_slice(data) {
        Ok(s) => s,
        Err(e) => {
            tracing::trace!(error = %e, "failed to parse IPv4 header, skipping");
            return None;
        }
    };

    let icmp_data = &data[ip_slice.slice().len()..];

    let icmp_slice = match Icmpv4Slice::from_slice(icmp_data) {
        Ok(s) => s,
        Err(e) => {
            tracing::trace!(error = %e, "failed to parse ICMP header, skipping");
            return None;
        }
    };

    if icmp_slice.type_u8() != expected_type {
        tracing::trace!(
            expected = expected_type,
            got = icmp_slice.type_u8(),
            "unexpected ICMP type, skipping"
        );
        return None;
    }

    let b5to8 = icmp_slice.bytes5to8();
    let meta = EchoMeta {
        id: u16::from_be_bytes([b5to8[0], b5to8[1]]),
        seq: u16::from_be_bytes([b5to8[2], b5to8[3]]),
    };

    let payload = icmp_slice.payload();
    if payload.is_empty() {
        tracing::trace!("ICMP echo packet with empty payload, skipping");
        return None;
    }

    Some((payload, meta))
}

impl IcmpReceiver {
    pub async fn recv(
        &mut self,
    ) -> Result<(BytesMut, Ipv4Addr, EchoMeta), TransportError> {
        // Heap buffers allocated once per call and reused for every skipped
        // datagram; the kernel can deliver a datagram of any size and nothing
        // is dropped or truncated for size.
        let mut scratch = BytesMut::zeroed(READ_SCRATCH_LEN);
        let mut output = BytesMut::zeroed(self.outer_mtu as usize);

        loop {
            let (n_bytes, src_addr) = self
                .socket
                .async_io(tokio::io::Interest::READABLE, |sock| {
                    // `peek_sender` + `read` receives a full datagram of any
                    // size into a plain `&mut [u8]`: socket2's `recv_from` only
                    // accepts an uninitialized-buffer slice parameter, which
                    // this module deliberately never deals in.
                    let src_addr = sock.peek_sender()?;
                    let mut reader: &Socket = sock;
                    let n_bytes = reader.read(&mut scratch[..])?;
                    Ok((n_bytes, src_addr))
                })
                .await
                .map_err(TransportError::Recv)?;

            let (payload, meta) =
                match parse_echo(&scratch[..n_bytes], self.icmp_type) {
                    Some(parsed) => parsed,
                    None => continue,
                };

            let src_ip = match src_addr.as_socket_ipv4() {
                Some(addr) => *addr.ip(),
                None => {
                    tracing::trace!(
                        "received IPv6 packet on IPv4 socket, skipping"
                    );
                    continue;
                }
            };

            output.clear();
            output.extend_from_slice(payload);
            return Ok((output, src_ip, meta));
        }
    }

    /// Drains parsed datagrams into `out`, one readiness wakeup per call.
    ///
    /// With the `AsyncFd` readiness guard held, `recv_many` runs until it
    /// returns `WouldBlock` (socket drained) or [`IDEAL_BATCH_SIZE`] datagrams
    /// have been read: N syscalls per wakeup instead of one wakeup + one
    /// syscall per datagram. Parse failures and non-IPv4 sources are skipped
    /// inside the batch and do not consume its budget beyond the read itself.
    ///
    /// `out` is appended to (callers clear it between batches). Each returned
    /// payload owns a fresh buffer because it moves into the caller's channel;
    /// the read scratch is reused across batches. Read errors are returned to
    /// the caller, which logs and continues.
    pub async fn recv_many(
        &mut self,
        out: &mut Vec<(BytesMut, Ipv4Addr, EchoMeta)>,
    ) -> Result<(), TransportError> {
        let scratch = &mut self.scratch;
        let mut guard =
            self.socket.readable().await.map_err(TransportError::Recv)?;

        let mut drained = 0usize;
        while drained < IDEAL_BATCH_SIZE {
            let received = guard.try_io(|sock| {
                // `peek_sender` + `read` receives a full datagram of any
                // size into a plain `&mut [u8]` (see `recv` for why).
                let sock = sock.get_ref();
                let src_addr = sock.peek_sender()?;
                let mut reader: &Socket = sock;
                let n_bytes = reader.read(&mut scratch[..])?;
                Ok((n_bytes, src_addr))
            });

            let (n_bytes, src_addr) = match received {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(TransportError::Recv(e)),
                // WouldBlock: this readiness event is fully drained.
                Err(_would_block) => break,
            };
            drained += 1;

            let (payload, meta) =
                match parse_echo(&scratch[..n_bytes], self.icmp_type) {
                    Some(parsed) => parsed,
                    None => continue,
                };

            let src_ip = match src_addr.as_socket_ipv4() {
                Some(addr) => *addr.ip(),
                None => {
                    tracing::trace!(
                        "received IPv6 packet on IPv4 socket, skipping"
                    );
                    continue;
                }
            };

            out.push((BytesMut::from(payload), src_ip, meta));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use etherparse::PacketBuilder;
    use etherparse::icmpv4::TYPE_ECHO_REQUEST;

    fn echo_request(identifier: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
            .icmpv4_echo_request(identifier, 1);
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    #[test]
    fn test_buffer_zeroed_has_correct_len() {
        let buf = BytesMut::zeroed(1500);
        assert_eq!(buf.len(), 1500);
    }

    #[test]
    fn test_extend_from_slice_works() {
        let mut buf = BytesMut::zeroed(10);
        let data = [1u8, 2, 3, 4, 5];
        buf.clear();
        buf.extend_from_slice(&data);
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[..], &[1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_echo_valid() {
        let packet = echo_request(0xBEEF, b"abc");
        let (payload, meta) =
            parse_echo(&packet, TYPE_ECHO_REQUEST).expect("parsed");
        assert_eq!(payload, &b"abc"[..]);
        assert_eq!(meta.id, 0xBEEF);
        assert_eq!(meta.seq, 1);
    }

    #[test]
    fn test_parse_echo_reports_a_rewritten_identifier() {
        // NAT gateways rewrite the echo identifier in transit (it is ICMP's
        // port equivalent); the receiver must report what arrived instead of
        // filtering on the configured value, or NATed peers become unreachable.
        let packet = echo_request(0xA959, b"abc");
        let (payload, meta) =
            parse_echo(&packet, TYPE_ECHO_REQUEST).expect("parsed");
        assert_eq!(payload, &b"abc"[..]);
        assert_eq!(meta.id, 0xA959);
        assert_eq!(meta.seq, 1);
    }

    #[test]
    fn test_parse_echo_rejects_truncated() {
        let packet = echo_request(0xBEEF, b"abc");
        assert_eq!(parse_echo(&packet[..12], TYPE_ECHO_REQUEST), None);
    }
}
