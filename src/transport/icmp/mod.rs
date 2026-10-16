use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::Arc;

use anyhow::Result;
use bytes::BytesMut;
use etherparse::icmpv4::TYPE_ECHO_REPLY;
use etherparse::icmpv4::TYPE_ECHO_REQUEST;
use socket2::Domain;
use socket2::Protocol;
use socket2::SockAddr;
use socket2::Socket;
use socket2::Type;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tun_rs::IDEAL_BATCH_SIZE;

use self::receive::IcmpReceiver;
use self::send::IcmpSender;
use crate::auth;
use crate::constants::CLIENT_ID_BYTES;
use crate::constants::RECV_SOCKET_BUFFER_SIZE;
use crate::constants::SEND_SOCKET_BUFFER_SIZE;
use crate::crypto;
use crate::error::EncryptionError;
use crate::error::TransportError;

pub mod receive;
pub mod send;

pub struct IcmpTransport {
    pub listen_ip: Ipv4Addr,
    pub icmp_identifier: u16,
    pub outer_mtu: u16,
    send_type: u8,
    recv_type: u8,
}

impl IcmpTransport {
    /// Client role: sends echo requests and receives echo replies.
    pub fn client(
        listen_ip: Ipv4Addr,
        icmp_identifier: u16,
        outer_mtu: u16,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            listen_ip,
            icmp_identifier,
            outer_mtu,
            send_type: TYPE_ECHO_REQUEST,
            recv_type: TYPE_ECHO_REPLY,
        })
    }

    /// Server role: sends echo replies and receives echo requests.
    pub fn server(
        listen_ip: Ipv4Addr,
        icmp_identifier: u16,
        outer_mtu: u16,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            listen_ip,
            icmp_identifier,
            outer_mtu,
            send_type: TYPE_ECHO_REPLY,
            recv_type: TYPE_ECHO_REQUEST,
        })
    }

    pub fn setup(&self) -> Result<(IcmpSender, IcmpReceiver)> {
        let socket =
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(TransportError::SocketCreate)?;

        socket.set_nonblocking(true).map_err(TransportError::SocketCreate)?;

        socket
            .bind(&SockAddr::from(SocketAddrV4::new(self.listen_ip, 0)))
            .map_err(TransportError::SocketCreate)?;

        // Without IP_HDRINCL the kernel prepends its own IPv4 header to our
        // userspace-built one, producing a double-header wire format peers cannot parse.
        socket
            .set_header_included_v4(true)
            .map_err(TransportError::SocketCreate)?;

        if let Err(e) = socket.set_recv_buffer_size(RECV_SOCKET_BUFFER_SIZE) {
            tracing::warn!(
                error = %e,
                size = RECV_SOCKET_BUFFER_SIZE,
                "SO_RCVBUF failed; keeping OS default"
            );
        }
        if let Err(e) = socket.set_send_buffer_size(SEND_SOCKET_BUFFER_SIZE) {
            tracing::warn!(
                error = %e,
                size = SEND_SOCKET_BUFFER_SIZE,
                "SO_SNDBUF failed; keeping OS default"
            );
        }

        let socket_fd = Arc::new(
            AsyncFd::new(socket).map_err(TransportError::SocketCreate)?,
        );

        let icmp_sender = IcmpSender::new(
            self.listen_ip,
            self.icmp_identifier,
            self.send_type,
            Arc::clone(&socket_fd),
        )?;

        let icmp_receiver = IcmpReceiver::new(
            socket_fd,
            self.icmp_identifier,
            self.recv_type,
            self.outer_mtu,
        )?;

        Ok((icmp_sender, icmp_receiver))
    }
}

/// Seals `payload` for the wire as `[client_id:16][nonce][ciphertext][tag]`.
///
/// The `client_id` is a plaintext prefix (for O(1) server-side routing); only the
/// payload is encrypted.
pub fn seal_payload(
    payload: &[u8],
    key: &[u8; 32],
    client_id: [u8; 16],
) -> Result<BytesMut, EncryptionError> {
    let mut enc = BytesMut::with_capacity(payload.len());
    enc.extend_from_slice(payload);
    crypto::encrypt_in_place(&mut enc, key)?;

    let mut packet = BytesMut::with_capacity(CLIENT_ID_BYTES + enc.len());
    packet.extend_from_slice(&client_id);
    packet.extend_from_slice(&enc);
    Ok(packet)
}

/// Opens a `[client_id:16][nonce][ciphertext][tag]` packet, returning the inner payload.
///
/// Validates the plaintext client-id prefix against `expected_client_id` when `Some`,
/// strips it, then decrypts the remainder. Errors if the packet is malformed or the
/// client-id prefix does not match.
pub fn open_packet(
    buf: &mut BytesMut,
    key: &[u8; 32],
    expected_client_id: Option<[u8; 16]>,
) -> Result<BytesMut, EncryptionError> {
    if buf.len() < CLIENT_ID_BYTES {
        return Err(EncryptionError::DecryptionFailed);
    }
    if let Some(expected) = expected_client_id
        && buf[..CLIENT_ID_BYTES] != expected[..]
    {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Strip the plaintext client-id prefix, then decrypt [nonce][ciphertext][tag].
    let mut rest = buf.split_off(CLIENT_ID_BYTES);
    crypto::decrypt_in_place(&mut rest, key)?;
    Ok(rest)
}

/// One datagram as decoded by a client's data path.
#[derive(Debug)]
pub enum Inbound {
    Data(BytesMut),
    SessionExpired,
}

/// Decodes one datagram received on a client's data path.
///
/// A data packet carries the client id in the clear as its first 16 bytes, so a
/// datagram with the expected prefix is opened with the session key;
/// `expected_client_id` of `None` accepts any prefix (unencrypted fallback used
/// only by tests).
///
/// Anything else is a server control frame: when the server drops a session it
/// answers that client's traffic with an encrypted session-expiry notice, which
/// only the holder of the session key can read - that is the cue to
/// re-authenticate.
///
/// # Errors
///
/// Returns the decrypt/parse error for foreign or undecryptable traffic (also for
/// a well-formed auth response arriving outside the handshake); the caller drops
/// the datagram.
pub fn decode_inbound(
    buf: &mut BytesMut,
    key: &[u8; 32],
    expected_client_id: Option<[u8; 16]>,
) -> Result<Inbound, EncryptionError> {
    let is_data = match expected_client_id {
        Some(expected) => {
            buf.len() >= CLIENT_ID_BYTES
                && buf[..CLIENT_ID_BYTES] == expected[..]
        }
        None => true,
    };

    if is_data {
        return open_packet(buf, key, expected_client_id).map(Inbound::Data);
    }

    match auth::parse_auth_response(buf, key) {
        Err(EncryptionError::SessionExpired) => Ok(Inbound::SessionExpired),
        // Everything else belongs to the handshake and is noise here: a tun-octet
        // response, or a credentials reject the server sent for a bad auth request.
        Ok(_) | Err(EncryptionError::AuthRejected) => {
            Err(EncryptionError::DecryptionFailed)
        }
        Err(e) => Err(e),
    }
}

/// Why [`icmp_to_channel`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpReceiveEnd {
    /// The channel to the consumer closed: the pipeline is shutting down.
    ChannelClosed,
    /// The server dropped the session: the client must re-authenticate.
    SessionExpired,
}

/// Receives ICMP datagrams and forwards their inner payloads into `channel`.
///
/// Receives in batches: one socket-readiness wakeup drains up to
/// [`tun_rs::IDEAL_BATCH_SIZE`] datagrams (see [`IcmpReceiver::recv_many`]) and
/// each parsed payload is forwarded into the channel. When `session_key` is
/// present the datagrams are decoded by [`decode_inbound`]; a `None` key is the
/// unencrypted fallback used only by tests. Undecodable datagrams are logged and
/// dropped. A closed channel ends the loop with [`IcmpReceiveEnd::ChannelClosed`],
/// and the server's session-drop notice with [`IcmpReceiveEnd::SessionExpired`].
pub async fn icmp_to_channel(
    mut receiver: IcmpReceiver,
    channel: Sender<(Ipv4Addr, BytesMut)>,
    session_key: Option<Arc<[u8; 32]>>,
    expected_client_id: Option<[u8; 16]>,
) -> IcmpReceiveEnd {
    // Batch buffer reused across wakeups.
    let mut batch: Vec<(BytesMut, Ipv4Addr)> =
        Vec::with_capacity(IDEAL_BATCH_SIZE);

    loop {
        batch.clear();
        if let Err(e) = receiver.recv_many(&mut batch).await {
            tracing::warn!(error = %e, "icmp receive failed");
            continue;
        }

        // Drain-batch forward: every parsed payload of this wakeup goes into
        // the channel; failures drop just that datagram.
        for (mut buf, src_addr) in batch.drain(..) {
            let inner = if let Some(key) = session_key.as_ref() {
                match decode_inbound(&mut buf, key.as_ref(), expected_client_id)
                {
                    Ok(Inbound::Data(inner)) => inner,
                    Ok(Inbound::SessionExpired) => {
                        return IcmpReceiveEnd::SessionExpired;
                    }
                    Err(e) => {
                        tracing::trace!(error = %e, "dropping undecryptable icmp packet");
                        continue;
                    }
                }
            } else {
                buf
            };

            if channel.send((src_addr, inner)).await.is_err() {
                return IcmpReceiveEnd::ChannelClosed;
            }
        }
    }
}

/// Seals payloads from `channel` and sends them as ICMP datagrams.
///
/// When `session_key` is present each payload is sealed with the `client_id` prefix and
/// encrypted; a `None` key is the unencrypted fallback used only by tests. Seal/send
/// failures are logged and the packet dropped.
pub async fn channel_to_icmp(
    mut channel: Receiver<(Ipv4Addr, BytesMut)>,
    sender: IcmpSender,
    session_key: Option<Arc<[u8; 32]>>,
    client_id: [u8; 16],
) {
    while let Some((dest_addr, payload)) = channel.recv().await {
        let packet = if let Some(key) = session_key.as_ref() {
            match seal_payload(&payload, key.as_ref(), client_id) {
                Ok(p) => p,
                Err(e) => {
                    tracing::trace!(error = %e, "dropping unsealable icmp packet");
                    continue;
                }
            }
        } else {
            payload
        };

        if let Err(e) = sender.send(dest_addr, &packet).await {
            tracing::warn!(error = %e, "icmp send failed");
            continue;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const CLIENT: [u8; 16] = [0xAA; 16];

    #[test]
    fn test_seal_open_roundtrip() {
        let payload = b"inner packet payload".to_vec();
        let mut packet = seal_payload(&payload, &KEY, CLIENT).unwrap();
        let inner = open_packet(&mut packet, &KEY, Some(CLIENT)).unwrap();
        assert_eq!(&inner[..], &payload[..]);
    }

    #[test]
    fn test_decode_inbound_data() {
        let payload = b"inner packet payload".to_vec();
        let mut packet = seal_payload(&payload, &KEY, CLIENT).unwrap();

        match decode_inbound(&mut packet, &KEY, Some(CLIENT)) {
            Ok(Inbound::Data(inner)) => assert_eq!(&inner[..], &payload[..]),
            other => panic!("expected data, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_inbound_session_expiry_notice() {
        // The server's session-expiry notice carries no client-id prefix, so it is
        // not opened as data; decrypting it means "re-authenticate".
        let mut notice = auth::build_session_expired(&KEY).unwrap();
        assert!(matches!(
            decode_inbound(&mut notice, &KEY, Some(CLIENT)),
            Ok(Inbound::SessionExpired)
        ));
    }

    #[test]
    fn test_decode_inbound_foreign_and_handshake_frames_are_dropped() {
        // Another client's data packet.
        let mut foreign = seal_payload(b"payload", &KEY, [0xBB; 16]).unwrap();
        assert!(decode_inbound(&mut foreign, &KEY, Some(CLIENT)).is_err());

        // A credentials reject belongs to the handshake, not to the data path.
        let mut reject = auth::build_auth_reject(&KEY).unwrap();
        assert!(decode_inbound(&mut reject, &KEY, Some(CLIENT)).is_err());

        // A granted tun octet outside the handshake is not data either.
        let mut response = auth::build_auth_response(&KEY, 7).unwrap();
        assert!(decode_inbound(&mut response, &KEY, Some(CLIENT)).is_err());

        // A notice encrypted for another key cannot be read.
        let mut foreign_notice =
            auth::build_session_expired(&[0x77; 32]).unwrap();
        assert!(
            decode_inbound(&mut foreign_notice, &KEY, Some(CLIENT)).is_err()
        );
    }

    #[test]
    fn test_open_wrong_key_errors() {
        let payload = b"payload".to_vec();
        let mut packet = seal_payload(&payload, &KEY, CLIENT).unwrap();
        let wrong_key = [0x43; 32];
        assert!(open_packet(&mut packet, &wrong_key, Some(CLIENT)).is_err());
    }

    #[test]
    fn test_open_wrong_client_errors() {
        let payload = b"payload".to_vec();
        let mut packet = seal_payload(&payload, &KEY, CLIENT).unwrap();
        let other_client = [0xBB; 16];
        assert!(open_packet(&mut packet, &KEY, Some(other_client)).is_err());
    }

    #[test]
    fn test_seal_prefix_is_plaintext_client_id() {
        let payload = b"payload".to_vec();
        let packet = seal_payload(&payload, &KEY, CLIENT).unwrap();
        // The client id sits in the clear at the head of the packet for routing.
        assert_eq!(&packet[..CLIENT_ID_BYTES], &CLIENT[..]);
    }
}
