use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::Arc;

use bytes::BytesMut;
use etherparse::PacketBuilder;
use etherparse::icmpv4::TYPE_ECHO_REPLY;
use socket2::SockAddr;
use socket2::Socket;
use tokio::io::unix::AsyncFd;

use super::EchoMeta;
use crate::constants::DEFAULT_TTL;
use crate::error::TransportError;

#[derive(Debug)]
pub struct IcmpSender {
    local_ip: Ipv4Addr,
    identifier: u16,
    icmp_type: u8, // TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST
    socket: Arc<AsyncFd<Socket>>,
}

impl IcmpSender {
    pub fn new(
        local_ip: Ipv4Addr,
        identifier: u16,
        icmp_type: u8,
        socket: Arc<AsyncFd<Socket>>,
    ) -> Result<Self, TransportError> {
        tracing::debug!(
            local_ip = %local_ip,
            identifier = format_args!("{:#06x}", identifier),
            ?icmp_type,
            "created ICMP sender"
        );

        Ok(Self { local_ip, identifier, icmp_type, socket })
    }
}

impl IcmpSender {
    /// Sends with the configured identifier and a fresh random sequence.
    pub async fn send(
        &self,
        dest_ip: Ipv4Addr,
        payload: &BytesMut,
    ) -> Result<(), TransportError> {
        self.send_as(
            dest_ip,
            EchoMeta { id: self.identifier, seq: fastrand::u16(..=u16::MAX) },
            payload,
        )
        .await
    }

    /// Sends with an explicit echo identifier and sequence.
    ///
    /// Replies must reuse the identifier and sequence of the datagram that
    /// prompted them (see [`EchoMeta`]): NAT gateways route ICMP by identifier,
    /// so a reply carrying any other one is dropped before it reaches the peer.
    pub async fn send_as(
        &self,
        dest_ip: Ipv4Addr,
        meta: EchoMeta,
        payload: &BytesMut,
    ) -> Result<(), TransportError> {
        let ip_builder = PacketBuilder::ipv4(
            self.local_ip.octets(),
            dest_ip.octets(),
            DEFAULT_TTL,
        );
        // Build the role-correct ICMP echo type: the client sends echo requests and the
        // server sends echo replies, so the packet type follows the transport role.
        let builder = if self.icmp_type == TYPE_ECHO_REPLY {
            ip_builder.icmpv4_echo_reply(meta.id, meta.seq)
        } else {
            ip_builder.icmpv4_echo_request(meta.id, meta.seq)
        };

        // get some memory to store the result
        let capacity = builder.size(payload.len());
        let mut buf = BytesMut::zeroed(capacity);

        {
            let mut writer: &mut [u8] = &mut buf[..];
            builder.write(&mut writer, payload).map_err(|_| {
                TransportError::Send(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "header write failed",
                ))
            })?;
        }

        self.socket
            .async_io(tokio::io::Interest::WRITABLE, |sock| {
                let dest_addr = SockAddr::from(SocketAddrV4::new(dest_ip, 0));
                sock.send_to(&buf[..], &dest_addr).map(|_| ())
            })
            .await
            .map_err(TransportError::Send)
    }
}
