use std::net::Ipv4Addr;
use std::time::Duration;

pub const IPV4_HEADER_LEN: usize = 20;

pub const ICMP_HEADER_LEN: usize = 8;

/// Overhead due to chacha20poly1305 authentication tag
pub const CHACHA20POLY1305_AUTH_OVERHEAD: usize = 16;

pub const CHACHA20_NONCE_SIZE: usize = 12;

/// size of client id in bytes
pub const CLIENT_ID_BYTES: usize = 16;

/// Magic marker byte written at the end of authenticated plaintext and validated
/// on receipt so structurally-invalid auth messages are rejected rather than parsed.
pub const AUTH_MAGIC: u8 = 0x01;

/// Sentinel tun octet used by the server to signal a rejected authentication.
/// Never a valid assignment (valid octets are `2..=254`).
pub const AUTH_REJECT_OCTET: u8 = 0x00;

/// Sentinel tun octet used by the server to tell a client that its session is
/// gone (dropped after client inactivity) and that it must re-authenticate.
pub const SESSION_EXPIRED_OCTET: u8 = 0xff;

/// Wire overhead wrapped around every inner (TUN) packet on the outer path.
///
/// Exact wire layout each term covers:
///
/// ```text
/// [IPv4 header .................. IPV4_HEADER_LEN = 20]
/// [ICMP echo header ............. ICMP_HEADER_LEN = 8]
/// [client id (plaintext) ........ CLIENT_ID_BYTES = 16]
/// [ChaCha20-Poly1305 nonce ...... CHACHA20_NONCE_SIZE = 12]
/// [ChaCha20-Poly1305 auth tag ... CHACHA20POLY1305_AUTH_OVERHEAD = 16]
/// [encrypted inner packet ...]
/// ```
///
/// The inner payload length needs no wire field of its own: it is recoverable
/// from the outer IPv4 total-length field, so it contributes nothing here.
///
/// The client's TUN MTU must be `outer_mtu - MTU_OVERHEAD` so an inner packet
/// plus the wire overhead always fits in one ICMP datagram.
pub const MTU_OVERHEAD: usize = ICMP_HEADER_LEN
    + IPV4_HEADER_LEN
    + CHACHA20POLY1305_AUTH_OVERHEAD
    + CHACHA20_NONCE_SIZE
    + CLIENT_ID_BYTES;

/// Default IP Time-To-Live written into every outer header.
pub const DEFAULT_TTL: u8 = 64;

/// `SO_RCVBUF` set on the raw receive socket.
///
/// 4 MiB of kernel buffer absorbs bursts of ~2800 x 1500 B datagrams while
/// userspace is busy, so nothing is dropped before the drain loop can read it.
pub const RECV_SOCKET_BUFFER_SIZE: usize = 4 * 1_024 * 1_024;

/// `SO_SNDBUF` set on the raw send socket (same burst headroom as
/// [`RECV_SOCKET_BUFFER_SIZE`]).
pub const SEND_SOCKET_BUFFER_SIZE: usize = 4 * 1_024 * 1_024;

/// Procfs path for the sysctl that suppresses kernel auto-replies to ICMP Echo Requests.
///
/// Set to `"1"` when Singularity operates in Echo Request mode so the kernel does
/// not send its own Echo Replies; restored to the previous value on shutdown.
pub const SYSCTL_ICMP_ECHO_IGNORE_ALL: &str =
    "/proc/sys/net/ipv4/icmp_echo_ignore_all";

/// Procfs path for the sysctl that enables IPv4 packet forwarding.
///
/// Set to `"1"` on server start (unless `--skip-nat`) so the kernel forwards
/// client traffic out of the WAN interface; the previous value is restored on
/// shutdown.
pub const SYSCTL_IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

pub const SERVER_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 1);

/// The tunnel subnet the server's TUN serves: `SERVER_TUN_IP` with its /24
/// netmask. The masquerade rule covers exactly this subnet.
pub const TUN_SUBNET: &str = "10.10.10.0/24";

/// Auth attempts before giving up; each attempt resends the request.
pub const AUTH_ATTEMPTS: usize = 5;

/// Receive window per auth attempt before the request is resent.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(1);

/// Capacity of each data-plane channel between the TUN and ICMP tasks.
pub const DATA_CHANNEL_CAPACITY: usize = 256;

/// Minimum viable inner (TUN) MTU: the IPv4 minimum reassembly size.
pub const MIN_INNER_MTU: u16 = 68;

/// Server-side session timeout: how long a client may stay silent before the
/// server drops its session.
///
/// A session that received nothing from its client for at least this long is
/// removed from the session table (freeing its tun octet for reuse) and the
/// client is told to re-authenticate.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on the session sweep cadence, i.e. the coarsest interval at which
/// idle sessions are dropped (see `server::sweep_interval`): a session disappears
/// at most this long after [`SESSION_TIMEOUT`] has elapsed.
pub const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_sentinels_are_not_assignable_octets() {
        // Both sentinels must stay outside the assignable range, or a control
        // frame would be indistinguishable from a granted session.
        for sentinel in [AUTH_REJECT_OCTET, SESSION_EXPIRED_OCTET] {
            assert!(!(2..=254).contains(&sentinel));
        }
        assert_ne!(AUTH_REJECT_OCTET, SESSION_EXPIRED_OCTET);
    }

    #[test]
    fn test_session_sweep_interval_is_finer_than_the_timeout() {
        // The sweep must be able to drop a session around its deadline: a cadence
        // at or above the timeout would leave idle sessions alive twice as long.
        assert!(SESSION_SWEEP_INTERVAL < SESSION_TIMEOUT);
    }

    #[test]
    fn test_mtu_overhead_matches_wire_layout() {
        assert_eq!(
            MTU_OVERHEAD,
            IPV4_HEADER_LEN
                + ICMP_HEADER_LEN
                + CLIENT_ID_BYTES
                + CHACHA20_NONCE_SIZE
                + CHACHA20POLY1305_AUTH_OVERHEAD
        );
        assert_eq!(MTU_OVERHEAD, 72);
    }

    #[test]
    fn test_tun_subnet_matches_server_tun_ip() {
        // The masquerade rule must cover exactly the subnet the server's TUN
        // address defines (SERVER_TUN_IP with its /24 netmask).
        let (network, prefix) =
            TUN_SUBNET.split_once('/').expect("TUN_SUBNET carries a /prefix");
        let network: Ipv4Addr =
            network.parse().expect("TUN_SUBNET network is an IPv4");
        assert_eq!(prefix, "24");
        assert_eq!(&network.octets()[..3], &SERVER_TUN_IP.octets()[..3]);
    }
}
