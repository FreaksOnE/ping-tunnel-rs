use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use bytes::BytesMut;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;
use tun_rs::async_framed::BytesCodec;
use tun_rs::async_framed::DeviceFramedWrite;
use uuid::Uuid;

use crate::ClientId;
use crate::auth;
use crate::bootstrap::SysctlGuard;
use crate::constants::CLIENT_ID_BYTES;
use crate::constants::DATA_CHANNEL_CAPACITY;
use crate::constants::IPV4_HEADER_LEN;
use crate::constants::SERVER_TUN_IP;
use crate::constants::SESSION_SWEEP_INTERVAL;
use crate::error::EncryptionError;
use crate::nat::NatGuard;
use crate::transport::icmp::IcmpTransport;
use crate::transport::icmp::open_packet;
use crate::transport::icmp::seal_payload;
use crate::transport::icmp::send::IcmpSender;
use crate::tun::channel_to_tun;
use crate::tun::tun_open;
use crate::tun::tun_to_channel;

#[derive(Debug)]
pub struct Session {
    pub key: [u8; 32],
    pub client_ip: Ipv4Addr,
    pub tun_octet: u8,
    /// Milliseconds from [`activity_origin`] to the last packet received from
    /// this client. Atomic so the data plane can refresh it through the shared
    /// read lock: the per-packet path stays free of session-table writes.
    last_seen_ms: AtomicU64,
}

impl Session {
    fn new(
        key: [u8; 32],
        client_ip: Ipv4Addr,
        tun_octet: u8,
        now: Instant,
    ) -> Self {
        Self {
            key,
            client_ip,
            tun_octet,
            last_seen_ms: AtomicU64::new(millis_since_origin(now)),
        }
    }

    fn touch(&self, now: Instant) {
        self.last_seen_ms.store(millis_since_origin(now), Ordering::Relaxed);
    }

    fn idle_for(&self, now: Instant) -> Duration {
        let idle_ms = millis_since_origin(now)
            .saturating_sub(self.last_seen_ms.load(Ordering::Relaxed));
        Duration::from_millis(idle_ms)
    }
}

/// One session per client id.
type SharedSessions = Arc<RwLock<SessionTable>>;

#[derive(Debug, Default)]
struct SessionTable {
    sessions: HashMap<ClientId, Session>,
    /// Tun octet => client id.
    octets: HashMap<u8, ClientId>,
}

impl SessionTable {
    fn insert(
        &mut self,
        client_id: ClientId,
        session: Session,
        octet: u8,
    ) -> Option<Session> {
        let displaced = self.sessions.insert(client_id.clone(), session);
        if let Some(previous) = &displaced {
            self.octets.remove(&previous.tun_octet);
        }
        self.octets.insert(octet, client_id);
        displaced
    }

    fn remove(&mut self, client_id: &ClientId) -> Option<Session> {
        let session = self.sessions.remove(client_id)?;
        self.octets.remove(&session.tun_octet);
        Some(session)
    }

    fn allocate_octet(&self) -> Option<u8> {
        (2..=254).find(|octet| !self.octets.contains_key(octet))
    }

    fn client_for_octet(&self, tun_octet: u8) -> Option<&ClientId> {
        self.octets.get(&tun_octet)
    }

    /// Drops every session whose client has been silent for at least `timeout`,
    /// returning the dropped sessions together with their client ids.
    ///
    /// Removal frees the session's tun octet for the next client; the caller
    /// tells each dropped client to re-authenticate.
    fn expire_idle(
        &mut self,
        now: Instant,
        timeout: Duration,
    ) -> Vec<(ClientId, Session)> {
        let expired: Vec<ClientId> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.idle_for(now) >= timeout)
            .map(|(client_id, _)| client_id.clone())
            .collect();

        expired
            .into_iter()
            .filter_map(|client_id| {
                self.remove(&client_id).map(|s| (client_id, s))
            })
            .collect()
    }
}

/// Monotonic origin of the session activity stamps. `Instant` has no atomic
/// representation, so activity is stored as milliseconds since this instant;
/// fixing the origin once per process keeps those stamps comparable.
static ACTIVITY_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn activity_origin() -> Instant {
    *ACTIVITY_ORIGIN.get_or_init(Instant::now)
}

fn millis_since_origin(at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(activity_origin()).as_millis())
        .unwrap_or(u64::MAX)
}

fn sweep_interval(timeout: Duration) -> Duration {
    (timeout / 4).clamp(Duration::from_secs(1), SESSION_SWEEP_INTERVAL)
}

pub struct Server {
    pub tun_name: String,
    pub icmp_identifier: u16,
    pub outer_mtu: u16,
    pub listen_ip: Ipv4Addr,
    pub allowlist: BTreeMap<ClientId, [u8; 32]>,
    pub session_timeout: Duration,
    pub out_interface: String,
    pub skip_nat: bool,
}

impl Server {
    /// Serves authenticated clients until shutdown.
    pub async fn run(&self) -> Result<()> {
        let _guard = SysctlGuard::suppress_echo_replies()?;

        let transport = IcmpTransport::server(
            self.listen_ip,
            self.icmp_identifier,
            self.outer_mtu,
        )?;
        let (icmp_sender, mut icmp_receiver) = transport.setup()?;
        let icmp_sender = Arc::new(icmp_sender);

        let sessions: SharedSessions =
            Arc::new(RwLock::new(SessionTable::default()));

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        let tun =
            tun_open(&self.tun_name, self.outer_mtu, SERVER_TUN_IP).await?;
        let framed_write =
            DeviceFramedWrite::new(Arc::clone(&tun), BytesCodec::new());

        let _nat_guard = if self.skip_nat {
            tracing::info!(
                "--skip-nat: leaving IPv4 forwarding and the firewall to the operator"
            );
            None
        } else {
            Some(NatGuard::install(&self.tun_name, &self.out_interface)?)
        };

        let (to_tun_tx, to_tun_rx) =
            mpsc::channel::<(Ipv4Addr, BytesMut)>(DATA_CHANNEL_CAPACITY);
        let (to_icmp_tx, to_icmp_rx) =
            mpsc::channel::<(Ipv4Addr, BytesMut)>(DATA_CHANNEL_CAPACITY);

        tasks.push(tokio::spawn(channel_to_tun(framed_write, to_tun_rx)));
        tasks.push(tokio::spawn(tun_to_channel(
            SERVER_TUN_IP,
            tun,
            to_icmp_tx,
        )));
        tasks.push(tokio::spawn(server_tun_to_icmp(
            to_icmp_rx,
            Arc::clone(&icmp_sender),
            Arc::clone(&sessions),
        )));

        let mut sweep =
            tokio::time::interval(sweep_interval(self.session_timeout));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutdown requested");
                    break;
                }
                _ = sweep.tick() => {
                    let expired = {
                        let mut guard = sessions.write().await;
                        guard.expire_idle(Instant::now(), self.session_timeout)
                    };
                    for (client_id, session) in expired {
                        tracing::info!(
                            client_id = %client_id.0,
                            client_ip = %session.client_ip,
                            tun_octet = session.tun_octet,
                            idle_timeout_secs = self.session_timeout.as_secs(),
                            "dropping session after client inactivity; client must re-authenticate"
                        );
                        send_session_expired(&icmp_sender, session.client_ip, &session.key).await;
                    }
                }
                result = icmp_receiver.recv() => {
                    let (mut buf, src_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(error = %e, "icmp receive failed");
                            continue;
                        }
                    };

                    // 1. Data plane: sessions are keyed by the plaintext client-id
                    //    prefix, so routing is one lookup and one decrypt trial. The
                    //    activity stamp is refreshed for a packet that actually
                    //    decrypts, so undecryptable traffic carrying someone else's
                    //    client id cannot keep a stale session alive.
                    if buf.len() >= CLIENT_ID_BYTES {
                        let mut client_id_bytes = [0u8; CLIENT_ID_BYTES];
                        client_id_bytes.copy_from_slice(&buf[..CLIENT_ID_BYTES]);
                        let client_id = ClientId(Uuid::from_bytes(client_id_bytes));

                        let routed = {
                            let guard = sessions.read().await;
                            match guard.sessions.get(&client_id) {
                                Some(session) => {
                                    // The prefix already identified the session, so
                                    // `open_packet` needs no expected id.
                                    let inner = open_packet(&mut buf, &session.key, None);
                                    if inner.is_ok() {
                                        session.touch(Instant::now());
                                    }
                                    Some(inner)
                                }
                                None => None,
                            }
                        };

                        match routed {
                            Some(Ok(inner)) => {
                                if to_tun_tx.send((src_addr, inner)).await.is_err() {
                                    tracing::warn!("tun writer channel closed");
                                }
                                continue;
                            }
                            Some(Err(e)) => {
                                tracing::trace!(error = %e, "dropping undecryptable packet for known client");
                                continue;
                            }
                            // No session: fall through to the auth plane below.
                            None => {}
                        }

                        // A packet carrying a known client id but no live session: the
                        // session was dropped after inactivity (or the client never
                        // authenticated). Reject it so the client re-authenticates
                        // instead of black-holing its traffic. An unknown id is not a
                        // client id at all - an auth request's first 16 bytes are its
                        // nonce - so it falls through to the auth plane below.
                        if let Some(key) = self.allowlist.get(&client_id) {
                            tracing::debug!(
                                client_id = %client_id.0,
                                client_ip = %src_addr,
                                "rejecting packet for a session that is gone; client must re-authenticate"
                            );
                            send_session_expired(&icmp_sender, src_addr, key).await;
                            continue;
                        }
                    }

                    // 2. Auth plane: no session claimed this datagram.
                    let mut guard = sessions.write().await;
                    let free_octet = guard.allocate_octet();
                    let outcome = {
                        let mut alloc_octet = || free_octet;
                        auth::server_try_auth(&mut buf, &self.allowlist, &mut alloc_octet)
                    };

                    match outcome {
                        Ok(Some(grant)) => {
                            let session =
                                Session::new(grant.key, src_addr, grant.tun_octet, Instant::now());
                            let replaced = guard
                                .insert(grant.client_id.clone(), session, grant.tun_octet)
                                .is_some();
                            drop(guard);
                            tracing::info!(
                                client_id = %grant.client_id.0,
                                client_ip = %src_addr,
                                tun_octet = grant.tun_octet,
                                replaced,
                                "session established"
                            );
                            match auth::build_auth_response(&grant.key, grant.tun_octet) {
                                Ok(response) => {
                                    if let Err(e) = icmp_sender.send(src_addr, &response).await {
                                        tracing::warn!(error = %e, "auth response send failed");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to build auth response");
                                }
                            }
                        }
                        Ok(None) => {
                            drop(guard);
                            if free_octet.is_none() {
                                tracing::warn!(client_ip = %src_addr, "rejecting auth: all tun octets assigned");
                            }
                            // A key matched but validation failed (or the server is
                            // full): reject so the client can tell "rejected" from
                            // "server gone". No key at all is a silent drop.
                            match auth::trial_decrypt_key(&buf, &self.allowlist) {
                                Some(key) => send_auth_reject(&icmp_sender, src_addr, &key).await,
                                None => {
                                    tracing::trace!(client_ip = %src_addr, "dropping datagram: no session and no matching key");
                                }
                            }
                        }
                        Err(e) => {
                            drop(guard);
                            tracing::trace!(error = %e, "dropping malformed auth attempt");
                        }
                    }
                }
            }
        }

        // Ctrl-c (the only exit) aborts the data-plane tasks; returning drops
        // `_nat_guard` (removes the NAT rules, restores ip_forward) and then
        // `_guard`, which restores the sysctl.
        for task in tasks {
            task.abort();
        }

        Ok(())
    }
}

async fn send_auth_reject(
    icmp_sender: &IcmpSender,
    client_ip: Ipv4Addr,
    key: &[u8; 32],
) {
    send_notice(
        icmp_sender,
        client_ip,
        "auth reject",
        auth::build_auth_reject(key),
    )
    .await;
}

async fn send_session_expired(
    icmp_sender: &IcmpSender,
    client_ip: Ipv4Addr,
    key: &[u8; 32],
) {
    send_notice(
        icmp_sender,
        client_ip,
        "session-expiry notice",
        auth::build_session_expired(key),
    )
    .await;
}

async fn send_notice(
    icmp_sender: &IcmpSender,
    client_ip: Ipv4Addr,
    what: &'static str,
    frame: Result<BytesMut, EncryptionError>,
) {
    match frame {
        Ok(frame) => {
            if let Err(e) = icmp_sender.send(client_ip, &frame).await {
                tracing::warn!(error = %e, %client_ip, what, "control frame send failed");
            }
        }
        Err(e) => {
            tracing::error!(error = %e, what, "failed to build control frame")
        }
    }
}

async fn server_tun_to_icmp(
    mut channel: Receiver<(Ipv4Addr, BytesMut)>,
    icmp_sender: Arc<IcmpSender>,
    sessions: SharedSessions,
) {
    while let Some((_, packet)) = channel.recv().await {
        let Some(dst_ip) = extract_dst_ip(&packet) else {
            tracing::warn!(
                packet_len = packet.len(),
                "dropping undersized inner packet"
            );
            continue;
        };
        if dst_ip.octets()[..3] != SERVER_TUN_IP.octets()[..3] {
            tracing::trace!(%dst_ip, "dropping inner packet for non-tunnel destination");
            continue;
        }

        let route = {
            let guard = sessions.read().await;
            guard.client_for_octet(dst_ip.octets()[3]).and_then(|client_id| {
                guard.sessions.get(client_id).map(|session| {
                    (*client_id.0.as_bytes(), session.key, session.client_ip)
                })
            })
        };
        let Some((client_id_bytes, key, client_ip)) = route else {
            tracing::trace!(%dst_ip, "no session for inner destination");
            continue;
        };

        match seal_payload(&packet, &key, client_id_bytes) {
            Ok(sealed) => {
                if let Err(e) = icmp_sender.send(client_ip, &sealed).await {
                    tracing::warn!(error = %e, "icmp send failed");
                }
            }
            Err(e) => {
                tracing::trace!(error = %e, "dropping unsealable inner packet");
            }
        }
    }
}

fn extract_dst_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < IPV4_HEADER_LEN {
        return None;
    }
    let dst = &packet[16..IPV4_HEADER_LEN];
    Some(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]))
}

#[cfg(test)]
mod tests {
    use crate::constants::SESSION_TIMEOUT;

    use super::*;

    fn client(n: u128) -> ClientId {
        ClientId(Uuid::from_u128(n))
    }

    fn test_now() -> Instant {
        activity_origin() + Duration::from_secs(1_000)
    }

    fn session_at(octet: u8, now: Instant) -> Session {
        Session::new([octet; 32], Ipv4Addr::new(203, 0, 113, octet), octet, now)
    }

    fn session(octet: u8) -> Session {
        session_at(octet, test_now())
    }

    fn table_of(
        entries: impl IntoIterator<Item = (ClientId, Session)>,
    ) -> SessionTable {
        let mut sessions = SessionTable::default();
        for (client_id, session) in entries {
            let octet = session.tun_octet;
            sessions.insert(client_id, session, octet);
        }
        sessions
    }

    #[test]
    fn test_session_activity_tracking() {
        let now = test_now();
        let session = session_at(2, now - Duration::from_secs(5));

        assert_eq!(session.idle_for(now), Duration::from_secs(5));

        session.touch(now);
        assert_eq!(session.idle_for(now), Duration::ZERO);
        assert_eq!(
            session.idle_for(now + Duration::from_secs(1)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn test_expire_idle_sessions_drops_only_idle_clients() {
        let now = test_now();
        let mut sessions = table_of([
            (
                client(1),
                session_at(2, now - SESSION_TIMEOUT - Duration::from_secs(1)),
            ),
            (
                client(2),
                session_at(3, now - SESSION_TIMEOUT + Duration::from_secs(1)),
            ),
            (client(3), session_at(4, now)),
        ]);

        let expired = sessions.expire_idle(now, SESSION_TIMEOUT);

        let expired_ids: Vec<ClientId> =
            expired.iter().map(|(client_id, _)| client_id.clone()).collect();
        assert_eq!(expired_ids, vec![client(1)]);
        assert_eq!(expired[0].1.tun_octet, 2);
        assert_eq!(sessions.sessions.len(), 2);
        assert!(sessions.sessions.contains_key(&client(2)));
        assert!(sessions.sessions.contains_key(&client(3)));

        assert_eq!(sessions.allocate_octet(), Some(2));
        assert!(sessions.client_for_octet(2).is_none());
    }

    #[test]
    fn test_expire_idle_sessions_with_no_sessions() {
        let mut sessions = SessionTable::default();
        assert!(sessions.expire_idle(test_now(), SESSION_TIMEOUT).is_empty());
    }

    #[test]
    fn test_sweep_interval_bounds() {
        assert_eq!(
            sweep_interval(Duration::from_secs(4)),
            Duration::from_secs(1)
        );
        assert_eq!(
            sweep_interval(Duration::from_secs(8)),
            Duration::from_secs(2)
        );
        assert_eq!(
            sweep_interval(Duration::from_secs(60)),
            SESSION_SWEEP_INTERVAL
        );
        assert_eq!(
            sweep_interval(Duration::from_secs(3_600)),
            SESSION_SWEEP_INTERVAL
        );
    }

    #[test]
    fn test_octet_allocation_first_free() {
        let sessions =
            table_of([(client(1), session(2)), (client(2), session(3))]);
        assert_eq!(sessions.allocate_octet(), Some(4));

        let sessions =
            table_of([(client(1), session(2)), (client(2), session(4))]);
        assert_eq!(sessions.allocate_octet(), Some(3));

        let sessions = table_of(
            (2..=254u8)
                .map(|octet| (client(u128::from(octet)), session(octet))),
        );
        assert_eq!(sessions.allocate_octet(), None);
    }

    #[test]
    fn test_dest_ip_extraction() {
        use etherparse::PacketBuilder;

        // 20-byte IPv4 header + 8-byte ICMP echo header + 12-byte payload.
        let src = Ipv4Addr::new(10, 10, 10, 2);
        let dst = Ipv4Addr::new(203, 0, 113, 7);
        let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .icmpv4_echo_request(1, 1);
        let mut packet = Vec::new();
        builder.write(&mut packet, &[0u8; 12]).expect("header write");
        assert_eq!(packet.len(), 40);
        assert_eq!(extract_dst_ip(&packet), Some(dst));

        // Anything shorter than an IPv4 header has no destination to read.
        assert_eq!(extract_dst_ip(&packet[..19]), None);
    }

    #[test]
    fn test_session_lookup_by_octet() {
        let sessions =
            table_of([(client(1), session(2)), (client(2), session(4))]);

        let client_id = sessions.client_for_octet(4).expect("octet 4 assigned");
        assert_eq!(*client_id, client(2));
        assert_eq!(sessions.sessions[client_id].tun_octet, 4);

        assert!(sessions.client_for_octet(3).is_none());
    }

    #[test]
    fn test_insert_replacing_client_keeps_one_octet_index_entry() {
        let mut sessions = table_of([(client(1), session(2))]);

        let replaced = sessions.insert(client(1), session(5), 5);

        assert!(replaced.is_some());
        assert!(sessions.client_for_octet(2).is_none());
        assert_eq!(sessions.client_for_octet(5), Some(&client(1)));
    }
}
