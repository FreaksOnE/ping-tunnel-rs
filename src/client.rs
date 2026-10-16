use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::Result;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::task::JoinHandle;
use tun_rs::AsyncDevice;
use tun_rs::async_framed::BytesCodec;
use tun_rs::async_framed::DeviceFramedWrite;

use crate::ClientId;
use crate::auth;
use crate::constants::AUTH_ATTEMPTS;
use crate::constants::AUTH_TIMEOUT;
use crate::constants::DATA_CHANNEL_CAPACITY;
use crate::constants::MIN_INNER_MTU;
use crate::constants::MTU_OVERHEAD;
use crate::crypto;
use crate::error::EncryptionError;
use crate::route::DefaultRouteGuard;
use crate::transport::icmp::IcmpReceiveEnd;
use crate::transport::icmp::IcmpTransport;
use crate::transport::icmp::channel_to_icmp;
use crate::transport::icmp::icmp_to_channel;
use crate::transport::icmp::receive::IcmpReceiver;
use crate::transport::icmp::send::IcmpSender;
use crate::tun::channel_to_tun;
use crate::tun::tun_open;
use crate::tun::tun_to_channel;

enum SessionEnd {
    CtrlC,
    SessionExpired,
}

enum SessionTask {
    TunReader,
    TunWriter,
    IcmpReceiveLoop,
    IcmpSendLoop,
}

impl SessionTask {
    fn name(self) -> &'static str {
        match self {
            SessionTask::TunReader => "tun reader",
            SessionTask::TunWriter => "tun writer",
            SessionTask::IcmpReceiveLoop => "icmp receive loop",
            SessionTask::IcmpSendLoop => "icmp send loop",
        }
    }
}

struct ClientTun {
    octet: u8,
    device: Arc<AsyncDevice>,
}

pub struct Client {
    pub client_id: ClientId,
    pub password: String,

    pub listen_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub tun_name: String,
    pub icmp_identifier: u16,
    pub outer_mtu: u16,
    pub skip_route: bool,
}

impl Client {
    /// Authenticates against the server, then runs the tunnel until shutdown.
    pub async fn run(&self) -> Result<()> {
        let inner_mtu = compute_inner_mtu(self.outer_mtu)?;
        let mut tun: Option<ClientTun> = None;
        // The default route spans sessions: installed once the first TUN device
        // exists, re-applied when a re-authentication replaces that device, and
        // restored by the guard's Drop when this function returns.
        let mut routes: Option<DefaultRouteGuard> = None;

        loop {
            // One transport per session: the previous session's tasks are joined
            // before this handshake, so nothing still holds the old socket.
            let transport = IcmpTransport::client(
                self.listen_ip,
                self.icmp_identifier,
                self.outer_mtu,
            )?;
            let (sender, mut receiver) = transport.setup()?;

            let (tun_octet, session_key) =
                self.authenticate(&sender, &mut receiver).await?;
            check_tun_octet(tun_octet)?;

            let session_tun =
                self.session_tun(tun_octet, inner_mtu, tun.take()).await?;
            let device = Arc::clone(&session_tun.device);

            if !self.skip_route {
                match routes.take() {
                    Some(mut guard) => {
                        guard.reapply()?;
                        routes = Some(guard);
                    }
                    None => {
                        routes = Some(DefaultRouteGuard::install(
                            &self.tun_name,
                            self.server_ip,
                        )?);
                    }
                }
            }

            match self
                .connect(
                    tun_octet,
                    session_key,
                    inner_mtu,
                    sender,
                    receiver,
                    device,
                )
                .await?
            {
                SessionEnd::CtrlC => return Ok(()),
                SessionEnd::SessionExpired => {
                    tracing::warn!(
                        "server dropped the session; re-authenticating"
                    );
                }
            }

            tun = Some(session_tun);
        }
    }

    /// Returns the TUN device for `tun_octet`, reusing `previous` when it already
    /// carries that address and opening a fresh device otherwise.
    async fn session_tun(
        &self,
        tun_octet: u8,
        inner_mtu: u16,
        previous: Option<ClientTun>,
    ) -> Result<ClientTun> {
        if let Some(existing) = previous
            && existing.octet == tun_octet
        {
            tracing::debug!(
                tun_octet,
                "reusing the TUN device for the new session"
            );
            return Ok(existing);
        }

        // The TUN MTU must be the inner MTU, or oversized inner packets get
        // fragmented or dropped by the outer path.
        let local_ip = Ipv4Addr::new(10, 10, 10, tun_octet);
        let device = tun_open(&self.tun_name, inner_mtu, local_ip).await?;
        Ok(ClientTun { octet: tun_octet, device })
    }

    /// Runs the auth handshake, returning the assigned tun octet and session key.
    async fn authenticate(
        &self,
        sender: &IcmpSender,
        receiver: &mut IcmpReceiver,
    ) -> Result<(u8, [u8; 32])> {
        let key =
            crypto::derive_key(&self.password, self.client_id.0.as_bytes());
        let packet = auth::build_auth_packet(&self.client_id, &self.password)?;

        for attempt in 1..=AUTH_ATTEMPTS {
            if let Err(e) = sender.send(self.server_ip, &packet).await {
                tracing::warn!(attempt, error = %e, "auth request send failed");
                continue;
            }

            let reply = tokio::time::timeout(AUTH_TIMEOUT, async {
                loop {
                    match receiver.recv().await {
                        Ok((buf, src_addr)) if src_addr == self.server_ip => {
                            break Ok(buf);
                        }
                        Ok((_, src_addr)) => {
                            tracing::trace!(
                                %src_addr,
                                "ignoring auth datagram from unexpected source"
                            );
                        }
                        Err(e) => break Err(e),
                    }
                }
            })
            .await;

            let mut buf = match reply {
                Err(_) => continue, // timed out; resend on the next attempt
                Ok(Err(e)) => {
                    tracing::warn!(attempt, error = %e, "auth receive failed");
                    continue;
                }
                Ok(Ok(buf)) => buf,
            };

            match auth::parse_auth_response(&mut buf, &key) {
                Ok(tun_octet) => return Ok((tun_octet, key)),
                Err(EncryptionError::AuthRejected) => {
                    anyhow::bail!(
                        "authentication failed: server rejected credentials"
                    );
                }
                // An expiry notice for the previous session can still be in flight
                Err(EncryptionError::SessionExpired) => {
                    tracing::debug!(
                        attempt,
                        "ignoring a session-expiry notice during the handshake"
                    );
                }
                Err(e) => {
                    tracing::trace!(attempt, error = %e, "ignoring undecryptable auth datagram");
                }
            }
        }

        anyhow::bail!("authentication failed: no response from server")
    }

    /// Runs the 4-task data pipeline of one session until it ends.
    async fn connect(
        &self,
        tun_octet: u8,
        session_key: [u8; 32],
        inner_mtu: u16,
        sender: IcmpSender,
        receiver: IcmpReceiver,
        tun: Arc<AsyncDevice>,
    ) -> Result<SessionEnd> {
        let local_ip = Ipv4Addr::new(10, 10, 10, tun_octet);
        let framed_write =
            DeviceFramedWrite::new(Arc::clone(&tun), BytesCodec::new());

        let (to_icmp_tx, to_icmp_rx) =
            mpsc::channel::<(Ipv4Addr, BytesMut)>(DATA_CHANNEL_CAPACITY);
        let (to_tun_tx, to_tun_rx) =
            mpsc::channel::<(Ipv4Addr, BytesMut)>(DATA_CHANNEL_CAPACITY);
        let key: Arc<[u8; 32]> = Arc::from(session_key);
        let client_id_bytes = *self.client_id.0.as_bytes();

        // The tuple address on the to_icmp channel is the outer destination used by
        // `channel_to_icmp`, so TUN packets are stamped with the server's real
        // address.
        let session_dropped = Arc::new(OnceLock::new());

        let tun_reader =
            tokio::spawn(tun_to_channel(self.server_ip, tun, to_icmp_tx));
        let tun_writer = tokio::spawn(channel_to_tun(framed_write, to_tun_rx));
        let icmp_recv_loop = tokio::spawn(receive_loop(
            receiver,
            to_tun_tx,
            Arc::clone(&key),
            client_id_bytes,
            Arc::clone(&session_dropped),
        ));
        let icmp_send_loop = tokio::spawn(channel_to_icmp(
            to_icmp_rx,
            sender,
            Some(key),
            client_id_bytes,
        ));

        tracing::info!(
            tun_name = %self.tun_name,
            tun_ip = %local_ip,
            inner_mtu,
            "tunnel established"
        );

        run_session_tasks(
            tun_reader,
            tun_writer,
            icmp_recv_loop,
            icmp_send_loop,
            &session_dropped,
        )
        .await
    }
}

/// Runs the receive loop, publishing the one end that is not a pipeline failure.
async fn receive_loop(
    receiver: IcmpReceiver,
    channel: mpsc::Sender<(Ipv4Addr, BytesMut)>,
    key: Arc<[u8; 32]>,
    client_id_bytes: [u8; 16],
    session_dropped: Arc<OnceLock<bool>>,
) {
    let end =
        icmp_to_channel(receiver, channel, Some(key), Some(client_id_bytes))
            .await;
    if end == IcmpReceiveEnd::SessionExpired {
        // `set` fails only if something already recorded an end, which no path does.
        let _ = session_dropped.set(true);
    }
}

/// Runs the session's data-plane tasks until the session ends, then reaps them all.
async fn run_session_tasks(
    tun_reader: JoinHandle<()>,
    tun_writer: JoinHandle<()>,
    icmp_recv_loop: JoinHandle<()>,
    icmp_send_loop: JoinHandle<()>,
    session_dropped: &OnceLock<bool>,
) -> Result<SessionEnd> {
    tokio::pin!(tun_reader, tun_writer, icmp_recv_loop, icmp_send_loop);

    let mut tun_reader_done = false;
    let mut tun_writer_done = false;
    let mut icmp_recv_done = false;
    let mut icmp_send_done = false;

    let mut outcome: Option<Result<SessionEnd>> = None;

    while !(tun_reader_done
        && tun_writer_done
        && icmp_recv_done
        && icmp_send_done)
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c(), if outcome.is_none() => {
                tracing::info!("shutdown requested, tunnel tasks aborted");
                outcome = Some(Ok(SessionEnd::CtrlC));
            }
            res = &mut tun_reader, if !tun_reader_done => {
                tun_reader_done = true;
                if outcome.is_none() {
                    outcome = Some(report_task_end(
                        SessionTask::TunReader,
                        res,
                        session_dropped.get().copied(),
                    ));
                }
            }
            res = &mut tun_writer, if !tun_writer_done => {
                tun_writer_done = true;
                if outcome.is_none() {
                    outcome = Some(report_task_end(
                        SessionTask::TunWriter,
                        res,
                        session_dropped.get().copied(),
                    ));
                }
            }
            res = &mut icmp_recv_loop, if !icmp_recv_done => {
                icmp_recv_done = true;
                if outcome.is_none() {
                    outcome = Some(report_task_end(
                        SessionTask::IcmpReceiveLoop,
                        res,
                        session_dropped.get().copied(),
                    ));
                }
            }
            res = &mut icmp_send_loop, if !icmp_send_done => {
                icmp_send_done = true;
                if outcome.is_none() {
                    outcome = Some(report_task_end(
                        SessionTask::IcmpSendLoop,
                        res,
                        session_dropped.get().copied(),
                    ));
                }
            }
        }

        // Any end is the end of the session: stop the survivors so the remaining
        // iterations only reap them. Aborting a task that already ended is a no-op.
        if outcome.is_some() {
            tun_reader.abort();
            tun_writer.abort();
            icmp_recv_loop.abort();
            icmp_send_loop.abort();
        }
    }

    let Some(outcome) = outcome else {
        anyhow::bail!("session tasks ended without an outcome");
    };
    outcome
}

/// Maps the task that ended on its own onto the tunnel-wide outcome.
fn report_task_end(
    task: SessionTask,
    result: Result<(), JoinError>,
    session_dropped: Option<bool>,
) -> Result<SessionEnd> {
    let name = task.name();

    if session_dropped == Some(true) && result.is_ok() {
        tracing::debug!(task = name, "server dropped the session");
        return Ok(SessionEnd::SessionExpired);
    }

    tracing::error!(task = name, "data-plane task ended, shutting down tunnel");
    match result {
        Ok(_) => anyhow::bail!("{name} task exited unexpectedly"),
        Err(e) => anyhow::bail!("{name} task failed: {e}"),
    }
}

fn compute_inner_mtu(outer_mtu: u16) -> Result<u16> {
    let inner_mtu = outer_mtu.saturating_sub(MTU_OVERHEAD as u16);
    if inner_mtu < MIN_INNER_MTU {
        anyhow::bail!(
            "outer MTU {outer_mtu} too small: inner MTU {inner_mtu} < {MIN_INNER_MTU}"
        );
    }
    Ok(inner_mtu)
}

/// Validates a server-assigned tun octet: only `2..=254` are assignable (0 is the
/// reject sentinel, 1 is the server itself, 255 is broadcast).
fn check_tun_octet(tun_octet: u8) -> Result<()> {
    if !(2..=254).contains(&tun_octet) {
        anyhow::bail!("server assigned invalid tun octet {tun_octet}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;

    #[test]
    fn test_inner_mtu_computation() {
        // 1500 - MTU_OVERHEAD (72) = 1428.
        assert_eq!(compute_inner_mtu(1500).ok(), Some(1428));
        assert!(compute_inner_mtu(100).is_err());
    }

    #[test]
    fn test_tun_octet_bounds() {
        assert!(check_tun_octet(1).is_err());
        assert!(check_tun_octet(255).is_err());
        assert!(check_tun_octet(2).is_ok());
        assert!(check_tun_octet(254).is_ok());
    }

    #[tokio::test]
    async fn test_ended_task_decides_and_the_rest_are_reaped() {
        let session_dropped = OnceLock::new();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_session_tasks(
                tokio::spawn(async {}),
                tokio::spawn(async {}),
                tokio::spawn(sleep(std::time::Duration::from_secs(30))),
                tokio::spawn(sleep(std::time::Duration::from_secs(30))),
                &session_dropped,
            ),
        )
        .await
        .expect("the survivors must be aborted and reaped, not left running");

        assert!(outcome.is_err(), "a data-plane task ending is a failure");
    }

    #[tokio::test]
    async fn test_session_expiry_comes_from_the_receive_loop() {
        let session_dropped = OnceLock::new();
        session_dropped.set(true).unwrap();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_session_tasks(
                tokio::spawn(sleep(std::time::Duration::from_secs(30))),
                tokio::spawn(sleep(std::time::Duration::from_secs(30))),
                tokio::spawn(async {}),
                tokio::spawn(sleep(std::time::Duration::from_secs(30))),
                &session_dropped,
            ),
        )
        .await
        .expect("the survivors must be aborted and reaped, not left running");

        assert!(
            matches!(outcome, Ok(SessionEnd::SessionExpired)),
            "a clean receive-loop end must lead to re-authentication"
        );
    }

    #[test]
    fn test_recorded_expiry_beats_the_teardown_race() {
        for task in [
            SessionTask::TunReader,
            SessionTask::TunWriter,
            SessionTask::IcmpReceiveLoop,
            SessionTask::IcmpSendLoop,
        ] {
            let outcome = report_task_end(task, Ok(()), Some(true));
            assert!(
                matches!(outcome, Ok(SessionEnd::SessionExpired)),
                "a recorded notice must make any clean task end a re-authentication"
            );
        }

        assert!(
            report_task_end(SessionTask::TunWriter, Ok(()), None).is_err(),
            "an unannounced clean task end must stay a failure"
        );
    }

    #[tokio::test]
    async fn test_failed_task_still_fails_during_expiry() {
        let handle = tokio::spawn(sleep(std::time::Duration::from_secs(30)));
        handle.abort();
        let join_error = handle.await.expect_err("the aborted task must fail");

        assert!(
            report_task_end(
                SessionTask::TunWriter,
                Err(join_error),
                Some(true)
            )
            .is_err(),
            "a failed task must stay a failure during the expiry teardown"
        );
    }

    #[test]
    fn test_session_task_names_are_distinct() {
        let names = [
            SessionTask::TunReader.name(),
            SessionTask::TunWriter.name(),
            SessionTask::IcmpReceiveLoop.name(),
            SessionTask::IcmpSendLoop.name(),
        ];
        for (index, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(
                !names[index + 1..].contains(name),
                "duplicate session task name {name}"
            );
        }
    }
}
