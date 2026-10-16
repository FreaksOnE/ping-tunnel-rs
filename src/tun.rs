use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use bytes::BytesMut;
use futures::SinkExt;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tun_rs::AsyncDevice;
use tun_rs::DeviceBuilder;
use tun_rs::IDEAL_BATCH_SIZE;
use tun_rs::async_framed::BytesCodec;
use tun_rs::async_framed::DeviceFramedWrite;

/// Largest frame the TUN device can deliver: the maximum IPv4 packet.
#[cfg(target_os = "linux")]
const READ_MAX: usize = 65_535;

/// Opens (and configures) the named TUN device with the given address and MTU.
pub async fn tun_open(
    name: &str,
    mtu: u16,
    local_ip: Ipv4Addr,
) -> Result<Arc<AsyncDevice>> {
    let tun = DeviceBuilder::new()
        .name(name)
        .ipv4(local_ip, 24, None)
        .mtu(mtu)
        .offload(true)
        .build_async()?;

    Ok(Arc::new(tun))
}

/// Forwards packets read from the TUN device into `sender` until the device or channel
/// closes. A read error or closed channel ends the task (logged, never panics).
pub async fn tun_to_channel(
    self_ip: Ipv4Addr,
    tun: Arc<AsyncDevice>,
    sender: Sender<(Ipv4Addr, BytesMut)>,
) {
    #[cfg(target_os = "linux")]
    recv_multiple_loop(self_ip, tun, sender).await;
    #[cfg(not(target_os = "linux"))]
    framed_read_loop(self_ip, tun, sender).await;
}

/// Batched receive via `recv_multiple` (Linux + `offload(true)`): one wakeup
/// serves up to [`IDEAL_BATCH_SIZE`] frames, since a GRO super-packet is split
/// into MTU-sized segments in a single syscall.
///
/// The scratch (`original_buffer`, the frame slots, `sizes`) is allocated once
/// before the loop and reused every batch. Each forwarded frame owns a fresh
/// buffer because the mpsc channel takes ownership of every message; the batch
/// infrastructure itself never reallocates.
#[cfg(target_os = "linux")]
async fn recv_multiple_loop(
    self_ip: Ipv4Addr,
    tun: Arc<AsyncDevice>,
    sender: Sender<(Ipv4Addr, BytesMut)>,
) {
    use tun_rs::VIRTIO_NET_HDR_LEN;

    // Raw read buffer: virtio-net header + the largest unsplit packet.
    let mut original_buffer = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + READ_MAX);
    let mut sizes = vec![0usize; IDEAL_BATCH_SIZE];

    // Frame slots sized to the device MTU: GRO segments never exceed it.
    let frame_capacity = match tun.mtu() {
        Ok(mtu) => usize::from(mtu),
        Err(e) => {
            tracing::error!(error = %e, "tun mtu query failed");
            return;
        }
    };
    let mut slots: Vec<BytesMut> = (0..IDEAL_BATCH_SIZE)
        .map(|_| BytesMut::zeroed(frame_capacity))
        .collect();

    loop {
        let num = match tun
            .recv_multiple(&mut original_buffer, &mut slots, &mut sizes, 0)
            .await
        {
            Ok(num) => num,
            Err(e) => {
                tracing::error!(error = %e, "tun read failed");
                return;
            }
        };

        for i in 0..num {
            let frame = BytesMut::from(&slots[i][..sizes[i]]);
            if sender.send((self_ip, frame)).await.is_err() {
                return;
            }
        }
    }
}

/// Single-frame receive fallback (tun-rs's `recv_multiple` is Linux-only).
/// Same channel semantics as [`recv_multiple_loop`], one wakeup per frame.
#[cfg(not(target_os = "linux"))]
async fn framed_read_loop(
    self_ip: Ipv4Addr,
    tun: Arc<AsyncDevice>,
    sender: Sender<(Ipv4Addr, BytesMut)>,
) {
    use futures::StreamExt;
    use tun_rs::async_framed::DeviceFramed;

    let mut framed = DeviceFramed::new(tun, BytesCodec::new());
    while let Some(item) = framed.next().await {
        let buf = match item {
            Ok(buf) => buf,
            Err(e) => {
                tracing::error!(error = %e, "tun read failed");
                break;
            }
        };
        if sender.send((self_ip, buf)).await.is_err() {
            break;
        }
    }
}

/// Drains `receiver` into the TUN device in batches (capped at [`IDEAL_BATCH_SIZE`]),
/// flushing after each batch. A channel close ends the task; a write/flush error is
/// logged and ends the task (never panics).
pub async fn channel_to_tun(
    mut tun: DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>>,
    mut receiver: Receiver<(Ipv4Addr, BytesMut)>,
) {
    while let Some((_, buf)) = receiver.recv().await {
        if let Err(e) = tun.feed(buf).await {
            tracing::error!(error = %e, "tun write failed");
            return;
        }

        let mut count = 1;
        while count < IDEAL_BATCH_SIZE {
            match receiver.try_recv() {
                Ok((_, buf)) => {
                    if let Err(e) = tun.feed(buf).await {
                        tracing::error!(error = %e, "tun write failed");
                        return;
                    }
                    count += 1;
                }
                Err(_) => break,
            }
        }

        if let Err(e) =
            <DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>> as SinkExt<
                BytesMut,
            >>::flush(&mut tun)
            .await
        {
            tracing::error!(error = %e, "tun flush failed");
            return;
        }
    }
}
