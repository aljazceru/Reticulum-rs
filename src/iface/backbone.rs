//! Backbone interface — Python `RNS.Interfaces.BackboneInterface` parity
//! (Phase 5.8).
//!
//! High-throughput TCP backbone links: the server spawns one
//! [`BackboneClient`] peer per accepted connection (announces, ingress
//! control and access codes are inherited), and clients reconnect with
//! tunnel synthesis once connected (`wants_tunnel`).
//!
//! Fast-flapping connection suppression
//! (Python `BackboneInterface.fast_flapping`): peers whose connections
//! repeatedly drop within `fast_flap_threshold` seconds are counted per
//! remote address; once the count exceeds `fast_flap_grace`, further
//! connections from that address are ignored until the block expires
//! after `fast_flap_expiry` seconds without a flap.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::hdlc::{Hdlc, HdlcDecoder};
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Hardware MTU of backbone links
/// (Python `BackboneInterface.HW_MTU`).
pub const HW_MTU: usize = 32768;

/// Nominal bitrate guess (Python `BITRATE_GUESS`).
pub const BITRATE_GUESS: u64 = 1_000_000_000;

/// Enable fast-flapping suppression by default
/// (Python `BLOCK_FAST_FLAPPING`).
pub const BLOCK_FAST_FLAPPING: bool = true;

/// A connection counts as a fast flap if it lasted less than this
/// (Python `FAST_FLAP_THRESHOLD`).
pub const FAST_FLAP_THRESHOLD: Duration = Duration::from_secs(20);

/// Allowed fast flaps before the remote is blocked
/// (Python `FAST_FLAP_GRACE`).
pub const FAST_FLAP_GRACE: u32 = 5;

/// Blocked remotes are released after this flap-free period
/// (Python `FAST_FLAP_EXPIRY`).
pub const FAST_FLAP_EXPIRY: Duration = Duration::from_secs(12 * 60 * 60);

/// Reconnect wait for initiator clients
/// (Python `BackboneClientInterface.RECONNECT_WAIT`).
pub const RECONNECT_WAIT: Duration = Duration::from_secs(15);

/// Fast-flapping suppression state
/// (Python `BackboneInterface.fast_flapping`: `[started, last_flap,
/// flaps]` per remote address).
#[derive(Debug, Default)]
pub struct FastFlapTable {
    enabled: bool,
    threshold: Duration,
    grace: u32,
    expiry: Duration,
    entries: HashMap<String, (tokio::time::Instant, tokio::time::Instant, u32)>,
}

impl FastFlapTable {
    pub fn new(enabled: bool, threshold: Duration, grace: u32, expiry: Duration) -> Self {
        Self {
            enabled,
            threshold,
            grace,
            expiry,
            entries: HashMap::new(),
        }
    }

    /// Whether an incoming connection from `remote` is currently
    /// blocked (Python `incoming_connection` check).
    pub fn is_blocked(&mut self, remote: &str, now: tokio::time::Instant) -> bool {
        if !self.enabled {
            return false;
        }
        match self.entries.get(remote) {
            Some((_, _, flaps)) => *flaps > self.grace && now.duration_since(self.entries[remote].1) < self.expiry,
            None => false,
        }
    }

    /// Account a disconnect of `remote` after `connected_for`
    /// (Python `BackboneClientInterface.teardown` fast-flap accounting).
    /// Returns the updated flap count.
    pub fn account_disconnect(
        &mut self,
        remote: &str,
        connected_for: Duration,
        now: tokio::time::Instant,
    ) -> u32 {
        if !self.enabled || connected_for >= self.threshold {
            return self.entries.get(remote).map(|e| e.2).unwrap_or(0);
        }

        let entry = self
            .entries
            .entry(remote.to_string())
            .or_insert((now, now, 0));
        entry.1 = now;
        entry.2 += 1;
        entry.2
    }

    /// Release blocks whose last flap is older than the expiry
    /// (Python `blocked_ip_list` maintenance in the server job).
    pub fn clean(&mut self, now: tokio::time::Instant) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, last_flap, _)| now.duration_since(*last_flap) < self.expiry);
        before - self.entries.len()
    }

    /// Number of currently blocked remotes
    /// (Python `blocked_ip_count`).
    pub fn blocked_count(&self) -> usize {
        self.entries.values().filter(|e| e.2 > self.grace).count()
    }
}

/// One backbone peer: a TCP stream with HDLC framing, either an
/// initiator client (reconnecting, requests tunnel synthesis) or
/// spawned by [`BackboneServer`] for an accepted connection
/// (Python `BackboneClientInterface`).
pub struct BackboneClient {
    /// `host:port` to connect to (initiator mode).
    pub addr: Option<String>,
    /// Already-accepted stream (spawned mode).
    pub connected_stream: Option<TcpStream>,
    /// Remote address label for fast-flap accounting (spawned mode).
    pub remote: Option<String>,
    /// Interface manager of the owning transport (tunnel synthesis
    /// signalling; the server also uses it to spawn peers).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
    /// Shared fast-flap table of the parent server, if spawned.
    pub fast_flap: Option<Arc<tokio::sync::Mutex<FastFlapTable>>>,
}

impl BackboneClient {
    /// Create an initiator client (Python `BackboneClientInterface`
    /// with `target_host`/`target_port`).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: Some(addr.into()),
            connected_stream: None,
            remote: None,
            iface_manager: None,
            fast_flap: None,
        }
    }

    /// Create a spawned peer for an accepted stream
    /// (Python `incoming_connection`).
    pub fn new_from_stream(stream: TcpStream, remote: String) -> Self {
        Self {
            addr: None,
            connected_stream: Some(stream),
            remote: Some(remote),
            iface_manager: None,
            fast_flap: None,
        }
    }

    /// Attach the interface manager of the owning transport.
    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    /// Attach the parent server's fast-flap table (spawned peers).
    pub fn with_fast_flap(mut self, table: Arc<tokio::sync::Mutex<FastFlapTable>>) -> Self {
        self.fast_flap = Some(table);
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();
        let inner = context.inner.clone();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let connected = inner.lock().unwrap().connected_stream.take();
            let initiator_addr = inner.lock().unwrap().addr.clone();

            let spawned_at = tokio::time::Instant::now();
            let mut spawned_remote = inner.lock().unwrap().remote.clone();

            let stream = match connected {
                Some(stream) => stream,
                None => {
                    let Some(addr) = initiator_addr else { break };

                    match TcpStream::connect(&addr).await {
                        Ok(stream) => {
                            log::info!("backbone: connected to <{addr}>");
                            spawned_remote = Some(addr);
                            stream
                        }
                        Err(_) => {
                            log::debug!("backbone: could not connect to <{addr}>, retrying");
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    }
                }
            };

            stream.set_nodelay(true).ok();
            stats.set_online(true);

            // Tunnel synthesis once the link is up
            // (Python `initial_connect`: `self.wants_tunnel = True`).
            let manager_of = inner.lock().unwrap().iface_manager.clone();
            if let Some(manager) = manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
            }

            let (read_half, write_half) = stream.into_split();

            let rx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 8192];
                    let mut frames: Vec<Vec<u8>> = Vec::new();

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = stop.cancelled() => true,
                            result = stream.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    decoder.feed(&buffer[..n], |frame| {
                                        if frame.len() > 2 {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx.read().expect("ifac lock").clone();
                                            match crate::iface::ifac::decode(&frame, ifac.as_deref()) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("backbone: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain)) {
                                            stats.count_rx(plain.len());
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                        }
                                    }
                                    false
                                }
                            },
                        };

                        if closed {
                            break;
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let tx_channel = tx_channel.clone();
                let channel_ifac = channel_ifac.clone();
                let mut stream = write_half;

                tokio::spawn(async move {
                    loop {
                        let mut buffer = [0u8; 2048];
                        let mut hdlc_buffer = [0u8; 2048 + 512];

                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            message = tx_channel.recv() => match message {
                                Some(message) => message,
                                None => break,
                            },
                        };

                        let packet = message.packet;
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire = crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());

                            let mut framed = OutputBuffer::new(&mut hdlc_buffer[..]);
                            if Hdlc::encode(&wire, &mut framed).is_ok()
                                && stream.write_all(framed.as_slice()).await.is_ok()
                            {
                                let _ = stream.flush().await;
                                stats.count_tx(wire.len());
                            } else {
                                break;
                            }
                        }
                    }
                })
            };

            let _ = tokio::join!(tx_task, rx_task);
            stats.set_online(false);

            // Fast-flap accounting for spawned peers
            // (Python `teardown` fast-flapping update).
            let fast_flap = inner.lock().unwrap().fast_flap.clone();
            let remote = inner.lock().unwrap().remote.clone().or(spawned_remote);
            if let (Some(table), Some(remote)) = (fast_flap, remote) {
                let mut table = table.lock().await;
                let flaps =
                    table.account_disconnect(&remote, spawned_at.elapsed(), tokio::time::Instant::now());
                if flaps > 0 {
                    log::debug!("backbone: {remote} fast-flap count {flaps}");
                }
            }

            if inner.lock().unwrap().connected_stream.is_none()
                && inner.lock().unwrap().addr.is_none()
            {
                break;
            }

            tokio::time::sleep(RECONNECT_WAIT).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for BackboneClient {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// The backbone server: accepts connections and spawns peers with
/// inherited access codes and the shared fast-flap table
/// (Python `BackboneInterface`).
pub struct BackboneServer {
    /// Listen address.
    pub addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    /// Fast-flapping suppression table shared with spawned peers.
    pub fast_flap: Arc<tokio::sync::Mutex<FastFlapTable>>,
}

impl BackboneServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        fast_flap: Arc<tokio::sync::Mutex<FastFlapTable>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            fast_flap,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let fast_flap = { context.inner.lock().unwrap().fast_flap.clone() };

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let listener = match TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(_) => {
                    log::warn!("backbone_server: couldn't bind to <{addr}>");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            log::info!("backbone_server: listen on <{addr}>");
            stats.set_online(true);

            // Periodic fast-flap block expiry
            // (Python server job `blocked_ip_list` maintenance).
            {
                let fast_flap = fast_flap.clone();
                let cancel = context.cancel.clone();
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(Duration::from_secs(60));
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tick.tick() => {
                                let removed = fast_flap
                                    .lock()
                                    .await
                                    .clean(tokio::time::Instant::now());
                                if removed > 0 {
                                    log::debug!("backbone_server: {removed} fast-flap blocks expired");
                                }
                            }
                        }
                    }
                });
            }

            loop {
                if context.cancel.is_cancelled() {
                    break;
                }

                let accepted = tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };

                let Ok((socket, peer)) = accepted else {
                    log::warn!("backbone_server: accept error on <{addr}>");
                    break;
                };

                let remote_ip = peer.ip().to_string();

                // Fast-flapping suppression gate
                // (Python `incoming_connection`).
                let blocked = {
                    let mut table = fast_flap.lock().await;
                    table.is_blocked(&remote_ip, tokio::time::Instant::now())
                };
                if blocked {
                    log::warn!(
                        "backbone_server: ignoring connection from fast-flapping {remote_ip}"
                    );
                    continue;
                }

                log::debug!("backbone_server: accepting connection from {remote_ip}");

                let inherited =
                    context.channel.ifac.read().expect("ifac lock").clone();

                let mut manager = iface_manager.lock().await;
                let address = manager.spawn(
                    BackboneClient::new_from_stream(socket, remote_ip)
                        .with_fast_flap(fast_flap.clone()),
                    BackboneClient::spawn,
                );

                if inherited.is_some() {
                    manager.with_iface_ifac(&address, |slot| {
                        *slot.write().expect("ifac lock") = inherited.clone();
                    });
                }
            }

            stats.set_online(false);
        }
    }
}

impl Interface for BackboneServer {
    fn mtu() -> usize {
        HW_MTU
    }
}
