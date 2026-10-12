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

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::hdlc::{Hdlc, HdlcDecoder};
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Python `BackboneInterface.HW_MTU` before `optimise_mtu` replaces it.
const HW_MTU_INITIAL: usize = 1_048_576;

/// Nominal bitrate guess (Python `BackboneInterface.BITRATE_GUESS`).
pub const BITRATE_GUESS: u64 = 100_000_000;

/// `Interface.bitrate` default. Backbone control state starts there until
/// a configured rate or [`BITRATE_GUESS`] replaces it, so a still-default
/// reading must not drive `optimise_mtu`.
const GENERIC_INTERFACE_BITRATE: u64 = 62_500;

/// Hardware MTU selected by Python `Interface.optimise_mtu`.
///
/// Backbone sets `AUTOCONFIGURE_MTU`, so the class `HW_MTU` (1048576) does
/// not stay in force: the bitrate tier replaces it. The decoder and
/// [`HW_MTU`] both use this function so they cannot diverge.
pub const fn hw_mtu_for_bitrate(bitrate: u64) -> usize {
    if bitrate >= 1_000_000_000 {
        524_288
    } else if bitrate >= 750_000_000 {
        262_144
    } else if bitrate >= 400_000_000 {
        131_072
    } else if bitrate >= 200_000_000 {
        65_536
    } else if bitrate >= 100_000_000 {
        32_768
    } else if bitrate >= 10_000_000 {
        16_384
    } else if bitrate >= 5_000_000 {
        8_192
    } else if bitrate >= 2_000_000 {
        4_096
    } else if bitrate >= 1_000_000 {
        2_048
    } else if bitrate >= 62_500 {
        1_024
    } else {
        // Below the lowest tier Python clears `HW_MTU`. Keep the class
        // ceiling so the decoder still has a finite limit.
        HW_MTU_INITIAL
    }
}

/// Effective backbone hardware MTU at [`BITRATE_GUESS`] (after `optimise_mtu`).
pub const HW_MTU: usize = hw_mtu_for_bitrate(BITRATE_GUESS);

/// Python `TransmitBuffer.COALESCE_TARGET`.
pub const COALESCE_TARGET: usize = 65_536;

/// Python `Interface.tx_hwm` / `BackboneInterface.DP_EC_HIGH_WM` (4 MiB).
pub const TX_HWM: usize = 4 * 1024 * 1024;
pub const DP_EC_HIGH_WM: usize = TX_HWM;
pub const DP_EC_MID_WM: usize = 128 * 1024;
pub const DP_EC_STALL_TICKS: u32 = 3;
pub const DP_EC_MAX_ETA: f64 = 10.0;
pub const DP_EC_RELEASE_ETA: f64 = 5.0;
pub const DP_EC_DEAD_TIME: Duration = Duration::from_secs(12);
pub const DP_EC_INTERVAL: Duration = Duration::from_secs(1);

/// Dataplane ingress watermarks (Python `DP_IC_*`). The queue length they
/// scale is `Transport.INBOUND_DA_QUEUE_LENGTH` (1024) unless configured.
pub const DP_IC_HIGH_WM_PCT: usize = 90;
pub const DP_IC_MID_WM_PCT: usize = 68;
pub const DP_IC_LOW_WM_PCT: usize = 10;
pub const DP_IC_INTERVAL: Duration = Duration::from_millis(250);
pub const DP_IC_RCVBUF: usize = 32_768;
pub const DP_IC_IF_HEADROOM: usize = 32;
pub const DP_IC_PENALTY: f64 = 1.5;
pub const DEFAULT_DATA_QUEUE_LEN: usize = 1024;

/// `(high, mid, low)` packet marks (Python startup scaling of `DP_IC_*_WM`).
pub fn dp_ic_watermarks(data_queue_len: usize) -> (usize, usize, usize) {
    let high = ((DP_IC_HIGH_WM_PCT * data_queue_len) / 100).max(4);
    let mid = ((DP_IC_MID_WM_PCT * data_queue_len) / 100).max(2);
    let low = (DP_IC_LOW_WM_PCT * data_queue_len) / 100;
    (high, mid, low)
}

fn ingress_hold(span: Duration, bytes: u64, interfaces: usize) -> Duration {
    let span_s = span.as_secs_f64().max(0.001);
    let avail = bytes as f64 / span_s;
    let alloc = 1.0 / ((interfaces.max(DP_IC_IF_HEADROOM) as f64) * DP_IC_PENALTY);
    let hold_s = (avail / (avail * alloc).max(1.0)) * span_s;
    Duration::from_secs_f64(hold_s.max(0.0))
}

/// Per-peer ingress gate (Python `__dp_ic_job` for one producer).
#[derive(Debug)]
pub struct IngressControl {
    gated: bool,
    hold_until: Option<Instant>,
    packets: u64,
    bytes: u64,
    snapshot: Instant,
}

impl IngressControl {
    pub fn new(now: Instant) -> Self {
        Self {
            gated: false,
            hold_until: None,
            packets: 0,
            bytes: 0,
            snapshot: now,
        }
    }

    pub fn gated(&self) -> bool {
        self.gated
    }

    pub fn note(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    /// Update the gate from the inbound data-queue depth.
    /// `true` when further socket reads should pause.
    pub fn evaluate(&mut self, q_depth: usize, now: Instant, data_queue_len: usize) -> bool {
        let (_high, mid, low) = dp_ic_watermarks(data_queue_len);
        if q_depth > mid && self.packets > 0 {
            let hold = ingress_hold(now.saturating_duration_since(self.snapshot), self.bytes, 1);
            self.gated = true;
            self.hold_until = Some(now + hold);
        } else if q_depth < low {
            let held = self.hold_until.is_some_and(|until| now < until);
            if !held {
                self.gated = false;
                self.hold_until = None;
            }
        }
        self.snapshot = now;
        self.packets = 0;
        self.bytes = 0;
        self.gated
    }
}

/// Coalesced egress buffer (Python `TransmitBuffer`).
///
/// Small frames share one chunk up to [`COALESCE_TARGET`]. The chunk is
/// published on [`Self::flush`] / [`Self::drain_to`], not on every append:
/// this task both produces and drains, so flushing each idle append would
/// split a burst into one socket write per frame.
#[derive(Debug, Default)]
pub struct TransmitBuffer {
    cur: Vec<u8>,
    chunks: VecDeque<Vec<u8>>,
    head_offset: usize,
    tx_total: u64,
    tx_visible: u64,
    tx_sent: u64,
}

impl TransmitBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buffered(&self) -> usize {
        (self.tx_total - self.tx_sent) as usize
    }

    pub fn sendable(&self) -> usize {
        (self.tx_visible - self.tx_sent) as usize
    }

    pub fn tx_sent(&self) -> u64 {
        self.tx_sent
    }

    fn tail_len(&self) -> usize {
        self.cur.len()
    }

    /// Queue one HDLC frame. `false` when `limit` (the TX high-water mark)
    /// would be exceeded — the caller drops the frame.
    pub fn append(&mut self, frame: &[u8], limit: Option<usize>) -> bool {
        if let Some(limit) = limit {
            if self.buffered() + frame.len() > limit {
                return false;
            }
        }

        if frame.len() >= COALESCE_TARGET {
            self.flush_tail();
            self.tx_visible += frame.len() as u64;
            self.chunks.push_back(frame.to_vec());
        } else {
            if !self.cur.is_empty() && self.cur.len() + frame.len() > COALESCE_TARGET {
                self.flush_tail();
            }
            self.cur.extend_from_slice(frame);
        }
        self.tx_total += frame.len() as u64;
        true
    }

    pub fn flush(&mut self) {
        self.flush_tail();
    }

    fn flush_tail(&mut self) {
        if !self.cur.is_empty() {
            self.tx_visible += self.cur.len() as u64;
            self.chunks.push_back(std::mem::take(&mut self.cur));
        }
    }

    fn pop_head(&mut self) {
        self.chunks.pop_front();
        self.head_offset = 0;
    }

    /// Write queued chunks. Each chunk is one `write` call. `Ok(0)` and
    /// [`DrainError::Blocked`] stop the drain; [`DrainError::Failed`]
    /// aborts the peer. Returns `false` only on a hard write failure.
    pub fn drain_to<F>(&mut self, mut write: F) -> bool
    where
        F: FnMut(&[u8]) -> Result<usize, DrainError>,
    {
        loop {
            if self.chunks.is_empty() {
                self.flush_tail();
                if self.chunks.is_empty() {
                    return true;
                }
            }

            let start = self.head_offset;
            let len = self.chunks[0].len();
            if start >= len {
                self.pop_head();
                continue;
            }

            match write(&self.chunks[0][start..]) {
                Ok(0) => return true,
                Ok(n) => {
                    let n = n.min(len - start);
                    self.head_offset += n;
                    self.tx_sent += n as u64;
                    if self.head_offset >= self.chunks[0].len() {
                        self.pop_head();
                    } else {
                        return true;
                    }
                }
                Err(DrainError::Blocked) => return true,
                Err(DrainError::Failed) => return false,
            }
        }
    }
}

/// Socket write outcome for [`TransmitBuffer::drain_to`].
#[derive(Debug)]
pub enum DrainError {
    Blocked,
    Failed,
}

/// Dataplane egress control (Python `BackboneInterface._dp_ec_evaluate`).
#[derive(Debug)]
pub struct EgressControl {
    prev_sent: u64,
    zero_ticks: u32,
    last_drain: Instant,
    pub tx_stalled: bool,
}

impl EgressControl {
    pub fn new(now: Instant) -> Self {
        Self {
            prev_sent: 0,
            zero_ticks: 0,
            last_drain: now,
            tx_stalled: false,
        }
    }

    /// `true` when the peer must be torn down (no drain progress for
    /// [`DP_EC_DEAD_TIME`] while bytes are still sendable).
    pub fn evaluate(&mut self, buffer: &TransmitBuffer, now: Instant) -> bool {
        let drained = buffer.tx_sent().saturating_sub(self.prev_sent);
        self.prev_sent = buffer.tx_sent();
        let sendable = buffer.sendable();
        let buffered = buffer.buffered();

        if buffered == 0 || sendable == 0 {
            self.zero_ticks = 0;
            self.last_drain = now;
            self.tx_stalled = false;
            return false;
        }

        if now.saturating_duration_since(self.last_drain) >= DP_EC_DEAD_TIME {
            return true;
        }

        if drained > 0 {
            self.last_drain = now;
            self.zero_ticks = 0;
            let drain_rate = drained as f64 / DP_EC_INTERVAL.as_secs_f64();
            let clear_eta = if drain_rate > 0.0 {
                buffered as f64 / drain_rate
            } else {
                f64::INFINITY
            };
            if buffered > DP_EC_MID_WM && clear_eta > DP_EC_MAX_ETA {
                self.tx_stalled = true;
            } else if clear_eta < DP_EC_RELEASE_ETA || buffered <= DP_EC_MID_WM {
                self.tx_stalled = false;
            }
        } else if buffered > DP_EC_MID_WM {
            self.zero_ticks = self.zero_ticks.saturating_add(1);
            if self.zero_ticks >= DP_EC_STALL_TICKS {
                self.tx_stalled = true;
            }
        } else {
            self.zero_ticks = 0;
            self.tx_stalled = false;
        }
        false
    }
}

fn accept_outbound(stalled: bool, buffer: &mut TransmitBuffer, frame: &[u8]) -> bool {
    if stalled {
        return false;
    }
    buffer.append(frame, Some(TX_HWM))
}

fn encode_hdlc_frame(
    packet: &Packet,
    ifac: Option<&crate::iface::ifac::IfacKey>,
) -> Option<(Vec<u8>, usize)> {
    let mut raw = [0u8; 4096];
    let mut output = OutputBuffer::new(&mut raw);
    if packet.serialize(&mut output).is_err() {
        return None;
    }
    let wire = crate::iface::ifac::encode(output.as_slice(), ifac);
    let payload_len = wire.len();
    Some((Hdlc::encode_frame_vec(&wire), payload_len))
}

enum Enqueue {
    Queued,
    Skip,
    Drop,
}

fn enqueue_frame(
    packet: &Packet,
    ifac: &crate::iface::IfacSlot,
    stats: &crate::iface::InterfaceCounters,
    stalled: bool,
    buffer: &mut TransmitBuffer,
) -> Enqueue {
    let ifac = ifac.read().expect("ifac lock").clone();
    let Some((frame, payload_len)) = encode_hdlc_frame(packet, ifac.as_deref()) else {
        return Enqueue::Skip;
    };
    if !accept_outbound(stalled, buffer, &frame) {
        log::debug!(
            "backbone: egress control dropping outbound frame of {} bytes",
            frame.len()
        );
        return Enqueue::Drop;
    }
    stats.count_tx(payload_len);
    Enqueue::Queued
}

fn drain_write(stream: &tokio::net::tcp::OwnedWriteHalf, buffer: &mut TransmitBuffer) -> bool {
    buffer.drain_to(|chunk| match stream.try_write(chunk) {
        Ok(n) => Ok(n),
        Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted => {
            Err(DrainError::Blocked)
        }
        Err(_) => Err(DrainError::Failed),
    })
}

fn resolve_bitrate(configured: u64, control: Option<u64>) -> u64 {
    match control {
        Some(rate) if rate != GENERIC_INTERFACE_BITRATE => rate,
        _ => {
            if configured == 0 {
                BITRATE_GUESS
            } else {
                configured
            }
        }
    }
}

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
            Some((_, _, flaps)) => {
                *flaps > self.grace && now.duration_since(self.entries[remote].1) < self.expiry
            }
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
    /// Bitrate used for `optimise_mtu` when interface control still has
    /// the generic default (Python `BITRATE_GUESS`, or the parent server's
    /// configured rate for a spawned peer).
    bitrate: u64,
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
            bitrate: BITRATE_GUESS,
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
            bitrate: BITRATE_GUESS,
        }
    }

    /// Override the bitrate `optimise_mtu` uses for this peer.
    pub fn with_bitrate(mut self, bitrate: u64) -> Self {
        self.bitrate = bitrate;
        self
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

            let hw_mtu = {
                // Drop the client lock before awaiting the manager.
                let (configured, manager_of) = {
                    let client = inner.lock().unwrap();
                    (client.bitrate, client.iface_manager.clone())
                };
                let control = if let Some(manager) = manager_of {
                    let manager = manager.lock().await;
                    manager.with_control(&iface_address, |control| control.bitrate)
                } else {
                    None
                };
                hw_mtu_for_bitrate(resolve_bitrate(configured, control))
            };

            let (read_half, write_half) = stream.into_split();
            let link_cancel = tokio_util::sync::CancellationToken::new();

            let rx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    // Same limit `optimise_mtu` stored on the peer. Python's
                    // class 1048576 is only the pre-optimise assignment.
                    let mut decoder = HdlcDecoder::new(hw_mtu);
                    let mut buffer = vec![0u8; hw_mtu.max(DP_IC_RCVBUF)];
                    let mut frames: Vec<Vec<u8>> = Vec::new();
                    let mut ingress = IngressControl::new(Instant::now());
                    let mut ic_tick = tokio::time::interval(DP_IC_INTERVAL);
                    ic_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        let gated = ingress.gated();
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = stop.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
                            _ = ic_tick.tick() => {
                                let depth = rx_channel
                                    .max_capacity()
                                    .saturating_sub(rx_channel.capacity());
                                ingress.evaluate(depth, Instant::now(), DEFAULT_DATA_QUEUE_LEN);
                                false
                            }
                            result = stream.read(&mut buffer), if !gated => match result {
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
                                            ingress.note(plain.len());
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
                    link_cancel.cancel();
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let tx_channel = tx_channel.clone();
                let channel_ifac = channel_ifac.clone();
                let stream = write_half;

                tokio::spawn(async move {
                    let mut coalesce = TransmitBuffer::new();
                    let mut egress = EgressControl::new(Instant::now());
                    let mut ec_tick = tokio::time::interval(DP_EC_INTERVAL);
                    ec_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut tx_channel = tx_channel.lock().await;

                    loop {
                        let sendable = coalesce.sendable() > 0;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            _ = ec_tick.tick() => {
                                // No drain progress for DP_EC_DEAD_TIME drops the peer.
                                if egress.evaluate(&coalesce, Instant::now()) {
                                    log::warn!("backbone: egress stalled, tearing down peer");
                                    break;
                                }
                            }
                            ready = stream.writable(), if sendable => {
                                if ready.is_err() || !drain_write(&stream, &mut coalesce) {
                                    break;
                                }
                            }
                            message = tx_channel.recv() => {
                                let Some(message) = message else { break };
                                let stalled = egress.tx_stalled;
                                match enqueue_frame(&message.packet, &channel_ifac, &stats, stalled, &mut coalesce) {
                                    Enqueue::Drop => {}
                                    Enqueue::Skip | Enqueue::Queued => {
                                        // Stop once append publishes a chunk
                                        // (the coalesce window filled) so the
                                        // socket write is not held behind the
                                        // rest of the queue.
                                        let published = coalesce.sendable();
                                        while coalesce.tail_len() < COALESCE_TARGET
                                            && coalesce.buffered() < TX_HWM
                                            && coalesce.sendable() == published
                                        {
                                            match tx_channel.try_recv() {
                                                Ok(more) => {
                                                    if matches!(
                                                        enqueue_frame(&more.packet, &channel_ifac, &stats, stalled, &mut coalesce),
                                                        Enqueue::Drop
                                                    ) {
                                                        break;
                                                    }
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    }
                                }
                                // One publish for the burst, so the frames
                                // share a socket write up to COALESCE_TARGET.
                                coalesce.flush();
                            }
                        }
                    }
                    link_cancel.cancel();
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
                let flaps = table.account_disconnect(
                    &remote,
                    spawned_at.elapsed(),
                    tokio::time::Instant::now(),
                );
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
        let server_address = context.channel.address;
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
                    let mut tick = tokio::time::interval(Duration::from_secs(60));
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

                let inherited = context.channel.ifac.read().expect("ifac lock").clone();

                let mut manager = iface_manager.lock().await;
                // Spawned peers inherit the listener bitrate (Python
                // `spawned_interface.bitrate = self.bitrate` then
                // `optimise_mtu`). The generic 62500 default is not a
                // backbone rate.
                let parent_bitrate = manager
                    .with_control(&server_address, |c| c.bitrate)
                    .filter(|rate| *rate != GENERIC_INTERFACE_BITRATE)
                    .unwrap_or(BITRATE_GUESS);
                let address = manager.spawn(
                    BackboneClient::new_from_stream(socket, remote_ip)
                        .with_fast_flap(fast_flap.clone())
                        .with_bitrate(parent_bitrate),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_small_writes_within_coalesce_window_leave_as_one_write() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(b"aaaa", Some(TX_HWM)));
        assert!(buffer.append(b"bbbb", Some(TX_HWM)));

        let mut writes = Vec::new();
        assert!(buffer.drain_to(|chunk| {
            writes.push(chunk.to_vec());
            Ok(chunk.len())
        }));

        assert_eq!(writes.len(), 1, "frames inside 65536 leave as one write");
        assert_eq!(writes[0], b"aaaabbbb");
    }

    #[test]
    fn coalesce_window_splits_above_target() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(&vec![1u8; COALESCE_TARGET - 4], Some(TX_HWM)));
        assert!(buffer.append(&vec![2u8; 8], Some(TX_HWM)));

        let mut writes = Vec::new();
        assert!(buffer.drain_to(|chunk| {
            writes.push(chunk.len());
            assert!(chunk.len() <= COALESCE_TARGET);
            Ok(chunk.len())
        }));
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn tx_high_water_mark_rejects_another_frame() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(&vec![0u8; TX_HWM], Some(TX_HWM)));
        assert!(!accept_outbound(false, &mut buffer, &[1]));
        assert_eq!(TX_HWM, DP_EC_HIGH_WM);
    }

    #[test]
    fn stalled_peer_is_torn_down() {
        let t0 = Instant::now();
        let mut buffer = TransmitBuffer::new();
        let mut egress = EgressControl::new(t0);
        assert!(accept_outbound(false, &mut buffer, b"stuck-frame"));
        buffer.flush();
        assert!(buffer.sendable() > 0);

        assert!(
            !egress.evaluate(&buffer, t0),
            "a full sendable buffer is not torn down immediately"
        );
        assert!(
            egress.evaluate(&buffer, t0 + DP_EC_DEAD_TIME),
            "no egress progress for the dead time tears the peer down"
        );
    }

    #[test]
    fn egress_mid_watermark_gates_outbound() {
        let t0 = Instant::now();
        let mut buffer = TransmitBuffer::new();
        let mut egress = EgressControl::new(t0);
        assert!(buffer.append(&vec![0u8; DP_EC_MID_WM + 1], Some(TX_HWM)));
        buffer.flush();

        for tick in 0..DP_EC_STALL_TICKS {
            assert!(!egress.evaluate(&buffer, t0 + DP_EC_INTERVAL * tick));
        }
        assert!(egress.tx_stalled);
        assert!(!accept_outbound(egress.tx_stalled, &mut buffer, b"dropped"));
    }

    #[test]
    fn decoder_mtu_follows_bitrate_tier() {
        assert_eq!(BITRATE_GUESS, 100_000_000);
        assert_eq!(HW_MTU, 32_768);
        assert_eq!(hw_mtu_for_bitrate(BITRATE_GUESS), HW_MTU);
        assert_eq!(BackboneClient::mtu(), HW_MTU);
        assert_eq!(BackboneServer::mtu(), HW_MTU);
        assert_ne!(HW_MTU, HW_MTU_INITIAL);
        assert_eq!(hw_mtu_for_bitrate(1_000_000_000), 524_288);
        assert_eq!(hw_mtu_for_bitrate(750_000_000), 262_144);
        assert_eq!(hw_mtu_for_bitrate(400_000_000), 131_072);
        assert_eq!(hw_mtu_for_bitrate(200_000_000), 65_536);
        assert_eq!(hw_mtu_for_bitrate(10_000_000), 16_384);
        assert_eq!(hw_mtu_for_bitrate(5_000_000), 8_192);
        assert_eq!(hw_mtu_for_bitrate(2_000_000), 4_096);
        assert_eq!(hw_mtu_for_bitrate(1_000_000), 2_048);
        assert_eq!(hw_mtu_for_bitrate(62_500), 1_024);
        assert_eq!(hw_mtu_for_bitrate(1_000), HW_MTU_INITIAL);
        assert_eq!(
            hw_mtu_for_bitrate(resolve_bitrate(
                BITRATE_GUESS,
                Some(GENERIC_INTERFACE_BITRATE)
            )),
            HW_MTU
        );
        assert_eq!(
            hw_mtu_for_bitrate(resolve_bitrate(BITRATE_GUESS, Some(1_000_000_000))),
            524_288
        );
    }

    #[test]
    fn ingress_watermarks_match_python_and_release() {
        assert_eq!(dp_ic_watermarks(DEFAULT_DATA_QUEUE_LEN), (921, 696, 102));
        let t0 = Instant::now();
        let mut ingress = IngressControl::new(t0);
        let (_high, mid, _low) = dp_ic_watermarks(DEFAULT_DATA_QUEUE_LEN);
        ingress.note(1500);
        assert!(ingress.evaluate(mid + 1, t0, DEFAULT_DATA_QUEUE_LEN));
        assert!(ingress.gated());
        assert!(!ingress.evaluate(0, t0 + Duration::from_secs(60), DEFAULT_DATA_QUEUE_LEN));
        assert!(!ingress.gated());
    }
}
