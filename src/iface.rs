pub mod control;
pub mod hdlc;
pub mod ifac;
pub mod local;

pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

#[cfg(all(feature = "iface-auto", target_os = "linux"))]
pub mod auto;
#[cfg(feature = "iface-serial")]
pub mod ax25;
pub mod backbone;
#[cfg(feature = "iface-i2p")]
pub mod i2p;
#[cfg(feature = "iface-serial")]
pub mod kiss;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
#[cfg(feature = "iface-rnode")]
pub mod rnode;
#[cfg(feature = "iface-serial")]
pub mod serial;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use rand_core::RngCore;
use tokio::sync::mpsc;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::hash::AddressHash;
use crate::hash::Hash;
pub use crate::iface::control::{IfaceControlParams, IfaceControlState, InterfaceMode};
use crate::packet::{Packet, PacketType};

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    Broadcast(Option<AddressHash>),
    Direct(AddressHash),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Packet,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub packet: Packet,       // Received packet
}

/// Runtime counters for a single interface, shared between the
/// [`InterfaceManager`] and the interface worker tasks.
///
/// Mirrors the `sent/received/txb/rxb/online` bookkeeping of
/// `RNS.Interfaces.Interface` used by `rnstatus`.
#[derive(Debug)]
pub struct InterfaceCounters {
    sent: AtomicU64,
    received: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    online: AtomicBool,
    /// Announce traffic (Python `arxb/atxb/arxc/atxc`).
    announces_received: AtomicU64,
    announces_sent: AtomicU64,
    announce_bytes_received: AtomicU64,
    announce_bytes_sent: AtomicU64,
    /// Path request traffic (Python `prxb/ptxb/prxc/ptxc`).
    path_requests_received: AtomicU64,
    path_requests_sent: AtomicU64,
    /// Protocol violations (Python `protocol_violations`).
    protocol_violations: AtomicU64,
    /// IFAC violations (Python `ifac_violations`).
    ifac_violations: AtomicU64,
    /// Early packet filter hits (Python `packet_filter_hits`).
    packet_filter_hits: AtomicU64,
    /// Last reported radio RSSI in dBm (`i32::MIN` = not reported).
    rssi: AtomicI32,
    /// Last reported radio SNR as f32 bits (`u32::MAX` = not reported).
    snr_bits: AtomicU32,
    /// Last reported derived link-quality percentage as f32 bits
    /// (`u32::MAX` = not reported; Python `r_stat_q`).
    quality_bits: AtomicU32,
}

impl InterfaceCounters {
    /// Account one transmitted packet of `bytes` payload bytes.
    pub fn count_tx(&self, bytes: usize) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account one received packet of `bytes` payload bytes.
    pub fn count_rx(&self, bytes: usize) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::Relaxed);
    }

    /// Account a received announce (Python `Interface.received_announce`).
    pub fn count_announce_rx(&self, bytes: usize) {
        self.announces_received.fetch_add(1, Ordering::Relaxed);
        self.announce_bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account a sent announce (Python `Interface.sent_announce`).
    pub fn count_announce_tx(&self, bytes: usize) {
        self.announces_sent.fetch_add(1, Ordering::Relaxed);
        self.announce_bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account a received path request
    /// (Python `Interface.received_path_request`).
    pub fn count_path_request_rx(&self, bytes: usize) {
        self.path_requests_received.fetch_add(1, Ordering::Relaxed);
        let _ = bytes;
    }

    /// Account a sent path request (Python `Interface.sent_path_request`).
    pub fn count_path_request_tx(&self, bytes: usize) {
        self.path_requests_sent.fetch_add(1, Ordering::Relaxed);
        let _ = bytes;
    }

    /// Account a protocol violation (Python `Interface.protocol_violation`).
    pub fn count_protocol_violation(&self) {
        self.protocol_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Account an IFAC violation (Python `Interface.ifac_violation`).
    pub fn count_ifac_violation(&self) {
        self.ifac_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Account an early packet filter hit
    /// (Python `Interface.packet_filter_hit`).
    pub fn count_packet_filter_hit(&self) {
        self.packet_filter_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Received announce count.
    pub fn announces_received(&self) -> u64 {
        self.announces_received.load(Ordering::Relaxed)
    }

    /// Sent announce count.
    pub fn announces_sent(&self) -> u64 {
        self.announces_sent.load(Ordering::Relaxed)
    }

    /// Received announce bytes.
    pub fn announce_bytes_received(&self) -> u64 {
        self.announce_bytes_received.load(Ordering::Relaxed)
    }

    /// Sent announce bytes.
    pub fn announce_bytes_sent(&self) -> u64 {
        self.announce_bytes_sent.load(Ordering::Relaxed)
    }

    /// Received path request count.
    pub fn path_requests_received(&self) -> u64 {
        self.path_requests_received.load(Ordering::Relaxed)
    }

    /// Sent path request count.
    pub fn path_requests_sent(&self) -> u64 {
        self.path_requests_sent.load(Ordering::Relaxed)
    }

    /// Protocol violation count.
    pub fn protocol_violations(&self) -> u64 {
        self.protocol_violations.load(Ordering::Relaxed)
    }

    /// IFAC violation count.
    pub fn ifac_violations(&self) -> u64 {
        self.ifac_violations.load(Ordering::Relaxed)
    }

    /// Packet filter hit count.
    pub fn packet_filter_hits(&self) -> u64 {
        self.packet_filter_hits.load(Ordering::Relaxed)
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    /// Publish the latest radio link-quality telemetry for this interface
    /// (Python `r_stat_rssi`/`r_stat_snr`/`r_stat_q`). `None` values keep
    /// the previous reading; quality is usually derived from SNR by the
    /// reporting interface.
    pub fn set_radio_quality(&self, rssi: Option<i16>, snr: Option<f32>, quality: Option<f32>) {
        if let Some(rssi) = rssi {
            self.rssi.store(rssi as i32, Ordering::Relaxed);
        }
        if let Some(snr) = snr {
            self.snr_bits.store(snr.to_bits(), Ordering::Relaxed);
        }
        if let Some(quality) = quality {
            self.quality_bits
                .store(quality.to_bits(), Ordering::Relaxed);
        }
    }

    /// Last reported RSSI in dBm, when this interface reports one.
    pub fn rssi(&self) -> Option<i16> {
        let value = self.rssi.load(Ordering::Relaxed);
        (value != i32::MIN).then_some(value as i16)
    }

    /// Last reported SNR in dB, when this interface reports one.
    pub fn snr(&self) -> Option<f32> {
        let bits = self.snr_bits.load(Ordering::Relaxed);
        (bits != u32::MAX).then(|| f32::from_bits(bits))
    }

    /// Last reported derived link-quality percentage (Python `r_stat_q`).
    pub fn quality(&self) -> Option<f32> {
        let bits = self.quality_bits.load(Ordering::Relaxed);
        (bits != u32::MAX).then(|| f32::from_bits(bits))
    }
}

/// Sentinel initializers for the radio-telemetry atomics in
/// [`InterfaceCounters`] (`AtomicI32`/`AtomicU64` default to 0, which is a
/// valid reading, so "unreported" is encoded explicitly).
impl Default for InterfaceCounters {
    fn default() -> Self {
        Self {
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            online: AtomicBool::new(false),
            announces_received: AtomicU64::new(0),
            announces_sent: AtomicU64::new(0),
            announce_bytes_received: AtomicU64::new(0),
            announce_bytes_sent: AtomicU64::new(0),
            path_requests_received: AtomicU64::new(0),
            path_requests_sent: AtomicU64::new(0),
            protocol_violations: AtomicU64::new(0),
            ifac_violations: AtomicU64::new(0),
            packet_filter_hits: AtomicU64::new(0),
            rssi: AtomicI32::new(i32::MIN),
            snr_bits: AtomicU32::new(u32::MAX),
            quality_bits: AtomicU32::new(u32::MAX),
        }
    }
}

/// Snapshot of the statistics of one interface
/// (compare `rnstatus` output of the Python reference implementation).
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceStats {
    /// Interface address used for routing
    pub address: AddressHash,
    /// Human-readable interface name (configuration name)
    pub name: String,
    /// Interface type (short Rust type name of the spawned interface)
    pub kind: String,
    /// Packets sent
    pub sent: u64,
    /// Packets received
    pub received: u64,
    /// Payload bytes sent
    pub tx_bytes: u64,
    /// Payload bytes received
    pub rx_bytes: u64,
    /// Whether the interface considers itself online
    pub online: bool,
    /// Announces received/sent (Python 1.5.0 traffic stats).
    pub announces_received: u64,
    pub announces_sent: u64,
    /// Announce payload bytes received/sent.
    pub announce_bytes_received: u64,
    pub announce_bytes_sent: u64,
    /// Path requests received/sent.
    pub path_requests_received: u64,
    pub path_requests_sent: u64,
    /// Protocol violations detected on this interface.
    pub protocol_violations: u64,
    /// IFAC violations detected on this interface.
    pub ifac_violations: u64,
    /// Early packet filter hits.
    pub packet_filter_hits: u64,
    /// Last reported radio RSSI in dBm (Python `r_stat_rssi`), when the
    /// interface reports radio telemetry (RNode and friends).
    pub rssi: Option<i16>,
    /// Last reported radio SNR in dB (Python `r_stat_snr`).
    pub snr: Option<f32>,
    /// Last reported derived link-quality percentage 0–100
    /// (Python `r_stat_q`).
    pub quality: Option<f32>,
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
    pub stats: Arc<InterfaceCounters>,
    /// Interface access code configuration for this interface
    /// (Python `interface.ifac_identity`); packets are wrapped/unwrapped
    /// by the interface worker when present.
    pub ifac: IfacSlot,
}

/// Shared IFAC configuration slot of an interface.
pub type IfacSlot = Arc<std::sync::RwLock<Option<Arc<ifac::IfacKey>>>>;

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
            stats: Arc::new(InterfaceCounters::default()),
            ifac: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub trait Interface {
    fn mtu() -> usize;
}

struct LocalInterface {
    address: AddressHash,
    name: String,
    kind: String,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    stats: Arc<InterfaceCounters>,
    ifac: IfacSlot,
}

pub struct InterfaceContext<T: Interface> {
    pub inner: Arc<Mutex<T>>,
    pub channel: InterfaceChannel,
    pub cancel: CancellationToken,
}

pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<tokio::sync::Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
    /// Per-interface transport control state (Python `Interface` ingress /
    /// egress control attributes).
    controls: Mutex<HashMap<AddressHash, IfaceControlState>>,
}

impl InterfaceManager {
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(tokio::sync::Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
            controls: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_named(tx_cap, "", "")
    }

    /// Create a new interface channel registered under `name` (configuration
    /// name, used for statistics) and `kind` (interface type).
    pub fn new_channel_named(&mut self, tx_cap: usize, name: &str, kind: &str) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let mut address_seed = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut address_seed);
        address_seed[..8].copy_from_slice(&counter_bytes[..8]);
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&address_seed));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {} <{}:{}>", address, name, kind);

        let stop = CancellationToken::new();
        let stats = Arc::new(InterfaceCounters::default());
        stats.set_online(false);

        let ifac: IfacSlot = Arc::new(std::sync::RwLock::new(None));

        self.ifaces.push(LocalInterface {
            address,
            name: name.to_string(),
            kind: kind.to_string(),
            tx_send,
            stop: stop.clone(),
            stats: stats.clone(),
            ifac: ifac.clone(),
        });

        self.controls
            .lock()
            .expect("iface control lock")
            .insert(address, IfaceControlState::new(tokio::time::Instant::now()));

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
            stats,
            ifac,
        }
    }

    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        let kind = interface_kind_name::<T>();
        let channel = self.new_channel_named(1, &kind, &kind);

        let inner = Arc::new(Mutex::new(inner));

        InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
        }
    }

    /// Set the statistics name of an already registered interface
    /// (interfaces spawned by a server get the peer address as name).
    pub fn set_iface_name(&mut self, address: &AddressHash, name: &str) {
        if let Some(iface) = self.ifaces.iter_mut().find(|i| &i.address == address) {
            iface.name = name.to_string();
        }
    }

    /// Stop a single interface by address. The interface worker observes the
    /// stop token of its channel and terminates; the entry is removed from
    /// the manager once it has been cleaned up.
    pub fn stop_iface(&mut self, address: &AddressHash) {
        if let Some(index) = self.ifaces.iter().position(|i| &i.address == address) {
            let iface = self.ifaces.remove(index);
            iface.stats.set_online(false);
            iface.stop.cancel();
            self.controls
                .lock()
                .expect("iface control lock")
                .remove(address);
        }
    }

    /// Run `f` with the control state of one interface
    /// (Python reads/writes attributes directly on the interface object).
    pub fn with_control<R>(
        &self,
        address: &AddressHash,
        f: impl FnOnce(&mut IfaceControlState) -> R,
    ) -> Option<R> {
        let mut controls = self.controls.lock().expect("iface control lock");
        controls.get_mut(address).map(f)
    }

    fn with_stats(&self, address: &AddressHash, f: impl FnOnce(&InterfaceCounters)) {
        if let Some(iface) = self.ifaces.iter().find(|i| i.address == *address) {
            f(&iface.stats);
        }
    }

    /// Configure the interface mode of an interface
    /// (Python interface `mode` configuration option).
    pub fn set_iface_mode(&self, address: &AddressHash, mode: InterfaceMode) -> bool {
        self.with_control(address, |control| control.mode = mode)
            .is_some()
    }

    /// Configure the nominal bitrate of an interface in bits per second
    /// (Python interface `bitrate` configuration option).
    pub fn set_iface_bitrate(&self, address: &AddressHash, bitrate: u64) -> bool {
        self.with_control(address, |control| control.bitrate = bitrate)
            .is_some()
    }

    /// Mark an interface as a local shared-instance client
    /// (Python `is_local_client_interface`).
    pub fn set_iface_local_client(&self, address: &AddressHash) -> bool {
        self.with_control(address, |control| control.is_local_client = true)
            .is_some()
    }

    /// Bind an interface to a tunnel id
    /// (Python `Interface.tunnel_id`).
    pub fn set_iface_tunnel(&self, address: &AddressHash, tunnel_id: Option<AddressHash>) -> bool {
        self.with_control(address, |control| control.tunnel_id = tunnel_id)
            .is_some()
    }

    /// Configure the interface access code of an interface
    /// (Python `ifac_size` / `networkname` / `passphrase` interface
    /// options; Python `Reticulum._add_interface` derivation).
    pub fn set_iface_ifac(
        &self,
        address: &AddressHash,
        netname: Option<&str>,
        netkey: Option<&str>,
        size: usize,
    ) -> Result<bool, crate::error::RnsError> {
        let key = ifac::IfacKey::derive(netname, netkey, size)?;
        Ok(self
            .with_iface_ifac(address, move |slot| {
                *slot.write().expect("ifac lock") = Some(Arc::new(key));
            })
            .is_some())
    }

    /// Spawn an interface worker with its IFAC slot already populated,
    /// so the worker never observes an unauthenticated frame before the
    /// key is installed (needed on multithreaded runtimes where `spawn`
    /// may begin polling immediately).
    pub fn spawn_with_ifac<T, F, R>(
        &mut self,
        inner: T,
        worker: F,
        ifac: Arc<ifac::IfacKey>,
    ) -> AddressHash
    where
        T: Interface,
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
    {
        let kind = interface_kind_name::<T>();
        let channel = self.new_channel_named(1, &kind, &kind);
        *channel.ifac.write().expect("ifac lock") = Some(ifac);

        let context = InterfaceContext::<T> {
            inner: Arc::new(Mutex::new(inner)),
            channel,
            cancel: self.cancel.clone(),
        };

        let address = context.channel.address;
        task::spawn(worker(context));
        address
    }

    /// Access the IFAC configuration slot of an interface.
    pub fn with_iface_ifac<R>(
        &self,
        address: &AddressHash,
        f: impl FnOnce(&IfacSlot) -> R,
    ) -> Option<R> {
        self.ifaces
            .iter()
            .find(|iface| &iface.address == address)
            .map(|iface| f(&iface.ifac))
    }

    /// Request tunnel synthesis for an interface
    /// (Python `Interface.wants_tunnel`).
    pub fn set_iface_wants_tunnel(&self, address: &AddressHash, wants: bool) -> bool {
        self.with_control(address, |control| control.wants_tunnel = wants)
            .is_some()
    }

    /// Addresses of interfaces currently requesting tunnel synthesis
    /// (Python `Interface.wants_tunnel`).
    pub fn interfaces_wanting_tunnel(&self) -> Vec<AddressHash> {
        let controls = self.controls.lock().expect("iface control lock");
        self.ifaces
            .iter()
            .filter(|iface| {
                !iface.stop.is_cancelled()
                    && controls
                        .get(&iface.address)
                        .map(|control| control.wants_tunnel)
                        .unwrap_or(false)
            })
            .map(|iface| iface.address)
            .collect()
    }

    /// The tunnel id an interface is bound to, if any.
    pub fn iface_tunnel(&self, address: &AddressHash) -> Option<AddressHash> {
        self.with_control(address, |control| control.tunnel_id)
            .flatten()
    }

    /// Whether an interface is a local shared-instance client.
    pub fn is_local_client_iface(&self, address: &AddressHash) -> bool {
        self.with_control(address, |control| control.is_local_client)
            .unwrap_or(false)
    }

    /// Addresses of live local-client interfaces
    /// (Python `Transport.local_client_interfaces`).
    pub fn local_client_iface_addresses(&self) -> Vec<AddressHash> {
        let controls = self.controls.lock().expect("iface control lock");
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .filter(|iface| {
                controls
                    .get(&iface.address)
                    .map(|control| control.is_local_client)
                    .unwrap_or(false)
            })
            .map(|iface| iface.address)
            .collect()
    }

    /// The interface mode of an interface (default `Full`).
    pub fn iface_mode(&self, address: &AddressHash) -> InterfaceMode {
        self.with_control(address, |control| control.mode)
            .unwrap_or(InterfaceMode::Full)
    }

    /// Account a received announce on an interface
    /// (Python `Interface.received_announce`).
    pub fn received_announce(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_announce(now));
        self.with_stats(address, |stats| stats.count_announce_rx(bytes));
    }

    /// Account a sent announce on an interface
    /// (Python `Interface.sent_announce`).
    pub fn sent_announce(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_announce(now));
        self.with_stats(address, |stats| stats.count_announce_tx(bytes));
    }

    /// Account a received path request on an interface
    /// (Python `Interface.received_path_request`).
    pub fn received_path_request(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_path_request(now));
        self.with_stats(address, |stats| stats.count_path_request_rx(bytes));
    }

    /// Account a sent path request on an interface
    /// (Python `Interface.sent_path_request`).
    pub fn sent_path_request(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_path_request(now));
        self.with_stats(address, |stats| stats.count_path_request_tx(bytes));
    }

    /// Account an early packet filter hit on an interface
    /// (Python `Interface.packet_filter_hit`).
    pub fn count_packet_filter_hit(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_packet_filter_hit());
    }

    /// Account a protocol violation on an interface
    /// (Python `Interface.protocol_violation`).
    pub fn count_protocol_violation(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_protocol_violation());
    }

    /// Account an IFAC violation on an interface
    /// (Python `Interface.ifac_violation`).
    pub fn count_ifac_violation(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_ifac_violation());
    }

    /// Release held announces on all interfaces whose burst penalty has
    /// elapsed (Python `Interface.process_held_announces`, driven by
    /// `threading.Timer` there and by the transport ticker here).
    /// Returns the interface each packet was held on, for re-injection.
    pub fn release_held_announces(&self) -> Vec<(AddressHash, Packet)> {
        let now = tokio::time::Instant::now();
        let mut controls = self.controls.lock().expect("iface control lock");
        let mut released = Vec::new();
        for (address, control) in controls.iter_mut() {
            while let Some(packet) = control.release_held_announce(now) {
                released.push((*address, packet));
            }
        }
        released
    }

    /// Transmit queued announces whose airtime budget allows it
    /// (Python `Interface.process_announce_queue`). Returns the direct
    /// transmit messages for the transport to send.
    pub fn process_announce_queues(&self) -> Vec<TxMessage> {
        let now = tokio::time::Instant::now();
        let mut controls = self.controls.lock().expect("iface control lock");
        let mut messages = Vec::new();
        for (address, control) in controls.iter_mut() {
            while let Some(packet) = control.take_queued_announce(now) {
                control.sent_announce(now);
                messages.push(TxMessage {
                    tx_type: TxMessageType::Direct(*address),
                    packet,
                });
            }
        }
        messages
    }

    /// Addresses of all live interfaces with their online status,
    /// for fan-out decisions (path request forwarding).
    pub fn live_iface_addresses(&self) -> Vec<(AddressHash, bool)> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| (iface.address, iface.stats.online()))
            .collect()
    }

    /// Kind string of a live interface (used for Python-parity
    /// per-interface capabilities such as link MTU negotiation).
    pub fn iface_kind(&self, address: &AddressHash) -> Option<String> {
        self.ifaces
            .iter()
            .find(|iface| &iface.address == address && !iface.stop.is_cancelled())
            .map(|iface| iface.kind.clone())
    }

    /// The hardware MTU of an interface (Python
    /// `Transport.next_hop_interface_hw_mtu`): `None` for interface
    /// types that cannot negotiate a path MTU, otherwise the type's
    /// fixed/auto-configured MTU.
    /// The lowest bitrate of all online interfaces with a configured
    /// bitrate (Python `Transport.lowest_interface_bitrate`, recomputed
    /// on the jobs loop there; `None` when no online interface has one).
    pub fn lowest_interface_bitrate(&self) -> Option<u64> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled() && iface.stats.online())
            .filter_map(|iface| self.with_control(&iface.address, |c| c.bitrate))
            .min()
    }

    /// The hardware MTU of the first live interface (single-interface
    /// instances have an unambiguous next hop).
    /// Address of the first live interface.
    pub fn first_iface_address(&self) -> Option<AddressHash> {
        self.ifaces
            .first()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| iface.address)
    }

    pub fn first_iface_hw_mtu(&self) -> Option<usize> {
        self.ifaces
            .first()
            .filter(|iface| !iface.stop.is_cancelled())
            .and_then(|iface| self.iface_hw_mtu(&iface.address))
    }

    pub fn iface_hw_mtu(&self, address: &AddressHash) -> Option<usize> {
        let kind = self.iface_kind(address)?;
        match kind.as_str() {
            // Python `AUTOCONFIGURE_MTU`/`FIXED_MTU` interfaces
            // (LocalInterface 262144, TCP 262144, Backbone 1048576,
            // AutoInterface 1196).
            "LocalServer" | "LocalClient" | "TcpClient" | "TcpServer" => Some(262_144),
            "BackboneClient" | "BackboneServer" => Some(1_048_576),
            "AutoInterface" => Some(1_196),
            _ => None,
        }
    }

    /// Snapshot of the statistics of all live interfaces.
    pub fn stats(&self) -> Vec<InterfaceStats> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| InterfaceStats {
                address: iface.address,
                name: iface.name.clone(),
                kind: iface.kind.clone(),
                sent: iface.stats.sent(),
                received: iface.stats.received(),
                tx_bytes: iface.stats.tx_bytes(),
                rx_bytes: iface.stats.rx_bytes(),
                online: iface.stats.online(),
                announces_received: iface.stats.announces_received(),
                announces_sent: iface.stats.announces_sent(),
                announce_bytes_received: iface.stats.announce_bytes_received(),
                announce_bytes_sent: iface.stats.announce_bytes_sent(),
                path_requests_received: iface.stats.path_requests_received(),
                path_requests_sent: iface.stats.path_requests_sent(),
                protocol_violations: iface.stats.protocol_violations(),
                ifac_violations: iface.stats.ifac_violations(),
                packet_filter_hits: iface.stats.packet_filter_hits(),
                rssi: iface.stats.rssi(),
                snr: iface.stats.snr(),
                quality: iface.stats.quality(),
            })
            .collect()
    }

    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = *context.channel.address();

        task::spawn(worker(context));

        address
    }

    /// Spawn an interface worker registered under a human-readable `name`
    /// (the configuration name of the interface).
    pub fn spawn_named<T: Interface, F, R>(
        &mut self,
        name: impl AsRef<str>,
        inner: T,
        worker: F,
    ) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = *context.channel.address();

        self.set_iface_name(&address, name.as_ref());

        task::spawn(worker(context));

        address
    }

    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    pub async fn send(&self, message: TxMessage) {
        let is_announce = message.packet.header.packet_type == PacketType::Announce;

        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }

                    // Announce forwarding policy between interface modes
                    // (Python `Transport.outbound` MODE_INTERNAL /
                    // MODE_ROAMING / MODE_BOUNDARY gating). Directly
                    // addressed transmissions (path responses) and locally
                    // originated announces bypass the policy.
                    if should_send && is_announce && message.packet.header.hops > 0 {
                        should_send = self.announce_forwarding_allowed(&iface.address, address);
                    }

                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if should_send && !iface.stop.is_cancelled() {
                // Egress airtime budgeting for forwarded announces
                // (Python announce cap + `Interface.announce_queue`).
                if is_announce && message.packet.header.hops > 0 {
                    let now = tokio::time::Instant::now();
                    let size = control::packet_wire_len(&message.packet);
                    let allowed = self.with_control(&iface.address, |control| {
                        if control.try_transmit_announce(size, now) {
                            control.sent_announce(now);
                            true
                        } else {
                            control.queue_announce(message.packet, now);
                            false
                        }
                    });
                    // Announce traffic stats (Python `Interface.sent_announce`).
                    if allowed.unwrap_or(false) {
                        iface.stats.count_announce_tx(size);
                    }

                    if !allowed.unwrap_or(true) {
                        continue;
                    }
                }

                let _ = iface.tx_send.send(message).await;
            }
        }
    }

    /// Whether an announce received on `from_iface` (or locally originated
    /// when `None`) may be forwarded onto `to_iface`
    /// (Python `Transport.outbound` mode interaction rules).
    pub fn announce_forwarding_allowed(
        &self,
        to_iface: &AddressHash,
        from_iface: Option<AddressHash>,
    ) -> bool {
        let to_mode = self.iface_mode(to_iface);

        match to_mode {
            InterfaceMode::Internal => {
                // Only boundary-mode or explicitly enabled interfaces may
                // inject announces into internal-mode interfaces.
                match from_iface {
                    None => true,
                    Some(from) => {
                        let from_mode = self.iface_mode(&from);
                        from_mode == InterfaceMode::Boundary
                            || self
                                .with_control(&from, |control| {
                                    control.announces_to_internal == Some(true)
                                })
                                .unwrap_or(false)
                    }
                }
            }
            InterfaceMode::Roaming => match from_iface {
                None => true,
                Some(from) => {
                    let from_mode = self.iface_mode(&from);
                    from_mode != InterfaceMode::Roaming && from_mode != InterfaceMode::Boundary
                }
            },
            InterfaceMode::Boundary => match from_iface {
                None => true,
                Some(from) => self.iface_mode(&from) != InterfaceMode::Roaming,
            },
            _ => true,
        }
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Short type name of an interface, used as statistics `kind`.
fn interface_kind_name<T: ?Sized>() -> String {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full).to_string()
}

// ---------------------------------------------------------------------------
// Interface status snapshot for tooling (`rnstatus`, Phase 8 utilities).
//
// Per-interface statistics (Python `Interface.ifstats`: sent/received/txb/rxb
// counters plus names, kinds and online status) are implemented by
// [`InterfaceStats`] above (Phase 5.9); `IfaceStats` is kept as an alias for
// the utilities.
// ---------------------------------------------------------------------------

/// Status of one spawned interface, as reported to `rnstatus`.
pub type IfaceStats = InterfaceStats;

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIface;

    impl Interface for TestIface {
        fn mtu() -> usize {
            500
        }
    }

    async fn test_worker(context: InterfaceContext<TestIface>) {
        let InterfaceContext { channel, .. } = context;
        let InterfaceChannel {
            address,
            rx_channel,
            mut tx_channel,
            stop,
            stats,
            ..
        } = channel;

        stats.set_online(true);

        loop {
            let packet = tokio::select! {
                _ = stop.cancelled() => break,
                Some(message) = tx_channel.recv() => message.packet,
            };

            stats.count_tx(128);
            let _ = rx_channel.send(RxMessage { address, packet }).await;
        }
    }

    #[tokio::test]
    async fn interface_stats_counters() {
        let mut manager = InterfaceManager::new(16);

        let address = manager.spawn_named("test iface", TestIface, test_worker);

        // let the worker come up and register itself online
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stats = manager.stats();
        assert_eq!(stats.len(), 1);
        let stats = &stats[0];
        assert_eq!(stats.name, "test iface");
        assert_eq!(stats.kind, "TestIface");
        assert_eq!(stats.address, address);
        assert!(stats.online);

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Packet::default(),
            })
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let stats = &manager.stats()[0];
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.tx_bytes, 128);

        manager.stop_iface(&address);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(manager.stats().is_empty());
    }

    #[test]
    fn radio_quality_counters_default_to_unreported() {
        let counters = InterfaceCounters::default();
        assert_eq!(counters.rssi(), None);
        assert_eq!(counters.snr(), None);
        assert_eq!(counters.quality(), None);

        let stats = InterfaceStats {
            address: AddressHash::new_empty(),
            name: "rnode".into(),
            kind: "RnodeInterface".into(),
            sent: 0,
            received: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            online: true,
            announces_received: 0,
            announces_sent: 0,
            announce_bytes_received: 0,
            announce_bytes_sent: 0,
            path_requests_received: 0,
            path_requests_sent: 0,
            protocol_violations: 0,
            ifac_violations: 0,
            packet_filter_hits: 0,
            rssi: None,
            snr: None,
            quality: None,
        };
        assert_eq!(stats.rssi, None);
    }

    #[test]
    fn radio_quality_publish_keeps_previous_readings() {
        let counters = InterfaceCounters::default();
        // RNode-style telemetry: RSSI -87 dBm, SNR 9.25 dB, quality 75%.
        counters.set_radio_quality(Some(-87), Some(9.25), Some(75.0));
        assert_eq!(counters.rssi(), Some(-87));
        assert_eq!(counters.snr(), Some(9.25));
        assert_eq!(counters.quality(), Some(75.0));

        // A partial update (RSSI only) keeps the other readings.
        counters.set_radio_quality(Some(-90), None, None);
        assert_eq!(counters.rssi(), Some(-90));
        assert_eq!(counters.snr(), Some(9.25));
        assert_eq!(counters.quality(), Some(75.0));

        // Values round-trip through the snapshot.
        let counters = InterfaceCounters::default();
        counters.set_radio_quality(Some(-100), Some(-7.5), Some(0.0));
        assert_eq!(counters.rssi(), Some(-100));
        assert_eq!(counters.snr(), Some(-7.5));
        assert_eq!(counters.quality(), Some(0.0));
    }
}
