pub mod control;
pub mod hdlc;
pub mod local;

pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

#[cfg(all(feature = "iface-auto", target_os = "linux"))]
pub mod auto;
#[cfg(feature = "iface-serial")]
pub mod ax25;
#[cfg(feature = "iface-serial")]
pub mod kiss;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
#[cfg(feature = "iface-serial")]
pub mod serial;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

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
#[derive(Debug, Default)]
pub struct InterfaceCounters {
    sent: AtomicU64,
    received: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    online: AtomicBool,
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
}

/// Snapshot of the statistics of one interface
/// (compare `rnstatus` output of the Python reference implementation).
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
    pub stats: Arc<InterfaceCounters>,
}

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
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {} <{}:{}>", address, name, kind);

        let stop = CancellationToken::new();
        let stats = Arc::new(InterfaceCounters::default());
        stats.set_online(false);

        self.ifaces.push(LocalInterface {
            address,
            name: name.to_string(),
            kind: kind.to_string(),
            tx_send,
            stop: stop.clone(),
            stats: stats.clone(),
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

    /// Request tunnel synthesis for an interface
    /// (Python `Interface.wants_tunnel`).
    pub fn set_iface_wants_tunnel(&self, address: &AddressHash, wants: bool) -> bool {
        self.with_control(address, |control| control.wants_tunnel = wants)
            .is_some()
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
    pub fn received_announce(&self, address: &AddressHash) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_announce(now));
    }

    /// Account a sent announce on an interface
    /// (Python `Interface.sent_announce`).
    pub fn sent_announce(&self, address: &AddressHash) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_announce(now));
    }

    /// Account a received path request on an interface
    /// (Python `Interface.received_path_request`).
    pub fn received_path_request(&self, address: &AddressHash) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_path_request(now));
    }

    /// Account a sent path request on an interface
    /// (Python `Interface.sent_path_request`).
    pub fn sent_path_request(&self, address: &AddressHash) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_path_request(now));
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
}
