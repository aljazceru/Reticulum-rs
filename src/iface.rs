pub mod hdlc;
pub mod local;

pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

#[cfg(all(feature = "iface-auto", target_os = "linux"))]
pub mod auto;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
#[cfg(feature = "iface-serial")]
pub mod ax25;
#[cfg(feature = "iface-serial")]
pub mod kiss;
#[cfg(feature = "iface-serial")]
pub mod serial;

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
use crate::packet::Packet;

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
        }
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_named(tx_cap, "", "")
    }

    /// Create a new interface channel registered under `name` (configuration
    /// name, used for statistics) and `kind` (interface type).
    pub fn new_channel_named(
        &mut self,
        tx_cap: usize,
        name: &str,
        kind: &str,
    ) -> InterfaceChannel {
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
        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }

                    should_send
                },
                TxMessageType::Direct(address) => address == iface.address,
            };

            if should_send && !iface.stop.is_cancelled() {
                let _ = iface.tx_send.send(message).await;
            }
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
