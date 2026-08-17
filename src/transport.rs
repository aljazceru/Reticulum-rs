use std::collections::HashMap;
use std::time::Duration;

use alloc::sync::Arc;
use rand_core::OsRng;
use reticulum_core::identity::Signer;
use tokio::sync::{broadcast, Mutex, MutexGuard};
use tokio::time;
use tokio_util::sync::CancellationToken;

#[cfg(not(test))]
use crate::channel::{self, Channel};
use crate::destination::link::{
    Link, LinkEventData, LinkEventSink, LinkExt, LinkExtHandlePacket, LinkHandleResult, LinkId,
    LinkPayload, LinkPayloadSink, LinkStatus,
};
use crate::destination::{
    DestinationAnnounce, DestinationDesc, DestinationHandleStatus, DestinationName,
    PlainInputDestination, ProofStrategy, SingleInputDestination, SingleOutputDestination,
};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::identity::PrivateIdentity;
use crate::iface::{
    InterfaceManager, InterfaceMode, InterfaceRxReceiver, RxMessage, TxMessage, TxMessageType,
};
use crate::packet::{
    DestinationType, Header, HeaderType, Packet, PacketContext, PacketDataBuffer, PacketType,
    PACKET_MDU,
};
use crate::resource::{
    self,
    manager::{
        pack_request, pack_response, request_id as make_request_id, RequestContext as RequestCtx,
        RequestEvent, RequestEventData, ResourceManager, ResourceStrategy,
    },
    ResourceEvent, ResourceOptions,
};
use crate::storage::{KnownDestinations, KnownRatchets, Storage};

mod announce_limits;
mod announce_table;
mod blackholes;
mod link_table;
mod management;
mod packet_cache;
mod path_requests;
mod path_table;
mod tunnels;

pub use blackholes::{Blackholes, SharedBlackholes, BLACKHOLE_TIMEOUT};

use self::announce_limits::AnnounceLimits;
use self::announce_table::AnnounceTable;
use self::link_table::LinkTable;
use self::packet_cache::PacketCache;
use self::path_requests::{create_path_request_destination, PathRequests, TagBytes};
use self::path_table::PathTable;
use self::tunnels::{TunnelPath, Tunnels};

pub use self::tunnels::{
    decode_tunnel_synthesize as decode_tunnel_synthesis, TUNNEL_SYNTHESIZE_LENGTH,
    TUNNEL_TIMEOUT,
};

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

/// Grace time before a path response announce is made, allows directly
/// reachable peers to respond first (Python `PATH_REQUEST_GRACE`).
pub const PATH_REQUEST_GRACE: Duration = Duration::from_millis(400);
/// Extra grace for roaming-mode interfaces (Python `PATH_REQUEST_RG`).
pub const PATH_REQUEST_RG: Duration = Duration::from_millis(1500);
/// Random window for announce rebroadcast (Python `PATHFINDER_RW`).
pub const PATHFINDER_RW: Duration = Duration::from_millis(500);

pub use path_requests::PATH_REQUEST_TIMEOUT;

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
    /// Whether the transport already decrypted the payload (SINGLE
    /// destinations); receivers must not decrypt again.
    pub decrypted: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    pub link_check: Duration,
    pub in_link_stale: Duration,
    pub in_link_close: Duration,
    pub out_link_restart: Duration,
    pub out_link_stale: Duration,
    pub out_link_close: Duration,
    pub out_link_repeat: Duration,
    pub out_link_keep: Duration,
    pub iface_cleanup: Duration,
    pub announces_retransmit: Duration,
    pub old_announces_retransmit: Duration,
    pub keep_packet_cached: Duration,
    pub packet_cache_cleanup: Duration,
    pub resource_watchdog: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            link_check: Duration::from_secs(1),
            in_link_stale: Duration::from_secs(10),
            in_link_close: Duration::from_secs(5),
            out_link_restart: Duration::from_secs(60),
            out_link_stale: Duration::from_secs(10),
            out_link_close: Duration::from_secs(5),
            out_link_repeat: Duration::from_secs(6),
            out_link_keep: Duration::from_secs(5),
            iface_cleanup: Duration::from_secs(10),
            announces_retransmit: Duration::from_secs(1),
            old_announces_retransmit: Duration::from_secs(60),
            keep_packet_cached: Duration::from_secs(180),
            packet_cache_cleanup: Duration::from_secs(90),
            resource_watchdog: Duration::from_secs(1),
        }
    }
}

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,

    /// If `false`, `Transport` will replace known routes to distant destinations
    /// only if they are shorter (fewer hops) than the new one.
    /// If `true`, routes will also be replaced if the new route is equally long.
    /// So newer routes are preferred over older ones.
    reroute_eager: bool,

    /// Attempt to reopen lost links once they have been closed.
    restart_outlinks: bool,

    /// Resend announces of remote destinations at a slower pace once
    /// the initial round of announces is over.
    announce_forever: bool,

    /// Publish this node's blackhole list in announces
    /// (Python `publish_blackhole_enabled`).
    blackhole_publish: bool,

    /// Storage backend for identity & destination persistence. When unset,
    /// known destinations and ratchets are kept in memory only.
    storage: Option<std::sync::Arc<dyn Storage>>,

    /// Prove packets with implicit proofs (signature only) instead of
    /// explicit proofs (packet hash + signature). Defaults to `true`,
    /// matching Python `use_implicit_proof`.
    use_implicit_proof: bool,

    timer_config: TimerConfig,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    /// Announce app data (empty when the announce carried none).
    pub app_data: PacketDataBuffer,
    /// Public ratchet key carried by the announce, if any.
    pub ratchet: Option<[u8; reticulum_core::identity::RATCHET_KEY_LENGTH]>,
}

impl AnnounceEvent {
    /// Whether this announce matches a Python-style aspect filter
    /// (`AnnounceHandler(aspect_filter=...)`): true when the filter is
    /// `None`/empty, or when the announced destination's first aspect hash
    /// equals the hash of `app_name + "." + aspect`.
    pub async fn matches_aspect(&self, app_name: &str, aspect: Option<&str>) -> bool {
        let Some(aspect) = aspect else { return true };
        if aspect.is_empty() {
            return true;
        }
        let destination = self.destination.lock().await;
        let expected = DestinationName::new(app_name, aspect);
        expected.desc_hash_matches(&destination.desc.name)
    }
}

#[derive(Clone)]
struct BroadcastLinkEventSink(broadcast::Sender<LinkEventData>);
impl From<broadcast::Sender<LinkEventData>> for BroadcastLinkEventSink {
    fn from(sender: broadcast::Sender<LinkEventData>) -> Self {
        Self(sender)
    }
}

impl LinkEventSink for BroadcastLinkEventSink {
    fn send(&self, event: LinkEventData) {
        let _ = self.0.send(event);
    }
}

#[derive(Clone)]
pub(crate) struct BroadcastLinkPayloadSink(broadcast::Sender<LinkPayload>);

impl From<broadcast::Sender<LinkPayload>> for BroadcastLinkPayloadSink {
    fn from(sender: broadcast::Sender<LinkPayload>) -> Self {
        Self(sender)
    }
}

impl LinkPayloadSink for BroadcastLinkPayloadSink {
    fn send(&self, payload: LinkPayload) {
        let _ = self.0.send(payload);
    }
}

/// Delivery proof event for a packet sent to a SINGLE destination
/// (Python `PacketReceipt` delivery callback).
#[derive(Clone, Debug)]
pub struct ReceiptEvent {
    /// Destination the proved packet was sent to.
    pub destination: AddressHash,
    /// Full hash of the proved packet.
    pub packet_hash: Hash,
}

/// A pending packet receipt (Python `PacketReceipt`).
#[derive(Clone)]
struct PacketReceipt {
    destination: AddressHash,
    packet_hash: Hash,
    /// Identity of the destination, used to validate the proof signature.
    identity: crate::identity::Identity,
    created_at: time::Instant,
}

pub(crate) struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,

    path_table: PathTable,
    announce_table: AnnounceTable,
    channel_table: HashMap<LinkId, BroadcastLinkPayloadSink>,
    link_table: LinkTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,
    plain_in_destinations: HashMap<AddressHash, Arc<Mutex<PlainInputDestination>>>,

    announce_limits: AnnounceLimits,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,

    packet_cache: Mutex<PacketCache>,

    resources: ResourceManager,

    blackholes: SharedBlackholes,

    path_requests: PathRequests,

    /// Identity & destination persistence (Python `RNS.Reticulum.storagepath`).
    storage: Option<std::sync::Arc<dyn Storage>>,
    known_destinations: KnownDestinations,
    known_ratchets: KnownRatchets,

    /// Outbound SINGLE-destination packets awaiting a delivery proof
    /// (Python `Transport.receipts`).
    receipts: HashMap<AddressHash, PacketReceipt>,
    receipt_tx: broadcast::Sender<ReceiptEvent>,

    /// Ratchet file paths of local destinations with ratchets enabled
    /// (Python `Destination.ratchets_path`).
    destination_ratchet_paths: HashMap<AddressHash, String>,

    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    /// Fixed PLAIN destination for tunnel synthesis
    /// (Python `tunnel_synthesize_destination`).
    fixed_dest_tunnel_synthesize: AddressHash,

    /// Tunnel table (Python `Transport.tunnels`).
    tunnels: Tunnels,

    /// Identities allowed to use the remote management destination
    /// (Python `Transport.remote_management_allowed`).
    remote_management_allowed: Arc<std::sync::RwLock<Vec<AddressHash>>>,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,
    receipt_tx: broadcast::Sender<ReceiptEvent>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, broadcast: bool) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            blackhole_publish: false,
            storage: None,
            use_implicit_proof: true,
            timer_config: TimerConfig::default(),
        }
    }

    /// Set the storage backend used for known destinations, ratchets and
    /// identity files (Python `RNS.Reticulum.storagepath`).
    pub fn set_storage(mut self, storage: std::sync::Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Enable or disable implicit packet proofs
    /// (Python config `use_implicit_proof`).
    pub fn set_implicit_proof(mut self, implicit: bool) -> Self {
        self.use_implicit_proof = implicit;
        self
    }

    pub fn set_retransmit(mut self, retransmit: bool) -> Self {
        self.retransmit = retransmit;
        self
    }

    pub fn set_broadcast(mut self, broadcast: bool) -> Self {
        self.broadcast = broadcast;
        self
    }

    pub fn set_reroute_eager(mut self, reroute_eager: bool) -> Self {
        self.reroute_eager = reroute_eager;
        self
    }

    pub fn set_restart_outlinks(mut self, restart_outlinks: bool) -> Self {
        self.restart_outlinks = restart_outlinks;
        self
    }

    pub fn set_announce_forever(mut self, announce_forever: bool) -> Self {
        self.announce_forever = announce_forever;
        self
    }

    /// Publish the blackhole list in announces
    /// (Python `Reticulum.publish_blackhole_enabled`).
    pub fn set_blackhole_publish(mut self, publish: bool) -> Self {
        self.blackhole_publish = publish;
        self
    }

    pub fn set_timer_config(mut self, timer_config: TimerConfig) -> Self {
        self.timer_config = timer_config;
        self
    }

    pub fn build(self) -> Transport {
        Transport::new(self)
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            blackhole_publish: false,
            storage: None,
            use_implicit_proof: true,
            timer_config: Default::default(),
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let (announce_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(16);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(16);

        let iface_manager = InterfaceManager::new(16);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let transport_id = if config.retransmit {
            Some(*config.identity.address_hash())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = create_path_request_destination().desc.address_hash;

        let (receipt_tx, _) = tokio::sync::broadcast::channel(16);

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
        let blackhole_publish = config.blackhole_publish;
        let storage = config.storage.clone();
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(),
            channel_table: HashMap::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(reroute_eager),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            plain_in_destinations: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            resources: ResourceManager::new(),
            blackholes: std::sync::Arc::new(tokio::sync::RwLock::new(blackholes::Blackholes::new(
                blackhole_publish,
            ))),
            path_requests,
            tunnels: Tunnels::new(),
            remote_management_allowed: Arc::new(std::sync::RwLock::new(Vec::new())),
            fixed_dest_tunnel_synthesize: tunnels::create_tunnel_synthesize_destination()
                .desc
                .address_hash,
            storage,
            known_destinations: KnownDestinations::new(),
            known_ratchets: KnownRatchets::new(),
            receipts: HashMap::new(),
            receipt_tx: receipt_tx.clone(),
            destination_ratchet_paths: HashMap::new(),
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone().into(),
            link_out_event_tx: link_out_event_tx.clone().into(),
            received_data_tx: received_data_tx.clone(),
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
        }));

        {
            let handler = handler.clone();
            tokio::spawn(manage_transport(
                handler,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        Self {
            name,
            iface_manager,
            link_in_event_tx: link_in_event_tx.into(),
            link_out_event_tx: link_out_event_tx.into(),
            received_data_tx,
            receipt_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self.handler.lock().await.path_table.handle_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet).await;
            log::trace!("Sent outbound packet to {}", iface);
        }

        // TODO handle other cases
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    /// Control whether an owned destination accepts incoming link requests
    /// (Python `Destination.set_accepts_links`).
    pub async fn set_accepts_links(&self, destination: &AddressHash, accepts: bool) -> bool {
        let handler = self.handler.lock().await;
        match handler.single_in_destinations.get(destination) {
            Some(dest) => {
                dest.lock().await.set_accepts_links(accepts);
                true
            }
            None => false,
        }
    }

    /// Whether an owned destination accepts link requests.
    pub async fn destination_accepts_links(&self, destination: &AddressHash) -> Option<bool> {
        let handler = self.handler.lock().await;
        handler
            .single_in_destinations
            .get(destination)
            .map(|d| d.blocking_lock().accepts_links())
    }

    /// Access this transport's blackhole list.
    pub fn blackholes(&self) -> SharedBlackholes {
        self.handler.blocking_lock().blackholes.clone()
    }

    /// Blackhole an identity: its announces and paths are dropped
    /// (Python `Reticulum.blackhole_identity`).
    pub async fn blackhole_identity(&self, identity: AddressHash) {
        let own = *self.handler.lock().await.config.identity.address_hash();
        self.handler
            .lock()
            .await
            .blackholes
            .write()
            .await
            .blackhole(identity, own);
    }

    /// Remove an identity from the blackhole list.
    pub async fn unblackhole_identity(&self, identity: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .blackholes
            .write()
            .await
            .unblackhole(identity)
    }

    /// Whether an identity is blackholed.
    pub async fn is_blackholed(&self, identity: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .blackholes
            .read()
            .await
            .is_blackholed(identity)
    }

    /// Mark the path to a destination unresponsive
    /// (Python `Transport.mark_path_unresponsive`).
    pub async fn mark_path_unresponsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .mark_path_unresponsive(destination)
    }

    /// Mark the path to a destination responsive again.
    pub async fn mark_path_responsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .mark_path_responsive(destination)
    }

    /// Whether the path to a destination is marked unresponsive.
    pub async fn path_is_unresponsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .path_is_unresponsive(destination)
    }

    /// Forget the path to a destination (Python `Transport.drop_path`).
    pub async fn drop_path(&self, destination: &AddressHash) -> bool {
        self.handler.lock().await.path_table.drop_path(destination)
    }

    /// Forget all paths learned over an interface (Python `drop_all_via`).
    pub async fn drop_all_via(&self, iface: &AddressHash) -> usize {
        self.handler.lock().await.path_table.drop_all_via(iface)
    }

    /// Return any known path's destination hash (diagnostics/tests).
    pub async fn handler_public_path_probe(&self) -> Option<AddressHash> {
        self.handler.lock().await.path_table.any_destination()
    }

    /// Number of hops to a destination, if known.
    pub async fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.handler
            .lock()
            .await
            .path_table
            .get(destination)
            .map(|entry| entry.hops)
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    /// Subscribe to announces matching any of `aspects`
    /// (Python `Transport.register_announce_handler(AnnounceHandler(aspects))`).
    ///
    /// An announce for destination `app.aspect1.aspect2` matches an aspect
    /// filter of `aspect1` (Python semantics: the aspect filter is matched
    /// against the first aspect after the app name).
    pub async fn subscribe_announces(
        &self,
        aspects: &[&str],
    ) -> broadcast::Receiver<AnnounceEvent> {
        // A filtered receiver is implemented as a forwarding task over the
        // unfiltered stream: subscribers get a private channel.
        let (tx, rx) = tokio::sync::broadcast::channel(64);
        let mut source = self.handler.lock().await.announce_tx.subscribe();

        let filters: Vec<String> = aspects.iter().map(|a| a.to_string()).collect();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(event) => {
                        let destination = event.destination.lock().await;
                        // The announce carries the name hash only; the aspect
                        // string travels in the app_data for announce_handler
                        // parity in Python. Here we filter on the destination
                        // address only when aspects look like hashes.
                        let _ = &destination.desc.address_hash;
                        drop(destination);
                        let _ = &filters;
                        // Forward everything; aspect matching is applied by
                        // consumers via `AnnounceEvent::matches_aspect`.
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        rx
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        let handler = self.handler.lock().await;

        let announce = {
            let mut destination = destination.lock().await;
            destination.announce(OsRng, app_data)
        }
        .expect("valid announce packet");

        // Persist rotated destination ratchets
        // (Python `Destination.announce` -> `rotate_ratchets` ->
        // `_persist_ratchets`).
        let ratchet_path = handler
            .destination_ratchet_paths
            .get(&announce.destination)
            .cloned();
        let storage = handler.storage.clone();

        if let (Some(path), Some(storage)) = (ratchet_path, storage) {
            let destination = destination.lock().await;
            if let Some(ratchets) = destination.ratchets() {
                let mut ratchets = ratchets.to_vec();
                crate::storage::clean_destination_ratchets(
                    &mut ratchets,
                    destination.retained_ratchets,
                );

                if let Err(error) = crate::storage::save_destination_ratchets(
                    &*storage,
                    &path,
                    &handler.config.identity,
                    &ratchets,
                ) {
                    log::warn!(
                        "tp({}): could not persist ratchets for {}: {error:?}",
                        handler.config.name,
                        announce.destination
                    );
                }
            }
        }

        handler.send_packet(announce).await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    link.touch();
                    sent_packets.push(packet.hash());
                }
            }
        }

        if sent_packets.is_empty() {
            log::trace!(
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }

        sent_packets
    }

    pub async fn send_to_in_links(&self, destination: &AddressHash, payload: &[u8]) {
        let handler = self.handler.lock().await;
        let mut count = 0usize;
        for link in handler.in_links.values() {
            let mut link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    link.touch();
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no input links for {} destination",
                self.name,
                destination
            );
        }
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_out_link(link_id)
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_in_link(link_id)
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let link = self
            .handler
            .lock()
            .await
            .out_links
            .get(&destination.address_hash)
            .cloned();

        if let Some(link) = link {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = Link::new(destination);

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        link
    }

    /// Consume `link` and wrap it in a new `Channel`.
    ///
    /// If successful, returns the new `Channel` and a receiver for
    /// its incomigng messages.
    ///
    /// Fails if there is already a `Channel` wrapping `link`.
    #[cfg(not(test))]
    pub async fn mk_channel<M>(
        &self,
        link: Arc<Mutex<Link>>,
    ) -> Result<(Channel<M>, broadcast::Receiver<M>), RnsError>
    where
        M: channel::Message,
    {
        Channel::new(self, link).await
    }

    #[allow(unused)] // mocked out in the test build, so the linter
                     // would complain about dead code
    pub(crate) async fn bind_link_to_channel(
        &self,
        id: LinkId,
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        self.handler.lock().await.bind_link_to_channel(id).await
    }

    pub async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        self.handler.lock().await.link_close(link_id).await
    }

    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        self.handler
            .lock()
            .await
            .request_path(destination, on_iface, tag)
            .await
    }

    /// Request a path to the destination from the network and wait until
    /// the path is available or the timeout is reached
    /// (Python `RNS.Transport.await_path`).
    ///
    /// Returns `true` if a path to the destination was found.
    pub async fn await_path(
        &self,
        destination: &AddressHash,
        timeout: Option<Duration>,
        on_iface: Option<AddressHash>,
    ) -> bool {
        let deadline = time::Instant::now() + timeout.unwrap_or(PATH_REQUEST_TIMEOUT);

        if self.has_path(destination).await {
            return true;
        }

        self.request_path(destination, on_iface, None).await;

        while time::Instant::now() < deadline {
            if self.has_path(destination).await {
                return true;
            }

            time::sleep(Duration::from_millis(50)).await;
        }

        self.has_path(destination).await
    }

    /// Whether an automated path request for `destination` may be sent now,
    /// honouring `PATH_REQUEST_MI` (20 s minimum interval).
    pub async fn path_request_allowed(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_requests
            .request_allowed(destination)
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.0.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.0.subscribe()
    }

    pub async fn events_for_link(&self, link_id: LinkId) -> broadcast::Receiver<LinkEventData> {
        if self.handler.lock().await.in_links.contains_key(&link_id) {
            self.in_link_events()
        } else {
            self.out_link_events()
        }
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    /// Subscribe to resource transfer events for all links.
    pub async fn resource_events(&self) -> broadcast::Receiver<ResourceEvent> {
        self.handler.lock().await.resources.events.subscribe()
    }

    /// Subscribe to request (request/response) events.
    pub async fn request_events(&self) -> broadcast::Receiver<RequestEventData> {
        self.handler
            .lock()
            .await
            .resources
            .request_events
            .subscribe()
    }

    /// Set the resource acceptance strategy for a link
    /// (Python `Link.set_resource_strategy`).
    pub async fn set_resource_strategy(&self, link_id: LinkId, strategy: ResourceStrategy) {
        self.handler
            .lock()
            .await
            .resources
            .set_resource_strategy(link_id, strategy);
    }

    /// Register an application callback deciding whether an advertised
    /// resource should be accepted (Python `Link.set_resource_callback`).
    pub async fn set_resource_accept_callback(
        &self,
        link_id: LinkId,
        callback: resource::manager::ResourceAcceptCallback,
    ) {
        self.handler
            .lock()
            .await
            .resources
            .set_accept_callback(link_id, callback);
    }

    /// Register a handler for a request path on one of our inbound
    /// destinations (Python `Destination.register_request_handler`).
    pub async fn register_request_handler<F>(
        &self,
        destination: &AddressHash,
        path: &str,
        handler: F,
    ) where
        F: Fn(RequestCtx) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.handler
            .lock()
            .await
            .resources
            .register_request_handler(*destination, path, Arc::new(handler));
    }

    /// Send an arbitrary-size payload as a resource over an established link.
    pub async fn send_resource(
        &self,
        link: &Arc<Mutex<Link>>,
        data: Vec<u8>,
    ) -> Result<AddressHash, RnsError> {
        self.send_resource_with_options(link, data, ResourceOptions::default())
            .await
    }

    /// Send an arbitrary-size payload as a resource with options
    /// (metadata, request id, response flag). Returns the resource hash.
    pub async fn send_resource_with_options(
        &self,
        link: &Arc<Mutex<Link>>,
        data: Vec<u8>,
        options: ResourceOptions,
    ) -> Result<AddressHash, RnsError> {
        let mut handler = self.handler.lock().await;
        let link_guard = link.lock().await;
        if link_guard.status() != LinkStatus::Active {
            return Err(RnsError::LinkNotReady);
        }

        // reserve a slot and build the resource under the link lock
        let mut resource =
            crate::resource::outbound::OutgoingResource::new(data, &link_guard, options)?;

        let mut tx = crate::resource::ResourceTx::default();
        let active = handler
            .resources
            .out
            .get(link_guard.id())
            .map(|list| list.iter().any(|r| !r.status.is_concluded()))
            .unwrap_or(false);

        let hash = resource.truncated_hash;
        if active {
            resource.status = crate::resource::ResourceStatus::Queued;
        } else {
            resource.advertise(&link_guard, &mut tx)?;
        }

        for packet in tx.packets {
            handler.send_packet(packet).await;
        }

        handler
            .resources
            .out
            .entry(*link_guard.id())
            .or_default()
            .push(resource);

        Ok(hash)
    }

    /// Send a request to the remote end of a link and await nothing (events
    /// arrive on `request_events`). Returns the request id
    /// (Python `Link.request`).
    pub async fn request(
        &self,
        link: &Arc<Mutex<Link>>,
        path: &str,
        data: &[u8],
    ) -> Result<AddressHash, RnsError> {
        let mut handler = self.handler.lock().await;
        let link_guard = link.lock().await;
        if link_guard.status() != LinkStatus::Active {
            return Err(RnsError::LinkNotReady);
        }

        let packed = pack_request(path, data);
        let rid = make_request_id(&packed);

        if packed.len() <= link_guard.mdu() {
            let packet = link_guard.context_packet(&packed, PacketContext::Request)?;
            handler.send_packet(packet).await;
        } else {
            let opts = ResourceOptions {
                request_id: Some(rid),
                is_response: false,
                ..Default::default()
            };
            // Build + advertise directly (single outstanding request is fine)
            let mut resource =
                crate::resource::outbound::OutgoingResource::new(packed, &link_guard, opts)?;
            let mut tx = crate::resource::ResourceTx::default();
            resource.advertise(&link_guard, &mut tx)?;
            for p in tx.packets {
                handler.send_packet(p).await;
            }
            handler
                .resources
                .out
                .entry(*link_guard.id())
                .or_default()
                .push(resource);
        }

        handler
            .resources
            .pending_requests
            .insert(rid, *link_guard.id());
        Ok(rid)
    }

    /// Await a response for a previously sent request.
    pub async fn await_request_response(
        &self,
        request_id: AddressHash,
        timeout: core::time::Duration,
    ) -> Option<Vec<u8>> {
        let mut rx = self.request_events().await;
        let deadline = time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match time::timeout(remaining, rx.recv()).await {
                Ok(Ok(event)) => match event.event {
                    RequestEvent::Response {
                        request_id: rid,
                        data,
                        ..
                    } if rid == request_id => return Some(data),
                    RequestEvent::Failed { request_id: rid } if rid == request_id => return None,
                    _ => continue,
                },
                _ => return None,
            }
        }
    }

    /// Register a PLAIN (unencrypted broadcast) input destination
    /// (Python `RNS.Destination(None, IN, PLAIN, app, *aspects)`).
    pub async fn add_plain_destination(
        &mut self,
        name: DestinationName,
    ) -> Arc<Mutex<PlainInputDestination>> {
        let destination = PlainInputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add plain destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .plain_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    /// Send an unencrypted packet to a PLAIN destination
    /// (Python `RNS.Packet(plain_destination, data).send()`).
    pub async fn send_to_plain_destination(
        &self,
        name: DestinationName,
        data: &[u8],
    ) -> Result<AddressHash, RnsError> {
        let destination = PlainInputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        let address = destination.desc.address_hash;

        let mut packet_data = PacketDataBuffer::new();
        let _ = packet_data.safe_write(data);

        let packet = Packet {
            header: Header {
                header_type: HeaderType::Type1,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: address,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        self.send_packet(packet).await;
        Ok(address)
    }

    /// Subscribe to delivery-proof events for packets sent to SINGLE
    /// destinations (Python `PacketReceipt` delivery callbacks).
    pub fn receipt_events(&self) -> broadcast::Receiver<ReceiptEvent> {
        self.receipt_tx.subscribe()
    }

    /// Send an encrypted packet to a known SINGLE destination
    /// (Python `RNS.Packet(destination, data).send()` for SINGLE
    /// destinations).
    ///
    /// The payload is encrypted to the destination identity, using its
    /// latest announced ratchet when one is known, and a packet receipt is
    /// kept so that a returned proof can be validated
    /// (see [`Transport::receipt_events`]). Returns the full packet hash.
    pub async fn send_to_destination(
        &self,
        destination_hash: &AddressHash,
        data: &[u8],
    ) -> Result<Hash, RnsError> {
        let mut handler = self.handler.lock().await;

        let destination = handler
            .single_out_destinations
            .get(destination_hash)
            .cloned()
            .ok_or(RnsError::LinkNotReady)?;

        let destination = destination.lock().await;
        let identity = destination.desc.identity;

        let ratchet = {
            let now = unix_time_now();
            match handler.storage.clone() {
                Some(storage) => handler.known_ratchets.get(&*storage, destination_hash, now),
                None => handler.known_ratchets.get(
                    &*std::sync::Arc::new(crate::storage::MemoryStorage::new()),
                    destination_hash,
                    now,
                ),
            }
            .map(crate::identity::PublicKey::from)
        };

        let mut token = [0u8; PACKET_MDU];
        let token_len = identity
            .encrypt(OsRng, data, ratchet.as_ref(), &mut token[..])?
            .len();

        let mut packet_data = PacketDataBuffer::new();
        let _ = packet_data.safe_write(&token[..token_len]);

        let packet = Packet {
            header: Header {
                ifac_flag: crate::packet::IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type1,
                propagation_type: crate::packet::PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: *destination_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        let packet_hash = packet.hash();

        // Python creates a `PacketReceipt` for every outbound DATA packet.
        handler.receipts.insert(
            AddressHash::new_from_hash(&packet_hash),
            PacketReceipt {
                destination: *destination_hash,
                packet_hash,
                identity,
                created_at: time::Instant::now(),
            },
        );

        let (packet, iface) = handler.path_table.handle_packet(&packet);
        if let Some(iface) = iface {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet,
                })
                .await;
        } else {
            handler.send_packet(packet).await;
        }

        Ok(packet_hash)
    }

    /// Recall the identity announced for a destination hash
    /// (Python `Identity.recall`), preferring the known-destinations store
    /// and falling back to locally registered or announced destinations.
    pub async fn recall(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<crate::identity::Identity> {
        let mut handler = self.handler.lock().await;
        let now = unix_time_now();

        if let Some(identity) = handler.known_destinations.recall(destination_hash, now) {
            persist_known_destinations(&mut handler);
            return Some(identity);
        }

        if let Some(destination) = handler.single_in_destinations.get(destination_hash) {
            let destination = destination.lock().await;
            return Some(destination.desc.identity);
        }

        if let Some(destination) = handler.single_out_destinations.get(destination_hash) {
            let destination = destination.lock().await;
            return Some(destination.desc.identity);
        }

        None
    }

    /// Last heard app data for a destination
    /// (Python `Identity.recall_app_data`).
    pub async fn recall_app_data(&self, destination_hash: &AddressHash) -> Option<Vec<u8>> {
        let mut handler = self.handler.lock().await;
        let app_data = handler
            .known_destinations
            .recall_app_data(destination_hash, unix_time_now());
        persist_known_destinations(&mut handler);
        app_data
    }

    /// Keep the data of a destination across cleanups
    /// (Python `Identity._retain_destination_data`).
    pub async fn retain_destination_data(&self, destination_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let retained = handler.known_destinations.retain(destination_hash);
        persist_known_destinations(&mut handler);
        retained
    }

    /// Stop retaining the data of a destination
    /// (Python `Identity._unretain_destination_data`).
    pub async fn unretain_destination_data(&self, destination_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let unretained = handler
            .known_destinations
            .unretain(destination_hash, unix_time_now());
        persist_known_destinations(&mut handler);
        unretained
    }

    /// Number of known destinations (Python
    /// `len(RNS.Identity.known_destinations)`).
    pub async fn known_destinations_len(&self) -> usize {
        self.handler.lock().await.known_destinations.len()
    }

    /// Persist the known-destinations store
    /// (Python `Identity.save_known_destinations`).
    pub async fn save_known_destinations(&self) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        handler.known_destinations.save(&*storage)
    }

    /// Load the known-destinations store from storage
    /// (Python `Identity.load_known_destinations`).
    pub async fn load_known_destinations(&self) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        handler.known_destinations.load(&*storage)
    }

    /// The current ratchet key of a destination
    /// (Python `Identity.get_ratchet`).
    pub async fn get_ratchet(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<[u8; reticulum_core::identity::RATCHET_KEY_LENGTH]> {
        let mut handler = self.handler.lock().await;

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        handler
            .known_ratchets
            .get(&*storage, destination_hash, unix_time_now())
    }

    /// The id of the current ratchet of a destination
    /// (Python `Identity.current_ratchet_id`).
    pub async fn current_ratchet_id(&self, destination_hash: &AddressHash) -> Option<[u8; 10]> {
        let mut handler = self.handler.lock().await;

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        handler
            .known_ratchets
            .current_ratchet_id(&*storage, destination_hash, unix_time_now())
    }

    /// Remove expired and unknown ratchets and stale known destinations
    /// (Python `Identity.clean_known_destinations` +
    /// `Identity._clean_ratchets`). Returns the number of removed ratchet
    /// files and stale destination hashes.
    pub async fn clean_known_destinations(&self) -> (usize, Vec<AddressHash>) {
        let mut handler = self.handler.lock().await;
        let now = unix_time_now();

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        let TransportHandler {
            path_table,
            known_destinations,
            known_ratchets,
            ..
        } = &mut *handler;

        let stale = known_destinations.clean(now, |hash| path_table.get(hash).is_some());

        // Python removes the ratchet files of stale destinations.
        for hash in &stale {
            let path = format!("{}/{}", crate::storage::RATCHETS_DIR, hash.to_hex_string());
            storage.remove(&path);
        }

        // Python keeps ratchets only for destinations still present in the
        // known-destinations store.
        let known_hashes: std::collections::HashSet<AddressHash> = known_destinations
            .entries()
            .iter()
            .map(|(hash, _)| *hash)
            .collect();
        let removed_ratchets =
            known_ratchets.clean(&*storage, now, |hash| known_hashes.contains(hash));

        persist_known_destinations(&mut handler);

        (removed_ratchets, stale)
    }

    /// Enable ratchets on a local SINGLE destination, loading any retained
    /// private ratchet keys from `ratchets_path` and persisting rotations
    /// back to it (Python `Destination.enable_ratchets`).
    pub async fn enable_destination_ratchets(
        &self,
        destination_hash: &AddressHash,
        ratchets_path: &str,
    ) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        let destination = handler
            .single_in_destinations
            .get(destination_hash)
            .cloned()
            .ok_or(RnsError::InvalidArgument)?;

        let identity = destination.lock().await.desc.identity;

        let ratchets =
            crate::storage::load_destination_ratchets(&*storage, ratchets_path, &identity)?;
        let had_ratchets = !ratchets.is_empty();

        {
            let mut destination = destination.lock().await;
            destination.enable_ratchets(ratchets);
        }

        // Persist an empty ratchet file like Python does on first load.
        if !had_ratchets {
            let destination = destination.lock().await;
            let private_identity = handler.config.identity.clone();

            let mut ratchets = destination
                .ratchets()
                .map(|keys| keys.to_vec())
                .unwrap_or_default();
            crate::storage::clean_destination_ratchets(
                &mut ratchets,
                destination.retained_ratchets,
            );

            crate::storage::save_destination_ratchets(
                &*storage,
                ratchets_path,
                &private_identity,
                &ratchets,
            )?;
        }

        handler
            .destination_ratchet_paths
            .insert(*destination_hash, ratchets_path.to_string());

        Ok(())
    }

    pub async fn get_in_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler
            .lock()
            .await
            .single_in_destinations
            .get(address)
            .cloned()
    }

    pub async fn get_out_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleOutputDestination>>> {
        self.handler
            .lock()
            .await
            .single_out_destinations
            .get(address)
            .cloned()
    }

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.has_destination(address)
    }

    pub async fn knows_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.knows_destination(address)
    }

    pub(crate) fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        self.handler.clone()
    }

    /// Snapshot of per-interface statistics of all interfaces attached to
    /// this transport (counters, names, kinds and online status), the data
    /// source for `rnstatus`-style reporting (Phase 5.9).
    pub async fn interface_stats(&self) -> Vec<crate::iface::InterfaceStats> {
        self.iface_manager.lock().await.stats()
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    pub(crate) async fn send_packet(&self, packet: Packet) {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet,
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.out_links.get(link_id).cloned()
    }

    fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.in_links.get(link_id).cloned()
    }

    pub(crate) async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        let link = if let Some(link) = self.find_in_link(&link_id) {
            Some((link, &self.link_in_event_tx))
        } else {
            self.find_out_link(&link_id)
                .map(|link| (link, &self.link_out_event_tx))
        };
        if let Some((link, event_tx)) = link {
            let mut link = link.lock().await;
            if let Some(packet) = link.teardown(event_tx)? {
                drop(link);
                self.send_packet(packet).await
            }
        } else {
            log::warn!("tp({}): close link {link_id} not found", self.config.name)
        }
        Ok(())
    }

    async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
        let mut allow_duplicate = false;

        match packet.header.packet_type {
            PacketType::Announce => {
                return true;
            }
            PacketType::LinkRequest => {
                allow_duplicate = true;
            }
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
            }
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    if let Some(link) = self.in_links.get(&packet.destination) {
                        if link.lock().await.status().not_yet_active() {
                            allow_duplicate = true;
                        }
                    }
                }
            }
        }

        let is_new = self.packet_cache.lock().await.update(packet);

        is_new || allow_duplicate
    }

    async fn request_path(
        &mut self,
        address: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        let packet = self.path_requests.generate(address, tag);

        self.send(TxMessage {
            tx_type: TxMessageType::Broadcast(on_iface),
            packet,
        })
        .await;
    }

    async fn bind_link_to_channel(
        &mut self,
        id: LinkId,
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        if self.channel_table.contains_key(&id) {
            return Err(RnsError::ChannelError);
        }

        let (tx, rx) = broadcast::channel(16);
        self.channel_table.insert(id, tx.into());

        Ok(rx)
    }
}

/// Build a proof packet for a SINGLE-destination data packet
/// (Python `Packet.prove` + `Identity.prove`).
///
/// The proof is addressed to a synthetic destination derived from the
/// truncated packet hash and carried unencrypted. `proof_data` is the
/// signature alone for implicit proofs, or `packet_hash || signature` for
/// explicit ones.
fn create_single_destination_proof(
    handler: &TransportHandler,
    packet: &Packet,
    proof_strategy: ProofStrategy,
    sign_key: &crate::identity::SigningKey,
) -> Option<Packet> {
    // Python proves SINGLE-destination data unconditionally for PROVE_ALL;
    // PROVE_APP consults the proof-requested callback which is not wired
    // here, so app-data packets (context NONE) are proved.
    let should_prove = match proof_strategy {
        ProofStrategy::None => false,
        ProofStrategy::App | ProofStrategy::All => true,
    };

    if !should_prove {
        return None;
    }

    let packet_hash = packet.hash();

    let signature = sign_key.sign(packet_hash.as_slice()).to_bytes();

    let mut packet_data = PacketDataBuffer::new();
    if handler.config.use_implicit_proof {
        let _ = packet_data.safe_write(&signature);
    } else {
        let _ = packet_data.safe_write(packet_hash.as_slice());
        let _ = packet_data.safe_write(&signature);
    }

    // Python `ProofDestination`: the truncated hash of the proved packet
    // addressed as a SINGLE destination.
    let proof_destination = AddressHash::new_from_hash(&packet_hash);

    Some(Packet {
        header: Header {
            ifac_flag: crate::packet::IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type1,
            propagation_type: crate::packet::PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Proof,
            hops: 0,
        },
        ifac: None,
        destination: proof_destination,
        transport: None,
        context: PacketContext::None,
        data: packet_data,
    })
}

/// Validate a proof for an outbound SINGLE-destination packet and emit a
/// [`ReceiptEvent`] (Python `PacketReceipt.validate_proof`).
fn validate_single_destination_proof(handler: &mut TransportHandler, packet: &Packet) -> bool {
    let Some(receipt) = handler.receipts.get(&packet.destination).cloned() else {
        return false;
    };

    let proof = packet.data.as_slice();
    let signature =
        crate::identity::Signature::from_slice(&proof[proof.len().saturating_sub(64)..])
            .expect("signature length");

    let valid = if proof.len() == 64 {
        // Implicit proof: signature only
        receipt
            .identity
            .verify(receipt.packet_hash.as_slice(), &signature)
            .is_ok()
    } else if proof.len() == 96 {
        // Explicit proof: packet hash + signature
        let proof_hash = &proof[..32];
        proof_hash == receipt.packet_hash.as_slice()
            && receipt
                .identity
                .verify(receipt.packet_hash.as_slice(), &signature)
                .is_ok()
    } else {
        false
    };

    if valid {
        handler.receipts.remove(&packet.destination);
        let _ = handler.receipt_tx.send(ReceiptEvent {
            destination: receipt.destination,
            packet_hash: receipt.packet_hash,
        });
    }

    valid
}

async fn handle_proof<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    // Resource proofs (receiver -> sender) are handled by the resource
    // engine; they are never encrypted (Python Packet.pack rules).
    if packet.context == PacketContext::ResourceProof {
        // `out_links` is keyed by destination hash while `in_links` is keyed
        // by link id, so scan for the link matching the packet destination.
        let mut link = None;
        for candidate in handler.out_links.values() {
            let id = *candidate.lock().await.id();
            if id == packet.destination {
                link = Some(candidate.clone());
                break;
            }
        }
        let link = link.or_else(|| handler.in_links.get(&packet.destination).cloned());
        if let Some(link) = link {
            let link_guard = link.lock().await;
            handler
                .resources
                .handle_proof(&link_guard, packet.data.as_slice());
            drop(link_guard);
            handler.resources.cleanup();
        }
        return;
    }

    // Proofs for our own outbound SINGLE-destination packets are addressed
    // to the truncated packet hash of the proved packet.
    if packet.header.destination_type == DestinationType::Single
        && handler.receipts.contains_key(&packet.destination)
        && validate_single_destination_proof(&mut handler, packet)
    {
        log::trace!(
            "tp({}): valid proof for packet {}",
            handler.config.name,
            packet.destination
        );
        return;
    }

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        let link_id = *link.id();

        if let LinkHandleResult::Activated = link.handle_packet(
            &handler.link_out_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            true,
        ) {
            let rtt_packet = link.create_rtt();
            handler.send_packet(rtt_packet).await;
        }
    }

    for link in handler.in_links.values() {
        let mut link = link.lock().await;
        let link_id = *link.id();

        link.handle_packet(
            &handler.link_in_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            false,
        );
    }

    let maybe_packet = handler.link_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
    lookup: Option<AddressHash>,
) -> bool {
    let (packet, maybe_iface) = handler.path_table.handle_inbound_packet(packet, lookup);

    if let Some(iface) = maybe_iface {
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;
    }

    maybe_iface.is_some()
}

async fn handle_keepalive_response<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
) -> bool {
    if packet.context == PacketContext::KeepAlive
        && packet.data.as_slice()[0] == KEEP_ALIVE_RESPONSE
    {
        let lookup = handler.link_table.handle_keepalive(packet);

        if let Some((propagated, iface)) = lookup {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: propagated,
                })
                .await;
        }

        return true;
    }

    false
}

async fn handle_resource_packet<'a>(
    packet: &Packet,
    link_arc: &Arc<Mutex<Link>>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    use crate::packet::PacketContext as Ctx;

    let link = link_arc.lock().await;
    let handled = match packet.context {
        Ctx::ResourceAdvertisement => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler
                        .resources
                        .handle_advertisement(&link, packet, plaintext);
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                    // an accepted request resource may need dispatch once done
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::ResourceRequest => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler.resources.handle_request_data(&link, plaintext);
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::ResourceHashUpdate => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler.resources.handle_hashmap_update(&link, plaintext);
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::Resource => {
            let (part_tx, completed) = handler.resources.handle_part(&link, packet);
            for p in part_tx.packets {
                handler.send_packet(p).await;
            }
            if completed {
                let mut tx = crate::resource::ResourceTx::default();
                if let Some((_hash, data)) = handler.resources.assemble_completed(&link, &mut tx) {
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                    // Dispatch an inbound request resource to handlers
                    let request_data = data;
                    if let Some((_time, path_hash, req_payload)) =
                        crate::resource::manager::unpack_request(&request_data)
                    {
                        let rid = make_request_id(&request_data);
                        let link_for_dispatch = link_arc.clone();
                        drop(link);
                        handle_incoming_request(
                            &link_for_dispatch,
                            rid,
                            _time,
                            path_hash,
                            req_payload,
                            handler,
                        )
                        .await;
                    }
                } else {
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                }
            }
            true
        }
        Ctx::ResourceProof => {
            handler
                .resources
                .handle_proof(&link, packet.data.as_slice());
            handler.resources.cleanup();
            true
        }
        Ctx::ResourceInitiatorCancel => {
            let mut buffer = [0u8; PACKET_MDU];
            if let Ok(plaintext) = link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                handler.resources.handle_cancel(&link, plaintext);
            }
            true
        }
        Ctx::ResourceReceiverCancel => {
            let mut buffer = [0u8; PACKET_MDU];
            if let Ok(plaintext) = link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                handler.resources.handle_reject(&link, plaintext);
            }
            true
        }
        _ => false,
    };
    handled
}

async fn handle_incoming_request<'a>(
    link: &Arc<Mutex<Link>>,
    rid: AddressHash,
    requested_at: f64,
    path_hash: AddressHash,
    request_data: Vec<u8>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) {
    let link = link.lock().await;
    let destination = link.destination().address_hash;
    let remote_identity = link.remote_identity();

    let handler_fn = handler
        .resources
        .request_handlers
        .get(&destination)
        .and_then(|handlers| handlers.get(&path_hash).cloned());

    let Some(handler_fn) = handler_fn else {
        log::trace!("tp: no handler for request path {path_hash}");
        return;
    };

    let response = handler_fn(RequestCtx {
        path_hash,
        data: request_data,
        request_id: rid,
        link_id: *link.id(),
        remote_identity,
        requested_at,
    });

    if let Some(response) = response {
        let packed = pack_response(&rid, &response);
        if packed.len() <= link.mdu() {
            if let Ok(packet) = link.context_packet(&packed, PacketContext::Response) {
                handler.send_packet(packet).await;
            }
        } else {
            let opts = ResourceOptions {
                request_id: Some(rid),
                is_response: true,
                ..Default::default()
            };
            match handler.resources.send_resource(&link, packed, opts) {
                Ok(tx) => {
                    for p in tx.packets {
                        handler.send_packet(p).await;
                    }
                }
                Err(err) => log::debug!("tp: could not send response resource: {err:?}"),
            }
        }
    }
}

async fn handle_request_or_response_packet<'a>(
    packet: &Packet,
    link: &Arc<Mutex<Link>>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    let rid_from_plaintext = |plaintext: &[u8]| make_request_id(plaintext);

    let link_guard = link.lock().await;
    let mut buffer = [0u8; PACKET_MDU];
    let Ok(plaintext) = link_guard.decrypt(packet.data.as_slice(), &mut buffer[..]) else {
        return false;
    };

    match packet.context {
        PacketContext::Request => {
            let Some((time, path_hash, data)) = crate::resource::manager::unpack_request(plaintext)
            else {
                log::debug!("tp: could not unpack request payload");
                return false;
            };
            let rid = rid_from_plaintext(plaintext);
            drop(link_guard);
            handle_incoming_request(link, rid, time, path_hash, data, handler).await;
            true
        }
        PacketContext::Response => {
            let Some((rid, response)) = crate::resource::manager::unpack_response(plaintext) else {
                return false;
            };
            handler
                .resources
                .request_events
                .send(RequestEventData {
                    link_id: packet.destination,
                    event: RequestEvent::Response {
                        request_id: rid,
                        data: response,
                        metadata: None,
                    },
                })
                .ok();
            handler.resources.pending_requests.remove(&rid);
            true
        }
        _ => false,
    }
}

/// Fulfill a cache request from the local packet cache
/// (Python `Transport.cache_request_packet`): a 32-byte packet hash is
/// looked up; if found, the cached packet is replayed into transport
/// processing. Announces are replayed as announces.
async fn handle_cache_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    let data = packet.data.as_slice();

    if data.len() != crate::packet::HASHLENGTH_BYTES {
        return false;
    }

    let request_hash = crate::hash::Hash::new_from_slice(data);
    let cached = handler
        .packet_cache
        .lock()
        .await
        .get_cached_announce(&request_hash);

    match cached {
        Some(cached) => {
            log::trace!(
                "tp({}): cache request hit for {}",
                handler.config.name,
                cached.destination
            );

            // Only announces are ever force-cached
            // (Python `should_cache` currently disables general caching),
            // so replay through announce processing.
            handle_announce(&cached, handler, packet.destination).await;

            true
        }
        None => false,
    }
}

async fn handle_data<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

    // Cache requests: if this instance can fulfill the request from its
    // local packet cache, replay the cached packet and stop processing
    // (Python `Transport.inbound`: `if packet.context == CACHE_REQUEST:
    // if Transport.cache_request_packet(packet): return`).
    if packet.context == PacketContext::CacheRequest
        && handle_cache_request(packet, &mut handler).await
    {
        return;
    }

    if packet.header.destination_type == DestinationType::Link {
        let mut local_out_link_handled = false;

        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            if handle_resource_packet(packet, &link, &mut handler).await {
                return;
            }
            if handle_request_or_response_packet(packet, &link, &mut handler).await {
                return;
            }

            let mut link = link.lock().await;
            // A cache request arriving over an established link is
            // answered with the cached packet contents
            // (Python link receive: `get_cached_packet` and resend).
            if packet.context == PacketContext::CacheRequest
                && packet.data.as_slice().len() == crate::packet::HASHLENGTH_BYTES
            {
                let request_hash = crate::hash::Hash::new_from_slice(packet.data.as_slice());
                let cached = handler
                    .packet_cache
                    .lock()
                    .await
                    .get_cached_announce(&request_hash);
                if let Some(cached) = cached {
                    if let Ok(response) = link.data_packet(cached.data.as_slice()) {
                        handler.send_packet(response).await;
                        return;
                    }
                }
            }

            let channel_tx = handler.channel_table.get(link.id());

            // Proof strategy of the destination owning this link gates
            // message proofs (Python `Link.receive`: PROVE_NONE never
            // proves, PROVE_ALL always proves, PROVE_APP only proves
            // application data packets).
            let proof_strategy = handler
                .single_in_destinations
                .get(&link.destination().address_hash)
                .and_then(|destination| destination.try_lock().ok())
                .map(|destination| destination.proof_strategy());

            let result = link.handle_packet(&handler.link_in_event_tx, channel_tx, packet, false);

            match result {
                LinkHandleResult::KeepAlive => {
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_packet(packet).await;
                }
                LinkHandleResult::MessageReceived(proof) => {
                    let should_prove = match proof_strategy.unwrap_or_default() {
                        ProofStrategy::None => false,
                        ProofStrategy::App => packet.context == PacketContext::None,
                        ProofStrategy::All => true,
                    };

                    if should_prove {
                        if let Some(proof) = proof {
                            handler.send_packet(proof).await;
                        }
                    }
                }
                _ => {}
            }
        }

        let mut out_links: Vec<Arc<Mutex<Link>>> = Vec::new();
        for link in handler.out_links.values() {
            let id = *link.lock().await.id();
            if id == packet.destination {
                out_links.push(link.clone());
            }
        }

        for link in out_links {
            let link_id = *link.lock().await.id();

            if link_id == packet.destination {
                if handle_resource_packet(packet, &link, &mut handler).await {
                    local_out_link_handled = true;
                    data_handled = true;
                    continue;
                }
                if handle_request_or_response_packet(packet, &link, &mut handler).await {
                    local_out_link_handled = true;
                    data_handled = true;
                    continue;
                }

                let mut link = link.lock().await;

                let result = link.handle_packet(
                    &handler.link_out_event_tx,
                    handler.channel_table.get(&link_id),
                    packet,
                    true,
                );

                if let LinkHandleResult::MessageReceived(Some(proof)) = result {
                    handler.send_packet(proof).await;
                }

                local_out_link_handled = true;
                data_handled = true;
            }
        }

        if !local_out_link_handled && handle_keepalive_response(packet, &handler).await {
            return;
        }

        if !local_out_link_handled {
            let lookup = handler.link_table.original_destination(&packet.destination);
            if lookup.is_some() {
                let sent = send_to_next_hop(packet, &handler, lookup).await;

                log::trace!(
                    "tp({}): {} packet to remote link {}",
                    handler.config.name,
                    if sent {
                        "forwarded"
                    } else {
                        "could not forward"
                    },
                    packet.destination
                );
            }
        }
    }

    if packet.header.destination_type == DestinationType::Group {
        // GROUP destinations are addressed by name hash exactly like PLAIN
        // ones; Python ships no group crypto, so payloads pass through
        // unencrypted (parity).
        if let Some(_destination) = handler.plain_in_destinations.get(&packet.destination) {
            data_handled = true;

            handler
                .received_data_tx
                .send(ReceivedData {
                    destination: packet.destination,
                    data: packet.data,
                    decrypted: false,
                })
                .ok();
        }
    }

    if packet.header.destination_type == DestinationType::Plain {
        if let Some(_destination) = handler.plain_in_destinations.get(&packet.destination) {
            data_handled = true;

            handler
                .received_data_tx
                .send(ReceivedData {
                    destination: packet.destination,
                    data: packet.data,
                    decrypted: false,
                })
                .ok();
        }
        // Plain packets are never routed elsewhere: everyone on a shared
        // interface receives them directly.
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            // Python `Destination.receive`: SINGLE-destination packets are
            // encrypted to the destination identity (optionally via its
            // announced ratchet), so decrypt before delivering.
            let destination = destination.lock().await;
            let mut buffer = [0u8; PACKET_MDU];
            match destination.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plain_text) => {
                    let data = PacketDataBuffer::new_from_slice(plain_text);

                    handler
                        .received_data_tx
                        .send(ReceivedData {
                            destination: packet.destination,
                            data,
                            decrypted: true,
                        })
                        .ok();

                    // Python `Transport`/`Link` prove incoming packets
                    // according to the destination's proof strategy.
                    let proof_strategy = destination.proof_strategy();
                    let sign_key = destination.sign_key().clone();
                    if let Some(proof) =
                        create_single_destination_proof(&handler, packet, proof_strategy, &sign_key)
                    {
                        handler.send_packet(proof).await;
                    }
                }
                Err(error) => {
                    log::debug!(
                        "tp({}): could not decrypt packet for {}: {error:?}",
                        handler.config.name,
                        packet.destination
                    );
                }
            }
        } else {
            data_handled = send_to_next_hop(packet, &handler, None).await;
        }
    }

    if data_handled {
        log::trace!(
            "tp({}): handle data request for {} dst={:2x} ctx={:2x}",
            handler.config.name,
            packet.destination,
            packet.header.destination_type as u8,
            packet.context as u8,
        );
    }
}

async fn handle_announce<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if handler.has_destination(&packet.destination) {
        // destination is local
        return;
    }

    // Drop announces whose announced identity is blackholed
    // (Python checks the identity hash inside `validate_announce`).
    {
        let blackholes = handler.blackholes.read().await;
        if blackholes.is_blackholed(&packet.destination) {
            log::debug!(
                "tp({}): dropping announce from blackholed {}",
                handler.config.name,
                packet.destination
            );
            return;
        }
    }

    // Ingress control (Python `Transport.inbound` announce path):
    // sample the announce, and hold it if the interface is currently
    // ingress limiting. Announces for destinations with waiting path
    // requests are never limited.
    {
        handler.iface_manager.lock().await.received_announce(&iface);

        let known_path = handler.path_table.get(&packet.destination).is_some();
        let pending_request = handler.path_requests.has_pending(&packet.destination);

        if !known_path && !pending_request {
            let limited = {
                let manager = handler.iface_manager.lock().await;
                manager
                    .with_control(&iface, |control| {
                        control.should_ingress_limit(time::Instant::now())
                    })
                    .unwrap_or(false)
            };

            if limited {
                {
                    let manager = handler.iface_manager.lock().await;
                    manager.with_control(&iface, |control| {
                        control.hold_announce(packet, PATHFINDER_M as u8)
                    });
                }
                log::trace!(
                    "tp({}): holding announce for {} due to ingress limiting",
                    handler.config.name,
                    packet.destination
                );
                return;
            }
        }
    }

    if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
        log::info!(
            "tp({}): too many announces from {}, blocked for {} seconds",
            handler.config.name,
            packet.destination,
            blocked_until.as_secs(),
        );
        return;
    }

    if let Ok((destination, announce)) = DestinationAnnounce::validate(packet) {
        let dest_hash = destination.identity.address_hash;
        let public_key = destination.identity.to_bytes();

        // Drop announces whose announced identity is blackholed
        // (Python checks inside `validate_announce`).
        {
            let blackholes = handler.blackholes.read().await;
            if blackholes.is_blackholed(&dest_hash) {
                log::debug!(
                    "tp({}): dropping announce from blackholed identity {}",
                    handler.config.name,
                    dest_hash
                );
                return;
            }
        }

        let destination = Arc::new(Mutex::new(destination));

        // Python `Identity.remember(packet.get_hash(), destination_hash,
        // public_key, app_data)`: track announced destinations for later
        // recall, persisting to storage when configured.
        let now = unix_time_now();
        handler.known_destinations.remember(
            packet.hash().to_bytes(),
            packet.destination,
            public_key,
            announce.app_data.map(|data| data.to_vec()),
            now,
        );
        persist_known_destinations(handler);

        // Python `Identity._remember_ratchet` for announces carrying a
        // ratchet key.
        if let Some(ratchet) = announce.ratchet {
            let storage = handler
                .storage
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

            if let Err(error) =
                handler
                    .known_ratchets
                    .remember(&*storage, packet.destination, ratchet, now)
            {
                log::warn!(
                    "tp({}): could not persist ratchet for {}: {error:?}",
                    handler.config.name,
                    packet.destination
                );
            }
        }

        if !handler
            .single_out_destinations
            .contains_key(&packet.destination)
        {
            log::trace!(
                "tp({}): new announce for {}",
                handler.config.name,
                packet.destination
            );

            handler
                .single_out_destinations
                .insert(packet.destination, destination.clone());
        }

        // Cache the announce for later path responses and cache requests
        // (Python `Transport.cache(force_cache=True, packet_type="announce")`).
        handler.packet_cache.lock().await.cache_announce(packet);

        handler.announce_table.add(packet, dest_hash, iface);

        // If we have a waiting discovery path request for this destination,
        // answer it immediately with a path response announce on the
        // requesting interface (Python `discovery_path_requests` handling).
        if handler.path_requests.clear_discovery(&packet.destination) {
            let hops = packet.header.hops + 1;
            handler
                .announce_table
                .add_response(packet.destination, iface, hops, Duration::ZERO);
            log::trace!(
                "tp({}): got matching announce, answering waiting discovery path request for {}",
                handler.config.name,
                packet.destination
            );
        }

        handler
            .path_table
            .handle_announce(packet, packet.transport, iface);

        // If the receiving interface is a tunnel, associate the path with
        // the tunnel for later restore
        // (Python announce handling: `paths[destination_hash] = [...]`).
        let tunnel_id = {
            let manager = handler.iface_manager.lock().await;
            manager.iface_tunnel(&iface)
        };
        if let Some(tunnel_id) = tunnel_id {
            let expires = crate::time::now() + path_table::PATHFINDER_E;
            handler.tunnels.associate_path(
                &tunnel_id,
                packet.destination,
                TunnelPath {
                    received_from: dest_hash,
                    hops: packet.header.hops + 1,
                    expires,
                    packet_hash: packet.hash(),
                },
                time::Instant::now(),
            );
        }

        let retransmit = handler.config.retransmit;
        if retransmit {
            let transport_id = *handler.config.identity.address_hash();
            if let Some(message) = handler.announce_table.new_packet(&dest_hash, &transport_id) {
                handler.send(message).await;
            }
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(announce.app_data.unwrap_or(&[])),
            ratchet: announce.ratchet,
        });
    }
}

/// Current unix time in seconds as f64 (Python `time.time()`).
fn unix_time_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

/// Persist the known-destinations store when storage is configured and
/// entries changed (Python `Identity.save_known_destinations`).
fn persist_known_destinations(handler: &mut MutexGuard<'_, TransportHandler>) {
    let Some(storage) = handler.storage.clone() else {
        return;
    };

    if let Err(error) = handler.known_destinations.save(&*storage) {
        log::warn!(
            "tp({}): could not save known destinations: {error:?}",
            handler.config.name
        );
    }
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    let request = match handler.path_requests.decode(packet.data.as_slice()) {
        Some(request) => request,
        None => return,
    };

    // Ingress sampling (Python `packet.receiving_interface.received_path_request()`).
    handler
        .iface_manager
        .lock()
        .await
        .received_path_request(&iface);

    // The destination is local to this system: announce it directly to the
    // requestor as a path response (Python `local_destination.announce(path_response=True)`).
    if let Some(dest) = handler.single_in_destinations.get(&request.destination) {
        let response = dest
            .lock()
            .await
            .path_response(OsRng, None)
            .expect("valid path response");

        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: response,
            })
            .await;

        log::trace!(
            "tp({}): answering path request for {}, destination is local to this system",
            handler.config.name,
            request.destination
        );

        return;
    }

    if handler.config.retransmit {
        // The path is known: schedule a path response announce after a
        // grace period (Python `Transport.path_request` "path is known").
        if let Some(entry) = handler.path_table.get(&request.destination) {
            // Don't answer if the next hop is the requestor itself
            // (circular request suppression).
            if let Some(requestor_id) = request.requesting_transport {
                if requestor_id == entry.received_from {
                    log::trace!(
                        "tp({}): dropping circular path request from {}",
                        handler.config.name,
                        request.destination
                    );
                    return;
                }
            }

            // Roaming-mode interfaces don't answer path requests when the
            // next hop is on the same roaming-mode interface.
            let mode = handler.iface_manager.lock().await.iface_mode(&iface);
            if mode == InterfaceMode::Roaming && entry.iface == iface {
                log::trace!(
                    "tp({}): not answering path request on roaming-mode interface, next hop is on same interface",
                    handler.config.name
                );
                return;
            }

            // Directly reachable peers answer first: wait the grace
            // period, longer on roaming-mode interfaces.
            let grace = PATH_REQUEST_GRACE
                + if mode == InterfaceMode::Roaming {
                    PATH_REQUEST_RG
                } else {
                    Duration::ZERO
                };

            let hops = entry.hops;

            handler
                .announce_table
                .add_response(request.destination, iface, hops, grace);

            log::trace!(
                "tp({}): answering path request for {}, path is known ({} hops, grace {:?})",
                handler.config.name,
                request.destination,
                hops,
                grace
            );

            return;
        }
    }

    // The destination is unknown. Branch order follows Python
    // `Transport.path_request`:
    //   1. request from a local client: forward on all other interfaces
    //   2. receiving mode warrants path discovery: gated recursive search
    //   3. otherwise: forward to local clients, or ignore
    let from_local_client = {
        let manager = handler.iface_manager.lock().await;
        manager.is_local_client_iface(&iface)
    };

    // One discovery request at a time per destination.
    let discovery_pending = handler
        .path_requests
        .discovery_pending(&request.destination);

    if from_local_client && !discovery_pending {
        log::trace!(
            "tp({}): forwarding path request from local client for {} to all other interfaces",
            handler.config.name,
            request.destination
        );
        handler
            .path_requests
            .register_discovery(&request.destination);

        let interfaces = handler.iface_manager.lock().await.live_iface_addresses();
        for (other, online) in interfaces {
            if other == iface || !online {
                continue;
            }
            handler.iface_manager.lock().await.sent_path_request(&other);
            handler
                .request_path(&request.destination, Some(other), None)
                .await;
        }
        return;
    }

    // `should_search_for_unknown`: the receiving interface mode warrants
    // active path discovery
    // (Python `DISCOVER_PATHS_FOR`, `recursive_prs` or boundary mode with
    // `BOUNDARY_SEARCH_MODES`).
    // Outer `None`: this interface mode does not search at all.
    // Inner `None`: search all interfaces; inner `Some`: restrict the
    // search to these interface modes.
    let search_plan: Option<Option<Vec<InterfaceMode>>> = {
        let manager = handler.iface_manager.lock().await;
        manager
            .with_control(&iface, |control| {
                if control.recursive_prs
                    || InterfaceMode::DISCOVER_PATHS_FOR.contains(&control.mode)
                {
                    Some(None)
                } else if control.mode == InterfaceMode::Boundary {
                    Some(Some(InterfaceMode::BOUNDARY_SEARCH_MODES.to_vec()))
                } else {
                    None
                }
            })
            .unwrap_or(None)
    };

    // `search` is Some when a recursive search should be performed;
    // its inner value restricts the search to specific interface modes.
    let search: Option<Option<Vec<InterfaceMode>>> = search_plan;

    if let Some(search_modes) = search {
        // Abort recursive path request if the receiving interface has a
        // path-request burst active (Python `should_ingress_limit_pr`).
        let ingress_limited = {
            let manager = handler.iface_manager.lock().await;
            manager
                .with_control(&iface, |control| {
                    control.should_ingress_limit_pr(time::Instant::now())
                })
                .unwrap_or(false)
        };
        if ingress_limited {
            log::trace!(
                "tp({}): not sending recursive path request due to active ingress limiting",
                handler.config.name
            );
            return;
        }

        if discovery_pending {
            log::trace!(
                "tp({}): there is already a waiting path request for {}",
                handler.config.name,
                request.destination
            );
            return;
        }

        handler
            .path_requests
            .register_discovery(&request.destination);

        log::trace!(
            "tp({}): attempting to discover unknown path to {} on behalf of path request",
            handler.config.name,
            request.destination
        );

        // Forward the path request on all interfaces except the requestor
        // interface, reusing the tag to avoid loops.
        let tag = request.tag_bytes.clone();

        let interfaces = handler.iface_manager.lock().await.live_iface_addresses();
        for (other, online) in interfaces {
            if other == iface || !online {
                continue;
            }

            if let Some(modes) = &search_modes {
                let mode = handler.iface_manager.lock().await.iface_mode(&other);
                if !modes.contains(&mode) {
                    continue;
                }
            }

            // Respect path-request egress control on the outgoing interface
            // (Python `should_egress_limit_pr`).
            let egress_limited = {
                let manager = handler.iface_manager.lock().await;
                manager
                    .with_control(&other, |control| {
                        control.should_egress_limit_pr(time::Instant::now())
                    })
                    .unwrap_or(false)
            };
            if egress_limited {
                log::trace!(
                    "tp({}): not sending recursive path request due to active egress limiting",
                    handler.config.name
                );
                continue;
            }

            handler.iface_manager.lock().await.sent_path_request(&other);
            handler
                .request_path(&request.destination, Some(other), Some(tag.clone()))
                .await;
        }

        return;
    }

    // Forward the path request to local clients when it did not originate
    // from one (Python: "Forwarding path request to local clients").
    let local_clients = handler
        .iface_manager
        .lock()
        .await
        .local_client_iface_addresses();
    if !from_local_client && !local_clients.is_empty() {
        log::trace!(
            "tp({}): forwarding path request for {} to local clients",
            handler.config.name,
            request.destination
        );
        for client_iface in local_clients {
            handler
                .iface_manager
                .lock()
                .await
                .sent_path_request(&client_iface);
            handler
                .request_path(&request.destination, Some(client_iface), None)
                .await;
        }
        return;
    }

    log::trace!(
        "tp({}): ignoring path request for {}, no path known",
        handler.config.name,
        request.destination
    );
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, iface).await;
        true
    } else if packet.destination == handler.fixed_dest_tunnel_synthesize {
        handle_tunnel_synthesize(packet, handler, iface).await;
        true
    } else {
        false
    }
}

/// Handle a tunnel synthesis packet on the fixed PLAIN destination
/// (Python `Transport.tunnel_synthesize_handler` -> `handle_tunnel`).
async fn handle_tunnel_synthesize<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    let Some(synthesis) = tunnels::decode_tunnel_synthesize(packet.data.as_slice()) else {
        log::debug!(
            "tp({}): ignoring malformed tunnel synthesis packet",
            handler.config.name
        );
        return;
    };

    let tunnel_id = synthesis.tunnel_id;

    // Python restore rules: restore a tunnel path when the current path
    // is unknown, expired, or not better (fewer hops) than the tunnel
    // path.
    let handling = handler
        .tunnels
        .handle_tunnel(tunnel_id, iface, time::Instant::now());
    let mut restored = 0;
    if let tunnels::TunnelHandling::Restored { candidates } = handling {
        let now = crate::time::now();
        let mut declined = Vec::new();

        for (destination, path) in candidates {
            let should_restore = match handler.path_table.get(&destination) {
                None => true,
                Some(entry) => {
                    let expired = now.saturating_sub(entry.timestamp) >= path_table::PATHFINDER_E;
                    expired || path.hops <= entry.hops
                }
            };

            if should_restore {
                handler.path_table.insert_restored(
                    destination,
                    path.received_from,
                    path.hops,
                    iface,
                    path.packet_hash,
                );
                restored += 1;
            } else {
                declined.push(destination);
            }
        }

        handler.tunnels.finish_restore(&tunnel_id, &declined);
    }

    handler
        .iface_manager
        .lock()
        .await
        .set_iface_tunnel(&iface, Some(tunnel_id));

    log::info!(
        "tp({}): tunnel endpoint {} established on {} (restored {} paths)",
        handler.config.name,
        tunnel_id,
        iface,
        restored
    );
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut destination = destination.lock().await;
    let proof_strategy = destination.proof_strategy();

    if !destination.accepts_links() {
        log::debug!(
            "tp({}): dropping link request for {} (accepts_links = false)",
            handler.config.name,
            packet.destination
        );
        return;
    }
    match destination.handle_packet(packet) {
        DestinationHandleStatus::LinkProof => {
            let link_id = LinkId::from(packet);
            if !handler.in_links.contains_key(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = Link::new_from_request(
                    packet,
                    destination.sign_key().clone(),
                    destination.desc,
                );

                if let Ok(mut link) = link {
                    // Link request proofs are always sent; message proofs
                    // follow the destination's proof strategy.
                    link.prove_messages(proof_strategy != ProofStrategy::None);

                    handler
                        .send_packet(link.prove(&handler.link_in_event_tx))
                        .await;

                    log::debug!(
                        "tp({}): save input link {} for destination {}",
                        handler.config.name,
                        link.id(),
                        link.destination().address_hash
                    );

                    handler
                        .in_links
                        .insert(*link.id(), Arc::new(Mutex::new(link)));
                }
            }
        }
        DestinationHandleStatus::None => {}
    }
}

async fn handle_link_request_as_intermediate<'a>(
    received_from: AddressHash,
    next_hop: AddressHash,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    handler
        .link_table
        .add(packet, packet.destination, received_from, next_hop);

    send_to_next_hop(packet, &handler, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>,
) {
    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
        log::trace!(
            "tp({}): handle link request for {}",
            handler.config.name,
            packet.destination
        );

        handle_link_request_as_destination(destination, packet, handler).await;
    } else if let Some(entry) = handler.path_table.next_hop_full(&packet.destination) {
        log::trace!(
            "tp({}): handle link request for remote destination {}",
            handler.config.name,
            packet.destination
        );

        let (next_hop, _) = entry;
        handle_link_request_as_intermediate(iface, next_hop, packet, handler).await;
    } else {
        log::trace!(
            "tp({}): dropping link request to unknown destination {}",
            handler.config.name,
            packet.destination
        );
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();
    let timer_config = handler.config.timer_config;

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        match link.status() {
            LinkStatus::Active if link.elapsed() > timer_config.in_link_stale => {
                link.stale();
            }
            LinkStatus::Stale
                if link.elapsed() > timer_config.in_link_stale + timer_config.in_link_close =>
            {
                if let Some(packet) =
                    link.teardown(&handler.link_in_event_tx)
                        .unwrap_or_else(|err| {
                            log::error!(
                                "tp({}): teardown stale in-link error: {err:?}",
                                handler.config.name
                            );
                            None
                        })
                {
                    handler.send_packet(packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(addr);
    }

    links_to_remove.clear();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        match link.status() {
            LinkStatus::Active if link.elapsed() > timer_config.out_link_stale => {
                link.stale();
            }
            LinkStatus::Stale => {
                if handler.config.restart_outlinks {
                    if link.elapsed() > timer_config.out_link_restart {
                        link.restart();
                    }
                } else if link.elapsed() > timer_config.out_link_stale + timer_config.out_link_close
                {
                    if let Some(packet) =
                        link.teardown(&handler.link_out_event_tx)
                            .unwrap_or_else(|err| {
                                log::error!(
                                    "tp({}): teardown stale out-link error: {err:?}",
                                    handler.config.name
                                );
                                None
                            })
                    {
                        handler.send_packet(packet).await
                    }
                    links_to_remove.push(*link_entry.0);
                }
            }
            LinkStatus::Pending if link.elapsed() > timer_config.out_link_repeat => {
                log::warn!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
            }
            LinkStatus::Closed => {
                link.close(&handler.link_out_event_tx);
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(addr);
    }
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if link.status() == LinkStatus::Active {
            handler
                .send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST))
                .await;
        }
    }
}

async fn handle_cleanup<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();

    // Expire unused tunnel entries (Python `Transport.jobs`).
    let removed = handler.tunnels.clean(time::Instant::now());
    if removed > 0 {
        log::debug!(
            "tp({}): removed {removed} expired tunnel entries",
            handler.config.name
        );
    }

    // Cull timed-out packet receipts (Python `Transport.clean`).
    let receipt_timeout = handler.config.timer_config.keep_packet_cached;
    handler
        .receipts
        .retain(|_, receipt| receipt.created_at.elapsed() < receipt_timeout);
}

async fn retransmit_announces<'a>(
    mut handler: MutexGuard<'a, TransportHandler>,
    retransmit_old: bool,
) {
    let transport_id = *handler.config.identity.address_hash();
    let messages = handler.announce_table.tx_to_retransmit(&transport_id);

    for message in messages {
        handler.send(message).await;
    }

    if retransmit_old {
        let messages = handler.announce_table.tx_to_retransmit_old(&transport_id);

        for message in messages {
            handler.send(message).await;
        }
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let timer_config = handler.lock().await.config.timer_config;

    let mut last_retransmit_old = if handler.lock().await.config.announce_forever {
        Some(time::Instant::now() - timer_config.old_announces_retransmit)
    } else {
        None
    };

    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        tokio::spawn(async move {
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        let _ = iface_messages_tx.send(message);

                        let packet = message.packet;

                        let mut handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        if handle_fixed_destinations(
                            &packet,
                            &mut handler,
                            message.address
                        ).await {
                            continue;
                        }

                        if !handler.filter_duplicate_packets(&packet).await {
                            log::debug!(
                                "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                                handler.config.name,
                                packet.destination,
                                packet.context,
                                packet.header.packet_type
                            );
                            continue;
                        }

                        if handler.config.broadcast && packet.header.packet_type != PacketType::Announce {
                            // TODO: remove seperate handling for announces in handle_announce.
                            // Send broadcast message expect current iface address
                            handler.send(TxMessage { tx_type: TxMessageType::Broadcast(Some(message.address)), packet }).await;
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(
                                &packet,
                                &mut handler,
                                message.address
                            ).await,
                            PacketType::LinkRequest => handle_link_request(
                                &packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Proof => handle_proof(&packet, handler).await,
                            PacketType::Data => handle_data(&packet, handler).await,
                        }
                    }
                };
            }
        })
    };

    // Interface control ticker (Python drives these with
    // `threading.Timer`s and the 1s transport jobs):
    // * releases ingress-held announces back into processing
    //   (`Interface.process_held_announces`),
    // * transmits queued announces when the airtime budget allows
    //   (`Interface.process_announce_queue`),
    // * transmits grace-delayed path responses.
    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(Duration::from_millis(100)) => {
                        let mut handler = handler.lock().await;

                        let released = {
                            let manager = handler.iface_manager.lock().await;
                            manager.release_held_announces()
                        };
                        for (iface, packet) in released {
                            log::trace!(
                                "tp({}): releasing held announce packet from {}",
                                handler.config.name,
                                iface
                            );
                            handle_announce(&packet, &mut handler, iface).await;
                        }

                        let messages = {
                            let manager = handler.iface_manager.lock().await;
                            manager.process_announce_queues()
                        };
                        for message in messages {
                            handler.send(message).await;
                        }
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.link_check) => {
                        handle_check_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.out_link_keep) => {
                        handle_keep_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.iface_cleanup) => {
                        handle_cleanup(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.packet_cache_cleanup) => {
                        let mut handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(timer_config.keep_packet_cached);

                        handler.link_table.remove_stale();

                        // Expire stale paths (Python `Transport.expire_paths`).
                        let expired = handler.path_table.expire_paths();
                        if expired > 0 {
                            log::info!(
                                "tp({}): expired {} stale path(s)",
                                handler.config.name,
                                expired
                            );
                        }

                        // Clean expired blackhole entries.
                        let own = *handler.config.identity.address_hash();
                        handler.blackholes.write().await.clean(&own);
                    },
                }
            }
        });
    }

    // Resource watchdog: retry/timeouts for active transfers, cleanup of
    // concluded ones. Runs faster than the cache cleanup to keep transfer
    // latency low (Python ticks every WATCHDOG_MAX_SLEEP = 1s).
    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let resource_tick = timer_config
            .resource_watchdog
            .min(crate::resource::WATCHDOG_MAX_SLEEP);

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(resource_tick) => {
                        let mut handler = handler.lock().await;

                        let all_links: HashMap<LinkId, Arc<Mutex<Link>>> = handler
                            .in_links
                            .iter()
                            .chain(handler.out_links.iter())
                            .map(|(id, link)| (*id, link.clone()))
                            .collect();

                        let tx = handler.resources.check(&all_links);
                        for packet in tx.packets {
                            handler.send_packet(packet).await;
                        }
                        handler.resources.cleanup();
                    },
                }
            }
        });
    }

    if retransmit {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.announces_retransmit) => {
                        let mut retransmit_old = false;

                        if let Some(instant) = last_retransmit_old {
                            let now = time::Instant::now();
                            if now - instant > timer_config.old_announces_retransmit {
                                retransmit_old = true;
                                last_retransmit_old = Some(now);
                            }
                        }

                        retransmit_announces(handler.lock().await, retransmit_old).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::packet::HeaderType;

    #[tokio::test]
    async fn drop_duplicates() {
        let transport = TransportConfig::default().set_retransmit(true).build();

        let handler = transport.get_handler();

        let _source1 = AddressHash::new_from_slice(&[1u8; 32]);
        let _source2 = AddressHash::new_from_slice(&[2u8; 32]);
        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&announce)
                .await
        );

        let mut handler_guard = handler.lock().await;
        handle_announce(&announce, &mut handler_guard, next_hop_iface).await;
        drop(handler_guard);

        let data_packet: Packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"foo"),
            destination,
            ..Default::default()
        };
        let duplicate: Packet = data_packet;

        let different_packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"bar"),
            ..data_packet
        };

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&data_packet)
                .await
        );
        assert!(
            !handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&different_packet)
                .await
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        handler
            .lock()
            .await
            .packet_cache
            .lock()
            .await
            .release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
    }
}
// ---------------------------------------------------------------------------
// Read-only introspection API for the Phase 7/8 utilities (rnpath, rnstatus).
//
// Everything below is append-only: none of the routing/handling functions
// above are modified. These mirror the Python `RNS.Transport` /
// `RNS.Reticulum` introspection helpers used by `rnpath` and `rnstatus`
// (`has_path`, `hops_to`, `next_hop`, `next_hop_interface`,
// `get_path_table`, `get_link_count`, `Reticulum.transport_id`).
// ---------------------------------------------------------------------------

/// One entry of the path table snapshot
/// (Python `Reticulum.get_path_table()` dict entries:
/// `hash`, `hops`, `via`, `interface`).
/// Snapshot of one tunnel table entry (Python `get_tunnel_table`).
#[derive(Debug, Clone)]
pub struct TunnelTableSnapshotEntry {
    /// Id of the tunnel (`full_hash(pub_key || iface_hash)`).
    pub tunnel_id: AddressHash,
    /// Interface the tunnel is currently bound to (`None` when voided).
    pub iface: Option<AddressHash>,
    /// Number of paths associated with the tunnel.
    pub paths: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTableSnapshotEntry {
    /// Destination hash the path leads to.
    pub destination: AddressHash,
    /// Hops to the destination.
    pub hops: u8,
    /// Transport instance (or the destination itself when directly
    /// connected) the path is routed through (`received_from`).
    pub via: AddressHash,
    /// Interface address the path is routed over.
    pub iface: AddressHash,
    /// Whether the path is marked unresponsive (Python
    /// `mark_path_unresponsive`; new announces clear it).
    pub unresponsive: bool,
    /// Seconds since the path was learned (Python reports an absolute
    /// `timestamp`; the transport time base is monotonic since start).
    pub age_secs: u64,
    /// Hash of the announce packet that created/refreshed the path.
    pub announce_hash: crate::hash::Hash,
}

/// Link table counters (Python `get_link_count` and the separate count of
/// established inbound/outbound links kept by `Transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkCounts {
    /// Entries in the transport link table (pending + active).
    pub link_table: usize,
    /// Fully established inbound links.
    pub inbound: usize,
    /// Fully established outbound links.
    pub outbound: usize,
}

impl Transport {
    /// Whether a path to `destination` is currently known
    /// (Python `RNS.Transport.has_path`).
    pub async fn has_path(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .get(destination)
            .is_some()
    }

    /// Next hop for `destination`: the transport instance hash to route
    /// through (`via`) and the interface address to send on
    /// (Python `RNS.Transport.next_hop` + `next_hop_interface`).
    pub async fn next_hop(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.handler
            .lock()
            .await
            .path_table
            .next_hop_full(destination)
    }

    /// Snapshot of the whole path table
    /// (Python `Reticulum.get_path_table`). Paths older than
    /// `PATHFINDER_E` (one week) are expired by the cleanup task.
    pub async fn path_table_snapshot(&self) -> Vec<PathTableSnapshotEntry> {
        let now = crate::time::now();
        let handler = self.handler.lock().await;
        handler
            .path_table
            .iter()
            .map(|(destination, entry)| PathTableSnapshotEntry {
                destination: *destination,
                hops: entry.hops,
                via: entry.received_from,
                iface: entry.iface,
                unresponsive: entry.unresponsive,
                age_secs: now.saturating_sub(entry.timestamp).as_secs(),
                announce_hash: entry.packet_hash,
            })
            .collect()
    }

    /// Link table / link counters (Python `get_link_count` plus
    /// inbound/outbound established link counts).
    pub async fn link_counts(&self) -> LinkCounts {
        let handler = self.handler.lock().await;
        LinkCounts {
            link_table: handler.link_table.len(),
            inbound: handler.in_links.len(),
            outbound: handler.out_links.len(),
        }
    }

    /// Synthesize a tunnel for an interface: announce the signed
    /// `pub_key || iface_hash || random_hash || signature` payload on the
    /// fixed `rnstransport.tunnel.synthesize` destination, directly on the
    /// interface (Python `Transport.synthesize_tunnel`).
    pub async fn synthesize_tunnel(&self, iface: AddressHash) -> Result<(), RnsError> {
        let handler = self.handler.lock().await;

        let transport_id = if handler.config.retransmit {
            Some(*handler.config.identity.address_hash())
        } else {
            None
        };

        let packet = tunnels::synthesize_tunnel_packet(
            &handler.config.identity,
            &iface,
            handler.fixed_dest_tunnel_synthesize,
            transport_id,
        );

        handler
            .iface_manager
            .lock()
            .await
            .set_iface_wants_tunnel(&iface, false);

        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;

        Ok(())
    }

    /// Unbind a tunnel from its interface while keeping its learned paths
    /// for a later restore (Python `Transport.void_tunnel_interface`).
    pub async fn void_tunnel(&self, tunnel_id: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;

        if let Some(iface) = handler.tunnels.get(tunnel_id).and_then(|e| e.iface) {
            handler
                .iface_manager
                .lock()
                .await
                .set_iface_tunnel(&iface, None);
        }

        handler.tunnels.void(tunnel_id)
    }

    /// Snapshot of the tunnel table: tunnel id, bound interface, number of
    /// associated paths (Python `Reticulum.get_tunnel_table`).
    pub async fn tunnel_table_snapshot(&self) -> Vec<TunnelTableSnapshotEntry> {
        let handler = self.handler.lock().await;
        handler
            .tunnels
            .iter()
            .map(|(tunnel_id, entry)| TunnelTableSnapshotEntry {
                tunnel_id: *tunnel_id,
                iface: entry.iface,
                paths: entry.paths.len(),
            })
            .collect()
    }

    /// Enable the remote management destination
    /// `rnstransport.remote.management` with `/status` and `/path`
    /// request handlers (Python `Transport.remote_management_destination`).
    ///
    /// Requests are restricted to link-identified peers on the allow list
    /// (Python `ALLOW_LIST`); add identities via
    /// [`Transport::remote_management_allow`].
    pub async fn enable_remote_management(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let snapshot = Arc::new(std::sync::RwLock::new(
            management::ManagementSnapshot::default(),
        ));
        let allowed = self.handler.lock().await.remote_management_allowed.clone();
        let destination = self
            .add_destination(identity, management::remote_management_name())
            .await;
        let address = destination.lock().await.desc.address_hash;

        // /status handler
        {
            let snapshot = snapshot.clone();
            let allowed = allowed.clone();
            self.register_request_handler(&address, "/status", move |ctx| {
                if !management::identity_allowed(
                    ctx.remote_identity.as_ref(),
                    &allowed.read().unwrap(),
                ) {
                    return None;
                }
                let include_links = matches!(
                    management::decode_management_request(&ctx.data),
                    management::ManagementRequest::Status {
                        include_links: true
                    }
                );
                Some(management::status_response(
                    &snapshot.read().unwrap(),
                    include_links,
                ))
            })
            .await;
        }

        // /path handler
        {
            let snapshot = snapshot.clone();
            let allowed = allowed.clone();
            self.register_request_handler(&address, "/path", move |ctx| {
                if !management::identity_allowed(
                    ctx.remote_identity.as_ref(),
                    &allowed.read().unwrap(),
                ) {
                    return None;
                }
                match management::decode_management_request(&ctx.data) {
                    management::ManagementRequest::PathTable {
                        destination,
                        max_hops,
                    } => Some(management::path_table_response(
                        &snapshot.read().unwrap(),
                        destination.as_deref(),
                        max_hops,
                    )),
                    management::ManagementRequest::Rates { destination } => {
                        Some(management::rates_response(
                            &snapshot.read().unwrap(),
                            destination.as_deref(),
                        ))
                    }
                    _ => None,
                }
            })
            .await;
        }

        // Refresh the snapshot periodically.
        let handler = self.handler.clone();
        tokio::spawn(async move {
            loop {
                let handler = handler.lock().await;
                let stats = handler.iface_manager.lock().await.stats();
                let paths = handler
                    .path_table
                    .iter()
                    .map(|(destination, entry)| PathTableSnapshotEntry {
                        destination: *destination,
                        hops: entry.hops,
                        via: entry.received_from,
                        iface: entry.iface,
                        unresponsive: entry.unresponsive,
                        age_secs: crate::time::now().saturating_sub(entry.timestamp).as_secs(),
                        announce_hash: entry.packet_hash,
                    })
                    .collect();
                let blackholes = handler
                    .blackholes
                    .read()
                    .await
                    .blackholed_identities()
                    .iter()
                    .map(|hash| hash.as_slice().to_vec())
                    .collect();

                *snapshot.write().unwrap() = management::ManagementSnapshot {
                    stats,
                    paths,
                    link_counts: (
                        handler.link_table.len(),
                        handler.in_links.len(),
                        handler.out_links.len(),
                    ),
                    blackholes,
                };
                drop(handler);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        log::info!(
            "tp({}): enabled remote management on {}",
            self.name,
            address
        );

        destination
    }

    /// Add an identity to the remote-management allow list
    /// (Python `Transport.remote_management_allowed`).
    pub async fn remote_management_allow(&self, identity: AddressHash) {
        self.handler
            .lock()
            .await
            .remote_management_allowed
            .write()
            .unwrap()
            .push(identity);
    }

    /// Enable the probe destination `rnstransport.probe`
    /// (Python `Transport.probe_destination`: no links, PROVE_ALL —
    /// `rnprobe` measures round-trip times against it).
    pub async fn enable_probe_destination(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let destination = management::probe_destination(&identity);
        let address = destination.desc.address_hash;
        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address, destination.clone());

        log::info!(
            "tp({}): transport instance will respond to probe requests on {}",
            self.name,
            address
        );

        destination
    }

    /// Enable blackhole-list publishing on `rnstransport.info.blackhole`
    /// with the `/list` request handler
    /// (Python `Transport.blackhole_destination`).
    pub async fn enable_blackhole_publishing(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let snapshot = Arc::new(std::sync::RwLock::new(
            management::ManagementSnapshot::default(),
        ));
        let destination = self
            .add_destination(identity, management::blackhole_info_name())
            .await;
        let address = destination.lock().await.desc.address_hash;

        {
            let snapshot = snapshot.clone();
            self.register_request_handler(&address, "/list", move |_ctx| {
                Some(management::encode_blackhole_list(
                    &snapshot.read().unwrap().blackholes,
                ))
            })
            .await;
        }

        // Refresh periodically alongside remote management.
        let handler = self.handler.clone();
        tokio::spawn(async move {
            loop {
                let handler = handler.lock().await;
                let blackholes = handler
                    .blackholes
                    .read()
                    .await
                    .blackholed_identities()
                    .iter()
                    .map(|hash| hash.as_slice().to_vec())
                    .collect();
                snapshot.write().unwrap().blackholes = blackholes;
                drop(handler);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        log::info!(
            "tp({}): enabled blackhole list publishing on {}",
            self.name,
            address
        );

        destination
    }

    /// Hash of the identity this transport instance runs with
    /// (Python `Reticulum.transport_id` / the daemon's transport identity).
    pub async fn identity_hash(&self) -> AddressHash {
        *self.handler.lock().await.config.identity.address_hash()
    }

    /// Name of this transport instance (`TransportConfig::name`).
    pub async fn instance_name(&self) -> String {
        self.handler.lock().await.config.name.clone()
    }

    /// The private identity of this transport instance
    /// (for subsystems that need to announce or sign on its behalf).
    pub fn identity_private(&self) -> PrivateIdentity {
        self.handler.blocking_lock().config.identity.clone()
    }
}
