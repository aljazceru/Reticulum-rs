use std::collections::HashMap;
use std::time::Duration;

use alloc::sync::Arc;
use rand_core::OsRng;
use tokio::sync::{broadcast, Mutex, MutexGuard};
use tokio::time;
use tokio_util::sync::CancellationToken;

#[cfg(not(test))]
use crate::channel::{self, Channel};
use crate::destination::link::{Link, LinkEventData, LinkEventSink, LinkExt, LinkExtHandlePacket,
    LinkHandleResult, LinkId, LinkPayload, LinkPayloadSink, LinkStatus};
use crate::resource::{
    self, manager::{pack_request, pack_response, request_id as make_request_id,
        RequestContext as RequestCtx, RequestEventData, RequestEvent,
        ResourceManager, ResourceStrategy},
    ResourceEvent, ResourceOptions,
};
use crate::destination::{DestinationAnnounce, DestinationDesc, DestinationHandleStatus,
    DestinationName, PlainInputDestination, SingleInputDestination, SingleOutputDestination};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::identity::PrivateIdentity;
use crate::iface::{InterfaceManager, InterfaceRxReceiver, RxMessage, TxMessage, TxMessageType};
use crate::packet::{
    DestinationType, Header, HeaderType, Packet, PacketContext, PacketDataBuffer, PacketType,
    PACKET_MDU,
};

mod announce_limits;
mod announce_table;
mod link_table;
mod packet_cache;
mod path_requests;
mod path_table;

use self::announce_limits::AnnounceLimits;
use self::announce_table::AnnounceTable;
use self::link_table::LinkTable;
use self::packet_cache::PacketCache;
use self::path_requests::{create_path_request_destination, PathRequests, TagBytes};
use self::path_table::PathTable;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
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

    timer_config: TimerConfig,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
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
pub (crate) struct BroadcastLinkPayloadSink(broadcast::Sender<LinkPayload>);

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

    path_requests: PathRequests,

    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,
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
            timer_config: TimerConfig::default(),
        }
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

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
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
            path_requests,
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

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.handler
            .lock()
            .await
            .send_packet(
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
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
    pub async fn mk_channel<M>(&self, link: Arc<Mutex<Link>>)
        -> Result<(Channel<M>, broadcast::Receiver<M>), RnsError>
    where M: channel::Message
    {
        Channel::new(self, link).await
    }

    #[allow(unused)]  // mocked out in the test build, so the linter
                      // would complain about dead code
    pub (crate) async fn bind_link_to_channel(
        &self,
        id: LinkId
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
        &mut self,
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
        self.handler.lock().await.resources.request_events.subscribe()
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
        self.send_resource_with_options(link, data, ResourceOptions::default()).await
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
        let mut resource = crate::resource::outbound::OutgoingResource::new(
            data,
            &link_guard,
            options,
        )?;

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
            let mut resource = crate::resource::outbound::OutgoingResource::new(
                packed, &link_guard, opts,
            )?;
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

        handler.resources.pending_requests.insert(rid, *link_guard.id());
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
                    RequestEvent::Response { request_id: rid, data, .. } if rid == request_id => {
                        return Some(data)
                    }
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
    pub async fn send_to_plain_destination(&self, name: DestinationName, data: &[u8]) -> Result<AddressHash, RnsError> {
        let destination = PlainInputDestination::new(
            reticulum_core::identity::EmptyIdentity,
            name,
        );
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
            self.find_out_link(&link_id).map(|link| (link, &self.link_out_event_tx))
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
            },
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
        id: LinkId
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        if self.channel_table.contains_key(&id) {
            return Err(RnsError::ChannelError);
        }

        let (tx, rx) = broadcast::channel(16);
        self.channel_table.insert(id, tx.into());

        Ok(rx)
    }
}

async fn handle_proof<'a>(
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>
) {
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
            handler.resources.handle_proof(&link_guard, packet.data.as_slice());
            drop(link_guard);
            handler.resources.cleanup();
        }
        return;
    }

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        let link_id = *link.id();

        if let LinkHandleResult::Activated = link.handle_packet(
            &handler.link_out_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            true
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
            false
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
            handler.send(TxMessage {
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
                if let Some((_hash, data)) =
                    handler.resources.assemble_completed(&link, &mut tx)
                {
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
                            &link_for_dispatch, rid, _time, path_hash, req_payload, handler,
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
            handler.resources.handle_proof(&link, packet.data.as_slice());
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
            let Some((rid, response)) = crate::resource::manager::unpack_response(plaintext)
            else {
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

async fn handle_data<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

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
            let channel_tx = handler.channel_table.get(link.id());

            let result = link.handle_packet(
                &handler.link_in_event_tx,
                channel_tx,
                packet,
                false
            );

            match result {
                LinkHandleResult::KeepAlive => {
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_packet(packet).await;
                }
                LinkHandleResult::MessageReceived(Some(proof)) => {
                    handler.send_packet(proof).await;
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
                    true
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

    if packet.header.destination_type == DestinationType::Plain {
        if let Some(_destination) = handler.plain_in_destinations.get(&packet.destination) {
            data_handled = true;

            handler.received_data_tx.send(ReceivedData {
                destination: packet.destination,
                data: packet.data,
            }).ok();
        }
        // Plain packets are never routed elsewhere: everyone on a shared
        // interface receives them directly.
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(_destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            handler.received_data_tx.send(ReceivedData {
                destination: packet.destination,
                data: packet.data,
            }).ok();
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
    mut handler: MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if handler.has_destination(&packet.destination) {
        // destination is local
        return;
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

    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
        let dest_hash = destination.identity.address_hash;
        let destination = Arc::new(Mutex::new(destination));

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

        handler.announce_table.add(packet, dest_hash, iface);

        handler
            .path_table
            .handle_announce(packet, packet.transport, iface);

        let retransmit = handler.config.retransmit;
        if retransmit {
            let transport_id = *handler.config.identity.address_hash();
            if let Some(message) = handler.announce_table.new_packet(&dest_hash, &transport_id) {
                handler.send(message).await;
            }
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(app_data),
        });
    }
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if let Some(request) = handler.path_requests.decode(packet.data.as_slice()) {
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
                "tp({}): send direct path response over {}",
                handler.config.name,
                iface
            );

            return;
        }

        if handler.config.retransmit {
            if let Some(entry) = handler.path_table.get(&request.destination) {
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

                let hops = entry.hops;

                handler
                    .announce_table
                    .add_response(request.destination, iface, hops);

                log::trace!(
                    "tp({}): scheduled remote path response to {} ({} hops) over {}",
                    handler.config.name,
                    request.destination,
                    hops,
                    iface
                );

                return;
            }
        }

        if let Some(packet) =
            handler
                .path_requests
                .generate_recursive(&request.destination, Some(iface), None)
        {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Broadcast(Some(iface)),
                    packet,
                })
                .await;
        }
    }
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, iface).await;
        true
    } else {
        false
    }
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut destination = destination.lock().await;
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
                    handler.send_packet(link.prove(&handler.link_in_event_tx)).await;

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
    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop,
    );

    send_to_next_hop(packet, &handler, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>
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
            LinkStatus::Stale if link.elapsed() > timer_config.in_link_stale + timer_config.in_link_close => {
                if let Some(packet) = link.teardown(&handler.link_in_event_tx).unwrap_or_else(|err| {
                    log::error!("tp({}): teardown stale in-link error: {err:?}", handler.config.name);
                    None
                }) {
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
                } else if link.elapsed() > timer_config.out_link_stale + timer_config.out_link_close {
                    if let Some(packet) = link.teardown(&handler.link_out_event_tx).unwrap_or_else(|err| {
                        log::error!(
                            "tp({}): teardown stale out-link error: {err:?}",
                            handler.config.name
                        );
                        None
                    }) {
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

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
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
                                handler,
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
        let transport = TransportConfig::default()
            .set_retransmit(true)
            .build();

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

        handle_announce(&announce, handler.lock().await, next_hop_iface).await;

        let data_packet: Packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"foo"),
            destination,
            ..Default::default()
        };
        let duplicate: Packet = data_packet;

        let different_packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"bar"),
            .. data_packet
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