//! Per-transport resource state: tracks outgoing/incoming resources per
//! link, routes resource packets and runs watchdog checks.

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};

use crate::destination::link::{Link, LinkId};
use crate::error::RnsError;
use crate::hash::AddressHash;
use crate::packet::Packet;

use super::{IncomingResource, OutgoingResource, ResourceAdvertisement, ResourceEvent,
            ResourceOptions, ResourceStatus, ResourceTx};

/// Default cap for decompression of incoming resources.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 5 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceStrategy {
    /// Reject all advertised resources (Python `Link.ACCEPT_NONE`).
    None,
    /// Let the application decide via the registered accept callback.
    App,
    /// Accept all advertised resources (Python `Link.ACCEPT_ALL`).
    All,
}

/// Callback deciding whether an advertised resource should be accepted.
pub type ResourceAcceptCallback =
    Arc<dyn Fn(&ResourceAdvertisement) -> bool + Send + Sync>;

/// Callback notified when an incoming advertisement was accepted.
pub type ResourceStartedCallback = Arc<dyn Fn(&ResourceAdvertisement) + Send + Sync>;

#[derive(Clone)]
pub struct RequestContext {
    /// Hash of the request path (truncated hash of the UTF-8 path string).
    pub path_hash: AddressHash,
    /// Request payload (already msgpack-unpacked from the wire).
    pub data: Vec<u8>,
    pub request_id: AddressHash,
    pub link_id: LinkId,
    pub remote_identity: Option<crate::identity::Identity>,
    pub requested_at: f64,
}

pub type RequestHandler =
    Arc<dyn Fn(RequestContext) -> Option<Vec<u8>> + Send + Sync>;

/// Async request handler: awaited on the async packet task.
pub type AsyncRequestHandler = Arc<
    dyn Fn(RequestContext) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug)]
pub(crate) struct SplitAssembly {
    pub(crate) data: Vec<u8>,
    pub(crate) metadata: Option<Vec<u8>>,
    /// Expected next segment index (segments must arrive contiguously:
    /// Python's sender only advertises segment n+1 after segment n's
    /// proof, so anything else is a hostile or broken peer).
    pub(crate) next_index: usize,
    /// Total segments and logical size fixed by segment one.
    pub(crate) total_segments: usize,
    pub(crate) data_size: usize,
    /// Last accepted segment time (stale assemblies expire).
    pub(crate) last_activity: f64,
}

/// Split assemblies whose sender disappears mid-transfer expire after
/// this long without progress (Python re-requests would keep a live
/// sender under the link RTT scale, not minutes).
const SPLIT_ASSEMBLY_TIMEOUT: f64 = 300.0;

/// Assemblies may only grow to their advertised logical size (plus a
/// small tolerance), never multiples of it.
const SPLIT_ASSEMBLY_GRACE_BYTES: f64 = 1024.0;

pub(crate) struct ResourceManager {
    pub out: HashMap<LinkId, Vec<OutgoingResource>>,
    pub incoming: HashMap<LinkId, Vec<IncomingResource>>,
    pub strategies: HashMap<LinkId, ResourceStrategy>,
    pub accept_callbacks: HashMap<LinkId, ResourceAcceptCallback>,
    pub started_callbacks: HashMap<LinkId, ResourceStartedCallback>,
    /// Registered request handlers per destination hash, keyed by path hash.
    pub request_handlers: HashMap<AddressHash, HashMap<AddressHash, RequestHandler>>,
    /// Pending outbound requests: request id -> link.
    pub pending_requests: HashMap<AddressHash, LinkId>,
    /// Responses that completed before the caller began awaiting them,
    /// retained until collected (broadcast retains no history).
    /// Async request handlers by (destination, path hash).
    pub async_request_handlers: HashMap<AddressHash, HashMap<AddressHash, AsyncRequestHandler>>,
    pub completed_responses: HashMap<AddressHash, Option<Vec<u8>>>,
    /// Accumulated bytes of split resources by original hash
    /// (Python appends per-segment assembled data to storage).
    pub split_assembly: HashMap<crate::hash::Hash, SplitAssembly>,
    pub events: broadcast::Sender<ResourceEvent>,
    pub request_events: broadcast::Sender<RequestEventData>,
    pub max_decompressed_size: usize,
    pub max_request_size: Option<usize>,
    pub max_response_size: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum RequestEvent {
    /// A response arrived for a pending request.
    Response {
        request_id: AddressHash,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    /// Progress of a resource-backed response.
    Progress { request_id: AddressHash, progress: f64 },
    /// The request failed or was rejected.
    Failed { request_id: AddressHash },
}

#[derive(Clone, Debug)]
pub struct RequestEventData {
    pub link_id: LinkId,
    pub event: RequestEvent,
}

#[allow(dead_code)]
impl ResourceManager {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        let (request_events, _) = broadcast::channel(64);
        Self {
            out: HashMap::new(),
            incoming: HashMap::new(),
            strategies: HashMap::new(),
            accept_callbacks: HashMap::new(),
            started_callbacks: HashMap::new(),
            request_handlers: HashMap::new(),
            pending_requests: HashMap::new(),
            async_request_handlers: HashMap::new(),
            completed_responses: HashMap::new(),
            split_assembly: HashMap::new(),
            events,
            request_events,
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_request_size: None,
            max_response_size: None,
        }
    }

    pub fn set_resource_strategy(&mut self, link_id: LinkId, strategy: ResourceStrategy) {
        self.strategies.insert(link_id, strategy);
    }

    pub fn resource_strategy(&self, link_id: LinkId) -> ResourceStrategy {
        self.strategies.get(&link_id).copied().unwrap_or(ResourceStrategy::None)
    }

    pub fn set_accept_callback(
        &mut self,
        link_id: LinkId,
        callback: ResourceAcceptCallback,
    ) {
        self.accept_callbacks.insert(link_id, callback);
    }

    pub fn set_started_callback(
        &mut self,
        link_id: LinkId,
        callback: ResourceStartedCallback,
    ) {
        self.started_callbacks.insert(link_id, callback);
    }

    pub fn register_request_handler(
        &mut self,
        destination: AddressHash,
        path: &str,
        handler: RequestHandler,
    ) {
        let path_hash = crate::hash::Hash::new_from_slice(path.as_bytes());
        let path_hash = AddressHash::new_from_hash(&path_hash);
        self.request_handlers
            .entry(destination)
            .or_default()
            .insert(path_hash, handler);
    }

    pub fn deregister_request_handler(&mut self, destination: AddressHash, path: &str) {
        let path_hash = crate::hash::Hash::new_from_slice(path.as_bytes());
        let path_hash = AddressHash::new_from_hash(&path_hash);
        if let Some(handlers) = self.request_handlers.get_mut(&destination) {
            handlers.remove(&path_hash);
        }
    }

    /// Create, store and advertise an outgoing resource on `link`.
    /// Returns the packets that must be transmitted.
    pub fn send_resource(
        &mut self,
        link: &Link,
        data: Vec<u8>,
        opts: ResourceOptions,
    ) -> Result<ResourceTx, RnsError> {
        let active = self
            .out
            .get(link.id())
            .map(|list| list.iter().any(|r| !r.status.is_concluded()))
            .unwrap_or(false);

        let mut resource = OutgoingResource::new(data, link, opts)?;
        let mut tx = ResourceTx::default();

        if active {
            resource.status = ResourceStatus::Queued;
        } else {
            resource.advertise(link, &mut tx)?;
        }

        self.out.entry(*link.id()).or_default().push(resource);
        Ok(tx)
    }

    /// Handle a decrypted resource advertisement plaintext.
    /// Returns packets to transmit.
    pub fn handle_advertisement(
        &mut self,
        link: &Link,
        advertisement_packet: &Packet,
        plaintext: &[u8],
    ) -> ResourceTx {
        let mut tx = ResourceTx::default();
        let adv = match ResourceAdvertisement::unpack(plaintext) {
            Ok(adv) => adv,
            Err(err) => {
                log::debug!("resource: could not decode advertisement: {err:?}");
                return tx;
            }
        };

        // Request resources: like responses, they must correspond to an
        // actually pending local request (a registered request handler on
        // the link's destination). Without one, the resource can never be
        // serviced — reject instead of allocating state
        // (Python `Link.receive` only accepts advertised resources whose
        // `is_request` matches a live `waiting_requests` entry).
        if adv.is_request() {
            let size_ok = self
                .max_request_size
                .map(|max| adv.data_size <= max)
                .unwrap_or(true);
            if !size_ok || !self.has_request_handlers(link) {
                log::debug!(
                    "resource: rejecting request advertisement ({} handlers for this destination)",
                    if self.has_request_handlers(link) { "oversized / no" } else { "no" }
                );
                let mut reject = IncomingResource::reject_packet_for(&adv, link);
                tx.packets.append(&mut reject);
                return tx;
            }
            self.accept(link, advertisement_packet, &adv, &mut tx);
            return tx;
        }

        if adv.is_response() {
            let pending = self
                .pending_requests
                .get(&adv.request_id.unwrap_or(AddressHash::new_empty()))
                .copied();
            let size_ok = self
                .max_response_size
                .map(|max| adv.data_size <= max)
                .unwrap_or(true);
            if !size_ok || pending.is_none() {
                log::debug!("resource: rejecting response advertisement");
                let mut reject = IncomingResource::reject_packet_for(&adv, link);
                tx.packets.append(&mut reject);
                if let Some(rid) = adv.request_id {
                    self.request_events.send(RequestEventData {
                        link_id: *link.id(),
                        event: RequestEvent::Failed { request_id: rid },
                    }).ok();
                }
                return tx;
            }
            self.accept(link, advertisement_packet, &adv, &mut tx);
            return tx;
        }

        // Plain resource: apply strategy
        match self.resource_strategy(*link.id()) {
            ResourceStrategy::None => {}
            ResourceStrategy::All => self.accept(link, advertisement_packet, &adv, &mut tx),
            ResourceStrategy::App => {
                let accept = self
                    .accept_callbacks
                    .get(link.id())
                    .map(|cb| cb(&adv))
                    .unwrap_or(false);
                if accept {
                    self.accept(link, advertisement_packet, &adv, &mut tx);
                } else {
                    let mut reject = IncomingResource::reject_packet_for(&adv, link);
                    tx.packets.append(&mut reject);
                }
            }
        }

        tx
    }

    fn accept(
        &mut self,
        link: &Link,
        advertisement_packet: &Packet,
        adv: &ResourceAdvertisement,
        tx: &mut ResourceTx,
    ) {
        let incoming = match IncomingResource::accept(advertisement_packet, &adv.pack(), link)
        {
            Ok(r) => r,
            Err(err) => {
                log::debug!("resource: could not accept resource: {err:?}");
                return;
            }
        };

        if self
            .incoming
            .get(link.id())
            .map(|list| list.iter().any(|r| r.hash == incoming.hash))
            .unwrap_or(false)
        {
            log::debug!("resource: advertisement for ongoing transfer, ignoring");
            return;
        }

        // Initialise the hashmap from the advertisement slice and start
        // requesting parts.
        let mut incoming = incoming;
        let hashmap = adv.hashmap.clone();
        incoming.hashmap_update(0, &hashmap);

        if let Some(cb) = self.started_callbacks.get(link.id()) {
            cb(adv);
        }

        let mut part_tx = ResourceTx::default();
        incoming.request_next(link, &mut part_tx);

        let _ = self.events.send(ResourceEvent {
            link_id: *link.id(),
            hash: incoming.hash,
            status: incoming.status,
            progress: 0.0,
            data: None,
            metadata: None,
            advertisement: Some(adv.clone()),
        });

        self.incoming.entry(*link.id()).or_default().push(incoming);
        tx.packets.extend(part_tx.packets);
    }

    /// Register an async request handler (awaited on the async packet
    /// task).
    pub fn register_async_request_handler(
        &mut self,
        destination: AddressHash,
        path: &str,
        handler: AsyncRequestHandler,
    ) {
        let path_hash = AddressHash::new_from_slice(path.as_bytes());
        self.async_request_handlers
            .entry(destination)
            .or_default()
            .insert(path_hash, handler);
    }

    /// Look up the async handler for a destination/path.
    pub fn async_request_handler(
        &self,
        destination: &AddressHash,
        path_hash: &AddressHash,
    ) -> Option<AsyncRequestHandler> {
        self.async_request_handlers
            .get(destination)
            .and_then(|handlers| handlers.get(path_hash))
            .cloned()
    }

    /// Whether any request handler is registered for the link's
    /// destination (requests without a handler can never be serviced).
    fn has_request_handlers(&self, link: &Link) -> bool {
        self.request_handlers
            .contains_key(&link.destination().address_hash)
    }

    /// Handle RESOURCE_REQ plaintext for a link.
    pub fn handle_request_data(
        &mut self,
        link: &Link,
        plaintext: &[u8],
    ) -> ResourceTx {
        let mut tx = ResourceTx::default();
        let prefix_offset = if plaintext.first() == Some(&super::HASHMAP_IS_EXHAUSTED) {
            1 + super::MAPHASH_LEN
        } else {
            1
        };
        // Requests are a flag byte, optionally a map hash, and a full
        // resource hash. Validate before slicing malformed network input.
        if plaintext.len() < prefix_offset + 32 {
            return tx;
        }
        let resource_hash_prefix = &plaintext[prefix_offset..];
        if resource_hash_prefix.len() < 32 {
            return tx;
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&resource_hash_prefix[..32]);
        let resource_hash = crate::hash::Hash::new(hash_bytes);

        let mut matched = false;
        if let Some(resources) = self.out.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.hash == resource_hash && !resource.status.is_concluded() {
                    resource.request(link, plaintext, &mut tx);
                    matched = true;
                }
            }
        }
        if !matched {
            log::trace!("resource: part request for unknown resource");
        }
        tx
    }

    /// Handle a received resource part (unencrypted ciphertext chunk).
    /// Returns (tx, just_completed) for assembly handling.
    pub fn handle_part(
        &mut self,
        link: &Link,
        packet: &Packet,
    ) -> (ResourceTx, bool) {
        let mut tx = ResourceTx::default();
        let mut assembled = false;

        if let Some(resources) = self.incoming.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.status.is_concluded() {
                    continue;
                }
                if resource.receive_part(packet, link, &mut tx) {
                    assembled = true;
                }
            }
        }

        (tx, assembled)
    }

    /// Assemble a completed incoming resource on this link (first match).
    /// Sends the proof and emits events; returns the assembled data when
    /// this was the final segment.
    pub fn assemble_completed(
        &mut self,
        link: &Link,
        tx: &mut ResourceTx,
    ) -> Option<(crate::hash::Hash, Vec<u8>)> {
        let resources = self.incoming.get_mut(link.id())?;
        for resource in resources.iter_mut() {
            if resource.assembled.is_some() || resource.status != ResourceStatus::Assembling {
                continue;
            }
            match resource.assemble(link, self.max_decompressed_size) {
                Ok(data) => {
                    resource.status = ResourceStatus::Complete;
                    resource.prove(link, &resource.assembled.clone().unwrap(), tx);
                    resource.last_activity = super::unix_time();

                    let progress = resource.progress();
                    let advertisement = resource.advertisement_of();
                    let is_response = resource.is_response;
                    let request_id = resource.request_id;
                    let is_final = resource.segment_index == resource.total_segments;

                    let (event_data, event_metadata, full_data) = if resource.split {
                        let assembly = self
                            .split_assembly
                            .entry(resource.original_hash)
                            .or_insert_with(|| SplitAssembly {
                                data: Vec::new(),
                                metadata: None,
                                next_index: 1,
                                total_segments: resource.total_segments,
                                data_size: resource.advertisement_of().data_size,
                                last_activity: super::unix_time(),
                            });

                        // Segment invariants: contiguous, no duplicates,
                        // and a consistent logical transfer (index, total
                        // and size may not change mid-assembly).
                        let advertisement = resource.advertisement_of();
                        let inconsistent = resource.segment_index != assembly.next_index
                            || resource.total_segments != assembly.total_segments
                            || advertisement.data_size != assembly.data_size;
                        if inconsistent {
                            resource.status = ResourceStatus::Corrupt;
                            self.split_assembly.remove(&resource.original_hash);
                            let _ = self.events.send(ResourceEvent {
                                link_id: *link.id(),
                                hash: resource.hash,
                                status: ResourceStatus::Corrupt,
                                progress: 0.0,
                                data: None,
                                metadata: None,
                                advertisement: Some(advertisement),
                            });
                            continue;
                        }

                        if resource.segment_index == 1 && assembly.metadata.is_none() {
                            assembly.metadata = resource.metadata.clone();
                        }
                        assembly.data.extend_from_slice(&data);
                        assembly.next_index += 1;
                        assembly.last_activity = super::unix_time();

                        if is_final {
                            let Some(complete) = self.split_assembly.remove(&resource.original_hash)
                            else {
                                resource.status = ResourceStatus::Corrupt;
                                let _ = self.events.send(ResourceEvent {
                                    link_id: *link.id(),
                                    hash: resource.hash,
                                    status: ResourceStatus::Corrupt,
                                    progress: resource.progress(),
                                    data: None,
                                    metadata: None,
                                    advertisement: Some(resource.advertisement_of()),
                                });
                                continue;
                            };
                            (
                                Some(complete.data.clone()),
                                complete.metadata.clone(),
                                Some(complete.data),
                            )
                        } else {
                            (None, None, None)
                        }
                    } else {
                        (Some(data.clone()), resource.metadata.clone(), Some(data.clone()))
                    };

                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash: resource.hash,
                        status: ResourceStatus::Complete,
                        progress,
                        data: event_data,
                        metadata: event_metadata.clone(),
                        advertisement: Some(advertisement),
                    });

                    let response_rid = if is_response && is_final { request_id } else { None };
                    if let (Some(request_id), Some(full_data)) = (response_rid, full_data.as_ref()) {
                        let event = match unpack_response(full_data) {
                            Some((rid, response)) if rid == request_id => {
                                // Retain for late awaiters before emitting.
                                self.completed_responses.insert(rid, Some(response.clone()));
                                RequestEvent::Response {
                                    request_id: rid,
                                    data: response,
                                    metadata: event_metadata.clone(),
                                }
                            }
                            Some((rid, response)) => RequestEvent::Response {
                                request_id: rid,
                                data: response,
                                metadata: event_metadata.clone(),
                            },
                            // A response resource with metadata is a FILE
                            // response (Python `Link.resource_concluded`:
                            // `if resource.has_metadata: handle_response(
                            // ..., resource.data, ..., metadata=...)`):
                            // the raw bytes are the response, no
                            // `[rid, data]` envelope exists.
                            None if event_metadata.is_some() => {
                                self.completed_responses
                                    .insert(request_id, Some(full_data.clone()));
                                RequestEvent::Response {
                                    request_id,
                                    data: full_data.clone(),
                                    metadata: event_metadata.clone(),
                                }
                            }
                            None => RequestEvent::Failed { request_id },
                        };
                        self.request_events
                            .send(RequestEventData { link_id: *link.id(), event })
                            .ok();
                        self.pending_requests.remove(&request_id);
                    }

                    if let Some(full_data) = full_data {
                        return Some((resource.hash, full_data));
                    }
                }
                Err(err) => {
                    log::debug!("resource: assembly failed: {err:?}");
                    resource.status = ResourceStatus::Corrupt;
                    if resource.split {
                        self.split_assembly.remove(&resource.original_hash);
                    }
                    let hash = resource.hash;
                    let advertisement = resource.advertisement_of();
                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash,
                        status: ResourceStatus::Corrupt,
                        progress: resource.progress(),
                        data: None,
                        metadata: None,
                        advertisement: Some(advertisement),
                    });
                }
            }
        }
        None
    }

    /// Handle RESOURCE_HMU plaintext.
    pub fn handle_hashmap_update(&mut self, link: &Link, plaintext: &[u8]) -> ResourceTx {
        if let Some(resources) = self.incoming.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if plaintext.len() >= 32
                    && plaintext[..32] == resource.hash.as_slice()[..32]
                {
                    resource.hashmap_update_packet(plaintext);
                    let mut tx = ResourceTx::default();
                    resource.request_next(link, &mut tx);
                    return tx;
                }
            }
        }
        ResourceTx::default()
    }

    /// Handle RESOURCE_PRF payload for outgoing resources. When a split
    /// segment completes, the prepared next segment is advertised
    /// immediately (Python `validate_proof` -> `next_segment.advertise()`).
    pub fn handle_proof(&mut self, link: &Link, proof_data: &[u8], tx: &mut ResourceTx) {
        if proof_data.len() != 64 {
            return;
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&proof_data[..32]);
        let resource_hash = crate::hash::Hash::new(hash_bytes);

        let mut next_to_advertise: Option<OutgoingResource> = None;
        let mut completed_hashes: Vec<(crate::hash::Hash, f64, ResourceAdvertisement)> = Vec::new();

        if let Some(resources) = self.out.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.hash != resource_hash
                    || resource.status == ResourceStatus::Complete
                {
                    continue;
                }
                if resource.validate_proof(proof_data) {
                    completed_hashes.push((resource.hash, resource.progress(), resource.advertisement()));

                    // Advertise the next segment of a split resource.
                    if resource.split && resource.segment_index < resource.total_segments {
                        // Prepare lazily if not pre-built.
                        if resource.next_segment.is_none() {
                            match resource.prepare_next_segment(link) {
                                Ok(next) => resource.next_segment = next,
                                Err(error) => {
                                    log::debug!("resource: next-segment prep failed: {error:?}")
                                }
                            }
                        }
                        if let Some(mut next) = resource.take_next_segment() {
                            let _ = next.advertise(link, tx);
                            next_to_advertise = Some(*next);
                        }
                    }
                }
            }
        }

        for (hash, progress, advertisement) in completed_hashes {
            let _ = self.events.send(ResourceEvent {
                link_id: *link.id(),
                hash,
                status: ResourceStatus::Complete,
                progress,
                data: None,
                metadata: None,
                advertisement: Some(advertisement),
            });
        }

        if let Some(next) = next_to_advertise {
            log::debug!(
                "resource: advertising segment {}/{} of {}",
                next.segment_index,
                next.total_segments,
                next.original_hash
            );
            self.out.entry(*link.id()).or_default().push(next);
        }
    }

    /// Handle RESOURCE_ICL (initiator cancel) plaintext.
    pub fn handle_cancel(&mut self, link: &Link, plaintext: &[u8]) {
        if plaintext.len() < 32 {
            return;
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&plaintext[..32]);
        let resource_hash = crate::hash::Hash::new(hash_bytes);

        if let Some(resources) = self.incoming.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.hash == resource_hash && !resource.status.is_concluded() {
                    resource.status = ResourceStatus::Failed;
                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash: resource_hash,
                        status: ResourceStatus::Failed,
                        progress: 0.0,
                        data: None,
                        metadata: None,
                        advertisement: Some(resource.advertisement_of()),
                    });
                }
            }
        }
    }

    /// Handle RESOURCE_RCL (receiver reject) plaintext.
    pub fn handle_reject(&mut self, link: &Link, plaintext: &[u8]) {
        if plaintext.len() < 32 {
            return;
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&plaintext[..32]);
        let resource_hash = crate::hash::Hash::new(hash_bytes);

        if let Some(resources) = self.out.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.hash == resource_hash && !resource.status.is_concluded() {
                    resource.status = ResourceStatus::Rejected;
                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash: resource_hash,
                        status: ResourceStatus::Rejected,
                        progress: 0.0,
                        data: None,
                        metadata: None,
                        advertisement: Some(resource.advertisement()),
                    });
                }
            }
        }
    }

    /// Watchdog pass over all resources. Returns packets to send.
    pub fn check(&mut self, links: &HashMap<LinkId, Arc<Mutex<Link>>>) -> ResourceTx {
        let mut tx = ResourceTx::default();
        let mut failed_events: Vec<(LinkId, crate::hash::Hash, ResourceStatus, f64, ResourceAdvertisement)> = Vec::new();

        let link_ids: Vec<LinkId> = self.out.keys().copied().collect();
        for link_id in link_ids {
            let Some(link) = links.get(&link_id).cloned() else {
                continue;
            };
            let Ok(link) = link.try_lock() else { continue };
            if let Some(resources) = self.out.get_mut(&link_id) {
                let any_active_snapshot = resources.iter().any(|r| {
                    !r.status.is_concluded() && r.status != ResourceStatus::Queued
                });
                let mut advertised_any = false;
                let mut i = 0;
                while i < resources.len() {
                    let tx_advertised_this_sweep = advertised_any;
                    let (hash, failed, progress, advertisement) = {
                        let resource = &mut resources[i];
                        if resource.status.is_concluded() {
                            i += 1;
                            continue;
                        }
                        if resource.status == ResourceStatus::Queued {
                            // Python queues new resources until the current
                            // transfer on the link concluded: advertise at
                            // most ONE queued resource per link per sweep
                            // (the oldest first), so concurrent transfers
                            // never compete on the same link. The
                            // any-active snapshot is taken before the
                            // mutable borrow of this element.
                            if !any_active_snapshot && !tx_advertised_this_sweep {
                                let _ = resource.advertise(&link, &mut tx);
                                advertised_any = true;
                            }
                            i += 1;
                            continue;
                        }
                        let failed = resource.check(&link, &mut tx);
                        (resource.hash, failed, resource.progress(), resource.advertisement())
                    };
                    if failed {
                        failed_events.push((link_id, hash, ResourceStatus::Failed, progress, advertisement));
                    }
                    advertised_any |= tx_advertised_this_sweep;
                    i += 1;
                }
            }
        }

        let link_ids: Vec<LinkId> = self.incoming.keys().copied().collect();
        for link_id in link_ids {
            let Some(link) = links.get(&link_id).cloned() else {
                continue;
            };
            let Ok(link) = link.try_lock() else { continue };
            if let Some(resources) = self.incoming.get_mut(&link_id) {
                let mut i = 0;
                while i < resources.len() {
                    let (hash, failed, progress, advertisement) = {
                        let resource = &mut resources[i];
                        if resource.status.is_concluded() {
                            i += 1;
                            continue;
                        }
                        let failed = resource.check(&link, &mut tx);
                        (resource.hash, failed, resource.progress(), resource.advertisement_of())
                    };
                    if failed {
                        failed_events.push((link_id, hash, ResourceStatus::Failed, progress, advertisement));
                    }
                    i += 1;
                }
            }
        }

        for (link_id, hash, status, progress, advertisement) in failed_events {
            let _ = self.events.send(ResourceEvent {
                link_id,
                hash,
                status,
                progress,
                data: None,
                metadata: None,
                advertisement: Some(advertisement),
            });
        }

        tx
    }

    /// Drop concluded resources to free memory.
    pub fn cleanup(&mut self) {
        let abandoned: HashSet<crate::hash::Hash> = self
            .incoming
            .values()
            .flat_map(|list| list.iter())
            .filter(|resource| {
                resource.split
                    && matches!(
                        resource.status,
                        ResourceStatus::Failed
                            | ResourceStatus::Corrupt
                            | ResourceStatus::Rejected
                    )
            })
            .map(|resource| resource.original_hash)
            .collect();
        self.out.retain(|_, list| {
            list.retain(|r| !r.status.is_concluded());
            !list.is_empty()
        });
        self.incoming.retain(|_, list| {
            list.retain(|r| !r.status.is_concluded());
            !list.is_empty()
        });
        self.split_assembly
            .retain(|hash, _| !abandoned.contains(hash));

        // A split assembly whose sender stopped after a SUCCESSFUL
        // non-final segment has no live resource left to fail it: expire
        // stale assemblies so an abandoned (or hostile) sender cannot pin
        // unbounded memory (Python writes segments to disk instead and
        // cleans its temporary files).
        let now = super::unix_time();
        self.split_assembly.retain(|_, assembly| {
            // next_index == 1 means nothing was accepted yet.
            assembly.next_index > 0
                && (assembly.data.len() as f64) < (assembly.data_size as f64) * 2.0 + SPLIT_ASSEMBLY_GRACE_BYTES
                && now < assembly.last_activity + SPLIT_ASSEMBLY_TIMEOUT
        });
    }
}

/// Unpack a packed response `[request_id, response]`.
pub fn unpack_response(data: &[u8]) -> Option<(AddressHash, Vec<u8>)> {
    let mut cursor: &[u8] = data;
    if rmp::decode::read_array_len(&mut cursor).ok()? != 2 {
        return None;
    }
    let len = rmp::decode::read_bin_len(&mut cursor).ok()? as usize;
    if cursor.len() < len || len != 16 {
        return None;
    }
    let request_id = AddressHash::new(cursor[..len].try_into().ok()?);
    let rest = &cursor[len..];
    // The response value may be any msgpack element (Python packs the
    // handler's return value directly). Binary values are unwrapped to
    // their contents — the convention for opaque payload echoes — while
    // every other element (dicts, ints, bools, ...) is returned as its
    // raw encoding for the caller to interpret.
    let mut value_cursor: &[u8] = rest;
    let value = rmpv::decode::read_value(&mut value_cursor).ok()?;
    let consumed = rest.len() - value_cursor.len();
    match value {
        rmpv::Value::Binary(bytes) => Some((request_id, bytes.to_vec())),
        _ => Some((request_id, rest[..consumed].to_vec())),
    }
}

/// Wrap opaque bytes as a msgpack bin value (Python request handlers
/// receive `data` as bytes; responses must be valid msgpack elements,
/// so binary responses are bin-wrapped like umsgpack would).
pub fn msgpack_bin(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_bin(&mut out, data).expect("write bin");
    out
}

/// Pack a request payload `[time, path_hash, data]` like Python
/// `Link.request`.
pub fn pack_request(path: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + data.len());
    rmp::encode::write_array_len(&mut out, 3).unwrap();
    rmp::encode::write_f64(&mut out, super::unix_time()).unwrap();
    let path_hash = crate::hash::Hash::new_from_slice(path.as_bytes());
    rmp::encode::write_bin(&mut out, &path_hash.as_slice()[..16]).unwrap();
    rmp::encode::write_bin(&mut out, data).unwrap();
    out
}

/// Compute the request id: truncated hash of the packed request.
pub fn request_id(packed_request: &[u8]) -> AddressHash {
    AddressHash::new_from_hash(&crate::hash::Hash::new_from_slice(packed_request))
}

/// Unpack a packed request `[time, path_hash, data]`.
pub fn unpack_request(data: &[u8]) -> Option<(f64, AddressHash, Vec<u8>)> {
    // Python `Link.request`: `[time.time(), truncated_hash(path), data]`
    // where `data` is `None` (msgpack `nil`) when the request carries no
    // payload.
    let mut cursor: &[u8] = data;
    if rmp::decode::read_array_len(&mut cursor).ok()? != 3 {
        return None;
    }
    let time = rmpv::decode::read_value(&mut cursor).ok()?.as_f64()?;
    let path = rmpv::decode::read_value(&mut cursor).ok()?;
    let path_bytes = match &path {
        rmpv::Value::Binary(bytes) => bytes.as_slice(),
        _ => return None,
    };
    if path_bytes.len() != 16 {
        return None;
    }
    let path_hash = AddressHash::new(path_bytes.try_into().ok()?);
    let payload = match rmpv::decode::read_value(&mut cursor).ok()? {
        rmpv::Value::Nil => Vec::new(),
        rmpv::Value::Binary(bytes) => bytes.to_vec(),
        _ => return None,
    };
    Some((time, path_hash, payload))
}

/// Pack a response `[request_id, response]`.
pub fn pack_response(request_id: &AddressHash, response: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + response.len());
    rmp::encode::write_array_len(&mut out, 2).unwrap();
    rmp::encode::write_bin(&mut out, request_id.as_slice()).unwrap();
    // Python packs the handler's return value with umsgpack, so handler
    // output is already a valid msgpack element and is spliced in
    // verbatim (dicts become nested maps, opaque blobs stay bins).
    out.extend_from_slice(response);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{DestinationName, SingleInputDestination};
    use crate::identity::PrivateIdentity;
    use rand_core::OsRng;

    fn link() -> Link {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        Link::new(
            SingleInputDestination::new(
                identity,
                DestinationName::new("test", "resource.request"),
            )
            .desc,
        )
    }

    #[test]
    fn malformed_part_requests_are_ignored_without_state_changes() {
        let link = link();
        let mut manager = ResourceManager::new();
        let before = (manager.out.len(), manager.incoming.len());

        let malformed = [
            Vec::new(),
            vec![0],
            vec![super::super::HASHMAP_IS_EXHAUSTED],
            vec![super::super::HASHMAP_IS_EXHAUSTED; 1 + super::super::MAPHASH_LEN],
            vec![0; 32],
            vec![super::super::HASHMAP_IS_EXHAUSTED; 1 + super::super::MAPHASH_LEN + 31],
        ];
        for request in malformed {
            assert!(manager.handle_request_data(&link, &request).packets.is_empty());
            assert_eq!((manager.out.len(), manager.incoming.len()), before);
        }

        let valid_normal = vec![0; 33];
        let valid_exhausted =
            vec![super::super::HASHMAP_IS_EXHAUSTED; 1 + super::super::MAPHASH_LEN + 32];
        assert!(manager
            .handle_request_data(&link, &valid_normal)
            .packets
            .is_empty());
        assert!(manager
            .handle_request_data(&link, &valid_exhausted)
            .packets
            .is_empty());
    }
}

#[cfg(test)]
mod split_validation_tests {
    use super::*;

    #[test]
    fn response_unpack_unwraps_bins_keeps_other_elements_raw() {
        // A Python bytes response stays unwrapped contents.
        let mut packed = Vec::new();
        rmp::encode::write_array_len(&mut packed, 2).unwrap();
        rmp::encode::write_bin(&mut packed, &[0x22u8; 16]).unwrap();
        rmp::encode::write_bin(&mut packed, b"response-data").unwrap();
        let (rid, response) = unpack_response(&packed).unwrap();
        assert_eq!(rid.as_slice(), &[0x22u8; 16][..]);
        assert_eq!(response, b"response-data");

        // A dict response returns its raw encoding for callers to parse.
        let mut packed = Vec::new();
        rmp::encode::write_array_len(&mut packed, 2).unwrap();
        rmp::encode::write_bin(&mut packed, &[0x22u8; 16]).unwrap();
        rmp::encode::write_map_len(&mut packed, 1).unwrap();
        rmp::encode::write_bin(&mut packed, &[1u8; 16]).unwrap();
        rmp::encode::write_str(&mut packed, "x").unwrap();
        let (rid, response) = unpack_response(&packed).unwrap();
        assert_eq!(rid.as_slice(), &[0x22u8; 16][..]);
        assert!(response.starts_with(&[0x81]));
    }

    #[test]
    fn request_unpack_accepts_nil_data() {
        // Python link.request(path) with no payload packs [time, hash, None].
        let mut packed = Vec::new();
        rmp::encode::write_array_len(&mut packed, 3).unwrap();
        rmp::encode::write_f64(&mut packed, 12345.678).unwrap();
        rmp::encode::write_bin(&mut packed, &[0x11u8; 16]).unwrap();
        rmp::encode::write_nil(&mut packed).unwrap();
        let (time, path, data) = unpack_request(&packed).expect("nil data request");
        assert!((time - 12345.678).abs() < 0.001);
        assert_eq!(path.as_slice(), &[0x11u8; 16][..]);
        assert!(data.is_empty());
    }
}
