//! Per-transport resource state: tracks outgoing/incoming resources per
//! link, routes resource packets and runs watchdog checks.

use std::collections::HashMap;
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

        // Request or response resources are always accepted if a matching
        // pending request exists or handlers are registered.
        if adv.is_request() {
            let size_ok = self
                .max_request_size
                .map(|max| adv.data_size <= max)
                .unwrap_or(true);
            if !size_ok {
                log::debug!("resource: rejecting oversized request");
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

    /// Handle RESOURCE_REQ plaintext for a link.
    pub fn handle_request_data(
        &mut self,
        link: &Link,
        plaintext: &[u8],
    ) -> ResourceTx {
        let mut tx = ResourceTx::default();
        let resource_hash_prefix = if plaintext.first() == Some(&super::HASHMAP_IS_EXHAUSTED) {
            &plaintext[1 + super::MAPHASH_LEN..]
        } else {
            &plaintext[1..]
        };
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
                    let hash = resource.hash;
                    resource.status = ResourceStatus::Complete;
                    resource.prove(link, &resource.assembled.clone().unwrap(), tx);
                    resource.last_activity = super::unix_time();

                    let progress = resource.progress();
                    let metadata = resource.metadata.clone();
                    let advertisement = resource.advertisement_of();

                    let is_request = resource.request_id.is_some() && !resource.is_response;
                    let is_response = resource.is_response;
                    let request_id = resource.request_id;
                    let is_final = resource.segment_index == resource.total_segments;

                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash,
                        status: ResourceStatus::Complete,
                        progress,
                        data: if is_final { Some(data.clone()) } else { None },
                        metadata,
                        advertisement: Some(advertisement),
                    });

                    let response_rid = if is_response && is_final { request_id } else { None };
                    if let Some(request_id) = response_rid {
                        let event = match unpack_response(&data) {
                            Some((rid, response)) => RequestEvent::Response {
                                request_id: rid,
                                data: response,
                                metadata: None,
                            },
                            None => RequestEvent::Failed { request_id },
                        };
                        self.request_events
                            .send(RequestEventData { link_id: *link.id(), event })
                            .ok();
                        self.pending_requests.remove(&request_id);
                    }

                    if is_request && is_final {
                        return Some((hash, data));
                    }
                    return Some((hash, data));
                }
                Err(err) => {
                    log::debug!("resource: assembly failed: {err:?}");
                    resource.status = ResourceStatus::Corrupt;
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

    /// Handle RESOURCE_PRF payload for outgoing resources.
    pub fn handle_proof(&mut self, link: &Link, proof_data: &[u8]) {
        if proof_data.len() != 64 {
            return;
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&proof_data[..32]);
        let resource_hash = crate::hash::Hash::new(hash_bytes);

        if let Some(resources) = self.out.get_mut(link.id()) {
            for resource in resources.iter_mut() {
                if resource.hash == resource_hash && resource.validate_proof(proof_data) {
                    let _ = self.events.send(ResourceEvent {
                        link_id: *link.id(),
                        hash: resource.hash,
                        status: ResourceStatus::Complete,
                        progress: 1.0,
                        data: None,
                        metadata: None,
                        advertisement: Some(resource.advertisement()),
                    });
                }
            }
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
        let mut failed_events = Vec::new();

        let link_ids: Vec<LinkId> = self.out.keys().copied().collect();
        for link_id in link_ids {
            let Some(link) = links.get(&link_id).cloned() else {
                continue;
            };
            let Ok(link) = link.try_lock() else { continue };
            if let Some(resources) = self.out.get_mut(&link_id) {
                let any_active = resources.iter().any(|r| !r.status.is_concluded()
                    && r.status != ResourceStatus::Queued);
                let mut i = 0;
                while i < resources.len() {
                    let (hash, failed) = {
                        let resource = &mut resources[i];
                        if resource.status.is_concluded() {
                            i += 1;
                            continue;
                        }
                        if resource.status == ResourceStatus::Queued {
                            // Python queues new resources until the current
                            // transfer on the link concluded.
                            if !any_active {
                                let _ = resource.advertise(&link, &mut tx);
                            }
                            i += 1;
                            continue;
                        }
                        let failed = resource.check(&link, &mut tx);
                        (resource.hash, failed)
                    };
                    if failed {
                        failed_events.push((link_id, hash, ResourceStatus::Failed));
                    }
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
                    let (hash, failed) = {
                        let resource = &mut resources[i];
                        if resource.status.is_concluded() {
                            i += 1;
                            continue;
                        }
                        let failed = resource.check(&link, &mut tx);
                        (resource.hash, failed)
                    };
                    if failed {
                        failed_events.push((link_id, hash, ResourceStatus::Failed));
                    }
                    i += 1;
                }
            }
        }

        for (link_id, hash, status) in failed_events {
            let _ = self.events.send(ResourceEvent {
                link_id,
                hash,
                status,
                progress: 0.0,
                data: None,
                metadata: None,
                advertisement: None,
            });
        }

        tx
    }

    /// Drop concluded resources to free memory.
    pub fn cleanup(&mut self) {
        self.out.retain(|_, list| {
            list.retain(|r| !r.status.is_concluded());
            !list.is_empty()
        });
        self.incoming.retain(|_, list| {
            list.retain(|r| !r.status.is_concluded());
            !list.is_empty()
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
    cursor = &cursor[len..];
    let data = rmp::decode::read_bin_len(&mut cursor).ok()? as usize;
    if cursor.len() < data {
        return None;
    }
    Some((request_id, cursor[..data].to_vec()))
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
    let mut cursor: &[u8] = data;
    if rmp::decode::read_array_len(&mut cursor).ok()? != 3 {
        return None;
    }
    let time = rmp::decode::read_f64(&mut cursor).ok()?;
    let len = rmp::decode::read_bin_len(&mut cursor).ok()? as usize;
    if cursor.len() < len || len != 16 {
        return None;
    }
    let path_hash = AddressHash::new(cursor[..len].try_into().ok()?);
    cursor = &cursor[len..];
    let dlen = rmp::decode::read_bin_len(&mut cursor).ok()? as usize;
    if cursor.len() < dlen {
        return None;
    }
    Some((time, path_hash, cursor[..dlen].to_vec()))
}

/// Pack a response `[request_id, response]`.
pub fn pack_response(request_id: &AddressHash, response: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + response.len());
    rmp::encode::write_array_len(&mut out, 2).unwrap();
    rmp::encode::write_bin(&mut out, request_id.as_slice()).unwrap();
    rmp::encode::write_bin(&mut out, response).unwrap();
    out
}