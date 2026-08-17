use alloc::collections::{BTreeMap, BTreeSet};

use rand_core::OsRng;

use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::AddressHash;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::identity::EmptyIdentity;
use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::PropagationType;

/// Default timeout for client path requests in seconds
/// (Python `Transport.PATH_REQUEST_TIMEOUT`).
pub const PATH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn create_path_request_destination() -> PlainInputDestination {
    PlainInputDestination::new(
        EmptyIdentity {},
        DestinationName::new("rnstransport", "path.request"),
    )
}

pub type TagBytes = Vec<u8>;

pub fn create_random_tag() -> TagBytes {
    AddressHash::new_from_rand(OsRng).as_slice().into()
}

pub struct PathRequest {
    pub destination: AddressHash,
    pub requesting_transport: Option<AddressHash>,
    pub tag_bytes: TagBytes,
}

impl PathRequest {
    fn decode(data: &[u8], transport_name: &str) -> Option<Self> {
        if data.len() <= ADDRESS_HASH_SIZE {
            log::info!(
                "tp({}): ignoring malformed path request: no {}",
                transport_name,
                if data.len() < ADDRESS_HASH_SIZE {
                    "destination"
                } else {
                    "tag"
                }
            );
            return None;
        }

        let mut destination = [0u8; ADDRESS_HASH_SIZE];
        destination.copy_from_slice(&data[..ADDRESS_HASH_SIZE]);
        let destination = AddressHash::new(destination);

        let mut requesting_transport = None;
        let mut tag_start = ADDRESS_HASH_SIZE;
        let mut tag_end = data.len();

        if data.len() > ADDRESS_HASH_SIZE * 2 {
            requesting_transport = Some(AddressHash::new_from_slice(
                &data[ADDRESS_HASH_SIZE..2 * ADDRESS_HASH_SIZE],
            ));
            tag_start = ADDRESS_HASH_SIZE * 2;
        }

        if tag_end - tag_start > ADDRESS_HASH_SIZE {
            tag_end = tag_start + ADDRESS_HASH_SIZE;
        }

        let tag_bytes = data[tag_start..tag_end].into();

        Some(Self {
            destination,
            requesting_transport,
            tag_bytes,
        })
    }
}

pub struct PathRequests {
    cache: BTreeSet<(AddressHash, TagBytes)>,
    name: String,
    transport_id: Option<AddressHash>,
    controlled_destination: PlainInputDestination,
    /// Outstanding (discovery) path requests sent on behalf of an unknown
    /// destination (Python `Transport.discovery_path_requests`).
    discovery: BTreeMap<AddressHash, Instant>,
    /// Path requests issued locally, with the time they were last sent
    /// (Python `Transport.path_requests` accounting, used to exempt
    /// announces for requested destinations from ingress limiting).
    pending: BTreeMap<AddressHash, Instant>,
    /// Minimum interval between automated path requests for the same
    /// destination (Python `Transport.PATH_REQUEST_MI`).
    min_request_interval: Duration,
}

impl PathRequests {
    pub fn new(name: &str, transport_id: Option<AddressHash>) -> Self {
        Self {
            cache: BTreeSet::new(),
            name: name.into(),
            transport_id,
            controlled_destination: create_path_request_destination(),
            discovery: BTreeMap::new(),
            pending: BTreeMap::new(),
            min_request_interval: Duration::from_secs(20),
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Option<PathRequest> {
        let path_request = PathRequest::decode(data, &self.name);

        if let Some(ref request) = path_request {
            let is_new = self
                .cache
                .insert((request.destination, request.tag_bytes.clone()));

            if !is_new {
                log::info!(
                    "tp({}): ignoring duplicate path request for destination {}",
                    self.name,
                    request.destination
                );
                return None;
            }
        }

        path_request
    }

    pub fn generate(&mut self, destination: &AddressHash, tag: Option<TagBytes>) -> Packet {
        self.pending.insert(*destination, Instant::now());

        let mut data = PacketDataBuffer::new_from_slice(destination.as_slice());

        if let Some(transport_id) = self.transport_id {
            data.safe_write(transport_id.as_slice());
        }

        data.safe_write(tag.unwrap_or_else(create_random_tag).as_slice());

        let destination = self.controlled_destination.desc.address_hash;

        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination,
            transport: self.transport_id,
            context: PacketContext::None,
            data,
        }
    }

    /// Whether a locally issued path request for `destination` is still
    /// outstanding (Python: `destination_hash in Transport.path_requests`).
    /// Entries expire after `PATH_REQUEST_TIMEOUT`.
    pub fn has_pending(&mut self, destination: &AddressHash) -> bool {
        let now = Instant::now();
        match self.pending.get(destination) {
            Some(at) if now - *at < PATH_REQUEST_TIMEOUT => true,
            Some(_) => {
                self.pending.remove(destination);
                false
            }
            None => false,
        }
    }

    /// Whether a recursive discovery request for `destination` is currently
    /// waiting (Python `Transport.discovery_path_requests`).
    pub fn discovery_pending(&self, destination: &AddressHash) -> bool {
        match self.discovery.get(destination) {
            Some(timeout) => Instant::now() < *timeout,
            None => false,
        }
    }

    /// Register a waiting discovery path request for `destination`
    /// (Python inserts `{"destination_hash", "timeout", "requesting_interface"}`).
    pub fn register_discovery(&mut self, destination: &AddressHash) {
        self.discovery
            .insert(*destination, Instant::now() + PATH_REQUEST_TIMEOUT);
    }

    /// A matching announce arrived for a waiting discovery request
    /// (Python removes the entry in `Transport.inbound`).
    pub fn clear_discovery(&mut self, destination: &AddressHash) -> bool {
        self.discovery.remove(destination).is_some()
    }

    /// Whether an automated path request for `destination` may be sent now,
    /// honouring `PATH_REQUEST_MI` (Python automated path request gating).
    pub fn request_allowed(&mut self, destination: &AddressHash) -> bool {
        match self.pending.get(destination) {
            Some(at) => Instant::now() - *at >= self.min_request_interval,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_request_roundtrip() {
        let mut testee = PathRequests::new("", None);

        let dest = AddressHash::new_from_rand(OsRng);

        let encoded = testee.generate(&dest, None);
        let decoded = testee.decode(encoded.data.as_slice()).unwrap();

        assert_eq!(decoded.destination, dest);
    }

    #[test]
    fn pending_requests_expire() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);

        assert!(!testee.has_pending(&dest));

        testee.generate(&dest, None);
        assert!(testee.has_pending(&dest));

        testee.pending.insert(
            dest,
            Instant::now() - PATH_REQUEST_TIMEOUT - Duration::from_secs(1),
        );
        assert!(!testee.has_pending(&dest));
    }

    #[test]
    fn discovery_registration() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);

        assert!(!testee.discovery_pending(&dest));
        testee.register_discovery(&dest);
        assert!(testee.discovery_pending(&dest));
        assert!(testee.clear_discovery(&dest));
        assert!(!testee.discovery_pending(&dest));

        // Requests are gated on waiting discovery entries in the transport
        // layer via `discovery_pending`.
        testee.register_discovery(&dest);
        assert!(testee.discovery_pending(&dest));
    }
}
