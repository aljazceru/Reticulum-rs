use std::collections::HashMap;

use crate::{
    hash::AddressHash,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType},
};

/// Path expiry time (Python `Transport.PATHFINDER_E` = 1 week).
pub const PATHFINDER_E: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 24 * 7);

pub struct PathEntry {
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    /// When this path was learned (unstable time base; only differences
    /// matter).
    pub timestamp: core::time::Duration,
    /// Paths marked unresponsive are skipped for new link attempts until a
    /// fresh announce arrives (Python `mark_path_unresponsive`).
    pub unresponsive: bool,
    /// Hash of the announce packet that created this path, for analytics.
    pub packet_hash: crate::hash::Hash,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    reroute_eager: bool,
    now: fn() -> core::time::Duration,
}

impl PathTable {
    pub fn new(reroute_eager: bool) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
            now: crate::time::now,
        }
    }

    /// Drop paths older than `PATHFINDER_E`
    /// (Python `Transport.expire_paths`).
    pub fn expire_paths(&mut self) -> usize {
        let now = (self.now)();
        let before = self.map.len();
        self.map.retain(|_, entry| now.saturating_sub(entry.timestamp) < PATHFINDER_E);
        before - self.map.len()
    }

    /// Mark a path unresponsive so link attempts prefer alternatives
    /// (Python `Transport.mark_path_unresponsive`).
    pub fn mark_path_unresponsive(&mut self, destination: &AddressHash) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                entry.unresponsive = true;
                true
            }
            None => false,
        }
    }

    /// Clear the unresponsive mark (Python `Transport.mark_path_responsive`).
    pub fn mark_path_responsive(&mut self, destination: &AddressHash) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                entry.unresponsive = false;
                true
            }
            None => false,
        }
    }

    pub fn path_is_unresponsive(&self, destination: &AddressHash) -> bool {
        self.map.get(destination).map(|e| e.unresponsive).unwrap_or(false)
    }

    /// Remove a single path (Python `Transport.drop_path`).
    pub fn drop_path(&mut self, destination: &AddressHash) -> bool {
        self.map.remove(destination).is_some()
    }

    /// Remove all paths learned via an interface (Python `drop_all_via`).
    pub fn drop_all_via(&mut self, iface: &AddressHash) -> usize {
        let before = self.map.len();
        self.map.retain(|_, entry| &entry.iface != iface);
        before - self.map.len()
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map.get(destination).map(|entry| (entry.received_from, entry.iface))
    }

    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) {
        let hops = announce.header.hops + 1;

        if let Some(existing_entry) = self.map.get(&announce.destination) {
            if hops > existing_entry.hops {
                return;
            }
            if !self.reroute_eager && hops == existing_entry.hops {
                return;
            }
        }

        let received_from = transport_id.unwrap_or(announce.destination);
        let new_entry = PathEntry {
            received_from,
            hops,
            iface,
            timestamp: (self.now)(),
            unresponsive: false,
            packet_hash: announce.hash(),
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );
    }

    pub fn handle_inbound_packet(
        &self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = lookup.unwrap_or(original_packet.destination);

        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type2,
                    hops: original_packet.header.hops + 1,
                    .. original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }

    /// Route an outbound packet (Python `Transport.outbound`).
    ///
    /// Only packets with more than one hop to the destination are inserted
    /// into transport (header type 2 with the next-hop transport id);
    /// directly reachable destinations are transmitted as-is. Python drops
    /// data packets carrying a transport id that is not its own, so
    /// wrapping single-hop packets would never be delivered.
    pub fn handle_packet(&mut self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (*original_packet, None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        if entry.hops <= 1 {
            // Directly reachable: transmit the packet unchanged.
            return (*original_packet, Some(entry.iface));
        }

        (
            Packet {
                header: Header {
                    header_type: HeaderType::Type2,
                    .. original_packet.header
                },
                ifac: original_packet.ifac,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }
}

// ---------------------------------------------------------------------------
// Read-only snapshots for tooling (`rnpath`/`rnstatus`, Phase 8 utilities).
// Appended for the Phase 7/8 utilities work; the routing logic above is
// untouched.
// ---------------------------------------------------------------------------

impl PathTable {
    /// Iterate over all known paths (destination, entry).
    #[allow(dead_code)] // len/is_empty used by rnstatus tooling builds
    pub fn iter(&self) -> impl Iterator<Item = (&AddressHash, &PathEntry)> {
        self.map.iter()
    }

    /// Any known destination hash (diagnostics/tests).
    pub fn any_destination(&self) -> Option<AddressHash> {
        self.map.keys().next().copied()
    }

    /// Number of known paths.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether any path is known.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
