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
        self.map
            .retain(|_, entry| now.saturating_sub(entry.timestamp) < PATHFINDER_E);
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
        self.map
            .get(destination)
            .map(|e| e.unresponsive)
            .unwrap_or(false)
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
        self.map
            .get(destination)
            .filter(|entry| !entry.unresponsive)
    }

    /// Whether an entry exists, including retained unresponsive entries used
    /// for diagnostics and equal-hop recovery.
    pub fn contains(&self, destination: &AddressHash) -> bool {
        self.map.contains_key(destination)
    }

    /// Insert a path restored from a tunnel table entry
    /// (Python `handle_tunnel` restore: writes the tunnel path entry
    /// directly into the path table).
    pub fn insert_restored(
        &mut self,
        destination: AddressHash,
        received_from: AddressHash,
        hops: u8,
        iface: AddressHash,
        packet_hash: crate::hash::Hash,
    ) {
        self.map.insert(
            destination,
            PathEntry {
                received_from,
                hops,
                iface,
                timestamp: (self.now)(),
                unresponsive: false,
                packet_hash,
            },
        );
    }

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map
            .get(destination)
            .filter(|entry| !entry.unresponsive)
            .map(|entry| (entry.received_from, entry.iface))
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
            if !existing_entry.unresponsive && !self.reroute_eager && hops == existing_entry.hops {
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

        let entry = match self.map.get(&lookup).filter(|entry| !entry.unresponsive) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        // Python `Transport.inbound` path-forwarding: with more than one
        // hop to go the packet stays addressed (HEADER_2) to the next
        // transport node; when the destination itself is the next hop
        // (single hop left) the transport headers are stripped so the
        // endpoint receives a plain HEADER_1 packet.
        let last_hop = entry.hops <= 1;

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: if last_hop {
                        HeaderType::Type1
                    } else {
                        HeaderType::Type2
                    },
                    hops: original_packet.header.hops + 1,
                    ..original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport: if last_hop {
                    None
                } else {
                    Some(entry.received_from)
                },
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
    /// Update the hop count of a known path (link-request proof
    /// rebalancing, Python `IDX_PT_HOPS` update).
    pub fn rebalance_hops(&mut self, destination: &AddressHash, hops: u8) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) if hops < entry.hops => {
                entry.hops = hops;
                true
            }
            _ => false,
        }
    }

    /// Route a locally-originated packet toward its destination.
    /// Python `Transport.outbound` writes the packet's own hop count
    /// (0 for freshly created packets); relays add hops on receive.
    pub fn handle_local_packet(&self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        let lookup = original_packet.destination;

        let entry = match self.map.get(&lookup).filter(|entry| !entry.unresponsive) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type2,
                    hops: original_packet.header.hops,
                    ..original_packet.header
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

        let entry = match self
            .map
            .get(&original_packet.destination)
            .filter(|entry| !entry.unresponsive)
        {
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
                    ..original_packet.header
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketContext, PacketDataBuffer};

    fn address(byte: u8) -> AddressHash {
        AddressHash::new_from_slice(&[byte; 32])
    }

    fn announce(destination: AddressHash, hops: u8, marker: u8) -> Packet {
        Packet {
            header: Header {
                packet_type: PacketType::Announce,
                hops,
                ..Default::default()
            },
            destination,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[marker]),
            ..Default::default()
        }
    }

    #[test]
    fn unresponsive_paths_are_retained_but_never_routed() {
        let destination = address(1);
        let first_iface = address(2);
        let recovered_iface = address(3);
        let mut table = PathTable::new(false);
        table.handle_announce(&announce(destination, 0, 1), None, first_iface);
        assert!(table.get(&destination).is_some());

        assert!(table.mark_path_unresponsive(&destination));
        assert!(table.contains(&destination));
        assert!(table.get(&destination).is_none());
        assert!(table.next_hop_full(&destination).is_none());
        assert_eq!(table.iter().count(), 1, "diagnostics retain the entry");

        let packet = Packet {
            destination,
            ..Default::default()
        };
        assert!(table.handle_packet(&packet).1.is_none());
        assert!(table.handle_inbound_packet(&packet, None).1.is_none());

        // A fresh equal-hop announce revives the route even without eager
        // rerouting.
        table.handle_announce(&announce(destination, 0, 2), None, recovered_iface);
        assert!(!table.path_is_unresponsive(&destination));
        assert_eq!(table.get(&destination).unwrap().iface, recovered_iface);

        assert!(table.mark_path_unresponsive(&destination));
        assert!(table.mark_path_responsive(&destination));
        assert!(table.get(&destination).is_some());
    }
}
