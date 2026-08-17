use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
}

/// Maximum number of cached announce packets
/// (Python caches announces to storage; this in-memory bound keeps the
/// cache usable for path responses and cache requests).
const MAX_CACHED_ANNOUNCES: usize = 8192;

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    remove_cache: Vec<Hash>,
    /// Force-cached announce packets by packet hash
    /// (Python `Transport.cache(force_cache=True, packet_type="announce")`).
    announces: HashMap<Hash, Packet>,
    announce_order: VecDeque<Hash>,
}

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            remove_cache: Vec::new(),
            announces: HashMap::new(),
            announce_order: VecDeque::new(),
        }
    }

    pub fn release(&mut self, duration: Duration) {
        for entry in &self.map {
            if entry.1.time.elapsed() > duration {
                self.remove_cache.push(*entry.0);
            }
        }

        for hash in &self.remove_cache {
            self.map.remove(hash);
        }

        self.remove_cache.clear();
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();

        let mut is_new_packet = false;

        let track = self.map.get_mut(&hash);
        if let Some(track) = track {
            track.time = Instant::now();
            track.min_hops = min(packet.header.hops, track.min_hops);
        } else {
            is_new_packet = true;

            self.map.insert(
                hash,
                PacketTrack {
                    time: Instant::now(),
                    min_hops: packet.header.hops,
                },
            );
        }

        is_new_packet
    }

    /// Cache an announce packet for later path responses and cache requests
    /// (Python `Transport.cache(force_cache=True, packet_type="announce")`).
    pub fn cache_announce(&mut self, packet: &Packet) {
        let hash = packet.hash();

        if !self.announces.contains_key(&hash) {
            self.announce_order.push_back(hash);
            if self.announce_order.len() > MAX_CACHED_ANNOUNCES {
                if let Some(evicted) = self.announce_order.pop_front() {
                    self.announces.remove(&evicted);
                }
            }
        }

        self.announces.insert(hash, *packet);
    }

    /// Retrieve a cached announce by packet hash
    /// (Python `Transport.get_cached_packet(hash, packet_type="announce")`).
    pub fn get_cached_announce(&self, hash: &Hash) -> Option<Packet> {
        self.announces.get(hash).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::AddressHash;
    use crate::packet::{
        DestinationType, Header, HeaderType, IfacFlag, PacketContext, PacketDataBuffer, PacketType,
        PropagationType,
    };

    fn announce_packet(hops: u8) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops,
            },
            ifac: None,
            destination: AddressHash::new([1; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[2; 32]),
        }
    }

    #[test]
    fn announce_cache_roundtrip() {
        let mut cache = PacketCache::new();
        let packet = announce_packet(2);
        let hash = packet.hash();

        assert!(cache.get_cached_announce(&hash).is_none());
        cache.cache_announce(&packet);
        assert_eq!(cache.get_cached_announce(&hash), Some(packet));
        assert!(cache.get_cached_announce(&hash).is_some());
    }
}
