use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rand_core::{OsRng, RngCore};
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::iface::{TxMessage, TxMessageType};
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
    PropagationType,
};

/// Announce rebroadcast retries (Python `Transport.PATHFINDER_R`).
const PATHFINDER_R: u8 = 1;
/// Retry grace period (Python `Transport.PATHFINDER_G` = 5 s).
const PATHFINDER_GRACE: Duration = Duration::from_secs(5);
/// Random window for announce rebroadcast (Python `PATHFINDER_RW`).
const PATHFINDER_RANDOM_WINDOW: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct AnnounceEntry {
    pub packet: Packet,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub hops: u8,
    pub response_to_iface: Option<AddressHash>,
}

impl AnnounceEntry {
    pub fn retransmit(&mut self, transport_id: &AddressHash) -> Option<TxMessage> {
        if self.response_to_iface.is_some() {
            // Path responses wait out their grace period before they are
            // sent once (directly reachable peers answer first).
            if self.retries == 0 || Instant::now() < self.timeout {
                return None;
            }
            self.retries = 0;
            return Some(self.always_retransmit(transport_id));
        }

        // Ordinary announce rebroadcasts follow Python's announce table:
        // the entry waits out a random window (`PATHFINDER_RW`), sends,
        // then retries once more after `PATHFINDER_G + PATHFINDER_RW`,
        // completing once retries exceed `PATHFINDER_R`.
        if Instant::now() < self.timeout {
            return None;
        }
        self.retries += 1;
        if self.retries > PATHFINDER_R {
            return None;
        }
        self.timeout = Instant::now() + PATHFINDER_GRACE + PATHFINDER_RANDOM_WINDOW;
        Some(self.always_retransmit(transport_id))
    }

    pub fn always_retransmit(&self, transport_id: &AddressHash) -> TxMessage {
        let context = if self.response_to_iface.is_some() {
            PacketContext::PathResponse
        } else {
            PacketContext::None
        };

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                // Retransmitted announces keep the original ratchet context
                // flag (Python `context_flag = packet.context_flag`).
                context_flag: self.packet.header.context_flag,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination,
            transport: Some(*transport_id),
            context,
            data: self.packet.data,
        };

        let tx_type = match self.response_to_iface {
            Some(iface) => TxMessageType::Direct(iface),
            None => TxMessageType::Broadcast(Some(self.received_from)),
        };

        TxMessage { tx_type, packet }
    }
}

struct AnnounceCache {
    newer: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    older: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    capacity: usize,
}

impl AnnounceCache {
    fn new(capacity: usize) -> Self {
        Self {
            newer: Some(BTreeMap::new()),
            older: None,
            capacity,
        }
    }

    fn insert(&mut self, destination: AddressHash, entry: AnnounceEntry) {
        if self.newer.as_ref().unwrap().len() >= self.capacity {
            self.older = Some(self.newer.take().unwrap());
            self.newer = Some(BTreeMap::new());
        }

        self.newer.as_mut().unwrap().insert(destination, entry);
    }

    fn get(&self, destination: &AddressHash) -> Option<AnnounceEntry> {
        if let Some(entry) = self.newer.as_ref().unwrap().get(destination) {
            return Some(AnnounceEntry::clone(entry));
        }

        if let Some(ref older) = self.older {
            return older.get(destination).cloned();
        }

        None
    }
}

pub struct AnnounceTable {
    map: BTreeMap<AddressHash, AnnounceEntry>,
    responses: BTreeMap<AddressHash, AnnounceEntry>,
    cache: AnnounceCache,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            responses: BTreeMap::new(),
            cache: AnnounceCache::new(100000), // TODO make capacity configurable
        }
    }

    pub fn add(&mut self, announce: &Packet, destination: AddressHash, received_from: AddressHash) {
        let now = Instant::now();
        // Hops are attacker-controlled (not covered by the announce
        // signature): saturate instead of wrapping — a replayed
        // hops=255 announce must not wrap to 0 and poison routes.
        let hops = announce.header.hops.saturating_add(1);

        // Retransmit within a small random window
        // (Python: `retransmit_timeout = now + rand()*PATHFINDER_RW`,
        // `retries = PATHFINDER_R`).
        let rand_window =
            Duration::from_secs_f64((OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * 0.5);

        let entry = AnnounceEntry {
            packet: *announce,
            timeout: now + rand_window,
            received_from,
            retries: 0,
            hops,
            response_to_iface: None,
        };

        self.map.insert(destination, entry);
    }

    fn do_add_response(
        &mut self,
        mut response: AnnounceEntry,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8,
        grace: Duration,
    ) {
        response.retries = 1;
        response.hops = hops;
        // Python `Transport.path_request`: responses are retransmitted
        // after a short grace period (plus extra grace on roaming-mode
        // interfaces) so directly reachable peers can answer first.
        response.timeout = Instant::now() + grace;
        response.response_to_iface = Some(to_iface);

        self.responses.insert(destination, response);
    }

    pub fn add_response(
        &mut self,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8,
        grace: Duration,
    ) -> bool {
        if let Some(entry) = self.map.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops, grace);
            return true;
        }

        if let Some(entry) = self.cache.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops, grace);
            return true;
        }

        false
    }

    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<TxMessage> {
        // Immediate first rebroadcast: the entry would otherwise wait out
        // its random window plus one retransmit tick, which starves under
        // heavy CPU load. Sending now consumes the first retry like
        // Python's post-retransmit state (retries = 1, next try after
        // PATHFINDER_G + PATHFINDER_RW).
        let entry = self.map.get_mut(dest_hash)?;
        if entry.response_to_iface.is_some() || entry.retries > 0 {
            return None;
        }
        entry.retries = 1;
        entry.timeout = Instant::now() + PATHFINDER_GRACE + PATHFINDER_RANDOM_WINDOW;
        Some(entry.always_retransmit(transport_id))
    }

    pub fn tx_to_retransmit(&mut self, transport_id: &AddressHash) -> Vec<TxMessage> {
        let mut messages = vec![];
        let mut completed = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if self.responses.contains_key(destination) {
                continue;
            }

            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
            } else {
                completed.push(*destination);
            }
        }

        let n_announces = messages.len();

        // Responses within their grace period stay queued until a later
        // tick actually retransmits them (Python keeps the announce-table
        // entry until `IDX_AT_RTRNS_TMO` passes and it is sent).
        let mut sent = vec![];
        for (destination, entry) in self.responses.iter_mut() {
            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
                sent.push(*destination);
            }
        }

        let n_responses = messages.len() - n_announces;

        for destination in sent {
            self.responses.remove(&destination); // each response is retransmitted once
        }

        if !(messages.is_empty() && completed.is_empty()) {
            log::trace!(
                "Announce cache: {} retransmitted, {} path responses, {} dropped",
                n_announces,
                n_responses,
                completed.len(),
            );
        }

        for destination in completed {
            if let Some(announce) = self.map.remove(&destination) {
                self.cache.insert(destination, announce);
            }
        }

        messages
    }

    pub fn tx_to_retransmit_old(&mut self, transport_id: &AddressHash) -> Vec<TxMessage> {
        let mut messages = vec![];

        if let Some(ref cache) = self.cache.newer {
            for (destination, entry) in cache {
                if self.responses.contains_key(destination) {
                    continue;
                }

                messages.push(entry.always_retransmit(transport_id));
            }
        }

        if let Some(ref cache) = self.cache.older {
            for (destination, entry) in cache {
                if self.responses.contains_key(destination) {
                    continue;
                }

                messages.push(entry.always_retransmit(transport_id));
            }
        }

        messages
    }
}
