use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

pub struct LinkEntry {
    pub proof_timeout: Instant,
    pub next_hop: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub remaining_hops: u8,
    pub validated: bool,
    /// Last forwarded activity; validated entries expire when idle
    /// (Python removes them after LINK_TIMEOUT).
    pub last_activity: Instant,
}

/// Idle lifetime of a validated intermediary link
/// (Python `LINK_TIMEOUT` = `STALE_TIME * 1.25` = 30 min).
const LINK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            hops: packet.header.hops + 1,
            .. packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop),
        context: packet.context,
        data: packet.data,
    };

    (propagated, entry.received_from)
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
    ) {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();

        let entry = LinkEntry {
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop,
            received_from,
            original_destination: destination,
            remaining_hops: 0,
            validated: false,
            last_activity: now,
        };

        self.0.insert(link_id, entry);
    }

    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(link_id).filter(|e| e.validated).map(|e| e.original_destination)
    }

    pub fn handle_keepalive(&mut self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get_mut(&packet.destination)?;
        entry.last_activity = Instant::now();
        Some(send_backwards(packet, entry))
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                Some(send_backwards(proof, entry))
            },
            None => None
        }
    }

    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                // Validated entries expire after LINK_TIMEOUT of inactivity
                // (Python `LINK_TIMEOUT`; without this, unbounded unique
                // links accumulate until process restart).
                if now.saturating_duration_since(entry.last_activity) > LINK_TIMEOUT {
                    stale.push(*link_id);
                }
            } else if entry.proof_timeout <= now {
                stale.push(*link_id);
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}

impl LinkTable {
    /// Number of entries in the link table (pending + active links).
    ///
    /// Python parity: `RNS.Transport.get_link_count()` returns
    /// `len(Transport.link_table)`.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the link table is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
