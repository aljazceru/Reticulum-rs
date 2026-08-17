//! Identity blackholing: announces and paths from blackholed identities are
//! dropped network-wide (Python `Reticulum.blackhole_identity` and the
//! blackhole-list propagation via `Discovery.BlackholeUpdater`).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::hash::AddressHash;

/// A set of blackholed identity hashes with source tracking.
///
/// Python `Transport.blackholed_identities` maps `identity_hash -> [source,
/// until]`; entries expire after `BLACKHOLE_TIMEOUT` unless renewed by the
/// publishing source.
pub struct Blackholes {
    entries: HashMap<AddressHash, (AddressHash, core::time::Duration)>,
    /// Whether this node republishes the blackhole list in its announces.
    publish: bool,
    /// Injected clock (monotonic `Duration`) for tests.
    now: fn() -> core::time::Duration,
}

impl Default for Blackholes {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            publish: false,
            now: crate::time::now,
        }
    }
}

/// How long a blackhole entry stays valid without renewal
/// (Python `blackhole_update_interval` is 12h; entries live ~2 intervals).
pub const BLACKHOLE_TIMEOUT: core::time::Duration =
    core::time::Duration::from_secs(60 * 60 * 24);

impl Blackholes {
    pub fn new(publish: bool) -> Self {
        Self { entries: HashMap::new(), publish, now: crate::time::now }
    }

    /// Replace the clock used for expiry (tests).
    pub fn with_clock(mut self, now: fn() -> core::time::Duration) -> Self {
        self.now = now;
        self
    }

    /// Blackhole an identity (Python `Reticulum.blackhole_identity`).
    pub fn blackhole(&mut self, identity: AddressHash, source: AddressHash) {
        self.entries.insert(identity, (source, (self.now)()));
    }

    /// Remove an identity from the blacklist
    /// (Python `Reticulum.unblackhole`).
    pub fn unblackhole(&mut self, identity: &AddressHash) -> bool {
        self.entries.remove(identity).is_some()
    }

    /// Whether an identity is currently blackholed.
    pub fn is_blackholed(&self, identity: &AddressHash) -> bool {
        self.entries.contains_key(identity)
    }

    /// All currently blackholed identities.
    pub fn blackholed_identities(&self) -> Vec<AddressHash> {
        self.entries.keys().copied().collect()
    }

    /// Whether this node publishes its blacklist in announces.
    pub fn publish_enabled(&self) -> bool {
        self.publish
    }

    /// Drop entries older than the validity window
    /// (unless they originate from this node).
    pub fn clean(&mut self, own_identity: &AddressHash) -> usize {
        let now = (self.now)();
        let before = self.entries.len();
        self.entries.retain(|_, (source, since)| {
            source == own_identity || now.saturating_sub(*since) < BLACKHOLE_TIMEOUT
        });
        before - self.entries.len()
    }

    /// Pack the blackhole list for announce propagation
    /// (Python packs `[identity_hash, ...]` into the announce app data).
    pub fn pack_list(&self) -> Vec<u8> {
        let mut out = Vec::new();
        rmp::encode::write_array_len(&mut out, self.entries.len() as u32).unwrap();
        for hash in self.entries.keys() {
            rmp::encode::write_bin(&mut out, hash.as_slice()).unwrap();
        }
        out
    }

    /// Unpack a blackhole list received in an announce app data and merge it.
    pub fn merge_list(&mut self, packed: &[u8], source: AddressHash) -> usize {
        let mut cursor: &[u8] = packed;
        let Ok(count) = rmp::decode::read_array_len(&mut cursor) else {
            return 0;
        };
        let mut merged = 0;
        for _ in 0..count {
            let Ok(len) = rmp::decode::read_bin_len(&mut cursor) else { break };
            let len = len as usize;
            if len != 16 || cursor.len() < len {
                break;
            }
            let hash = AddressHash::new(cursor[..len].try_into().unwrap());
            cursor = &cursor[len..];
            if !self.entries.contains_key(&hash) {
                merged += 1;
            }
            self.blackhole(hash, source);
        }
        merged
    }
}

/// Shared blackhole store used by the transport.
pub type SharedBlackholes = Arc<RwLock<Blackholes>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> AddressHash {
        AddressHash::new([byte; 16])
    }

    #[test]
    fn blackhole_roundtrip() {
        let mut bh = Blackholes::new(false);
        let id = hash(1);
        assert!(!bh.is_blackholed(&id));
        bh.blackhole(id, hash(9));
        assert!(bh.is_blackholed(&id));
        assert!(bh.unblackhole(&id));
        assert!(!bh.is_blackholed(&id));
    }

    #[test]
    fn pack_merge_list() {
        let mut bh = Blackholes::new(true);
        bh.blackhole(hash(1), hash(9));
        bh.blackhole(hash(2), hash(9));
        let packed = bh.pack_list();

        let mut other = Blackholes::new(false);
        let merged = other.merge_list(&packed, hash(8));
        assert_eq!(merged, 2);
        assert!(other.is_blackholed(&hash(1)));
        assert!(other.is_blackholed(&hash(2)));
        // merging again adds nothing
        assert_eq!(other.merge_list(&packed, hash(8)), 0);
    }

    #[test]
    fn clean_expires_remote_entries() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static FAKE_NOW: AtomicU64 = AtomicU64::new(1000);
        fn fake_now() -> core::time::Duration {
            core::time::Duration::from_secs(FAKE_NOW.load(Ordering::SeqCst))
        }

        let mut bh = Blackholes::new(false).with_clock(fake_now);
        let own = hash(0xF0);
        let remote_source = hash(0xEE);
        bh.blackhole(hash(1), own);
        bh.blackhole(hash(2), remote_source);

        // Advance the clock beyond the validity window.
        FAKE_NOW.store(1000 + BLACKHOLE_TIMEOUT.as_secs() + 1, Ordering::SeqCst);

        let removed = bh.clean(&own);
        assert_eq!(removed, 1);
        assert!(bh.is_blackholed(&hash(1)));
        assert!(!bh.is_blackholed(&hash(2)));
    }

    #[test]
    fn malformed_list_is_ignored() {
        let mut bh = Blackholes::new(false);
        assert_eq!(bh.merge_list(&[0xff, 0xff], hash(9)), 0);
        assert_eq!(bh.merge_list(&[], hash(9)), 0);
    }
}
