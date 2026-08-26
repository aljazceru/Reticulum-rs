//! Remote management and probe destinations — Python `RNS.Transport`
//! management destinations (Phase 6.7).
//!
//! * `rnstransport.remote.management` (SINGLE, inbound, transport
//!   identity): request handlers `/status` (interface stats, optionally
//!   link counts) and `/path` (path table / rates) mirroring Python's
//!   `remote_status_handler` / `remote_path_handler`
//! * `rnstransport.probe` (SINGLE, inbound, no links, PROVE_ALL):
//!   answers any packet with a proof, so `rnprobe` can measure round-trip
//!   times
//! * `rnstransport.info.blackhole` (SINGLE, inbound): `/list` handler
//!   returning the blackholed identity hashes
//!   (Python `blackhole_list_handler`, enabled with
//!   `publish_blackhole`)

use alloc::vec::Vec;

use rmp::encode as mp;

use crate::destination::{DestinationName, SingleInputDestination};

/// Periodically refreshed state snapshot the management handlers serve
/// (the handlers cannot lock the transport while it processes requests).
#[derive(Debug, Default)]
pub struct ManagementSnapshot {
    pub stats: Vec<crate::iface::InterfaceStats>,
    pub paths: Vec<crate::transport::PathTableSnapshotEntry>,
    /// (link_table, inbound, outbound) link counts
    pub link_counts: (usize, usize, usize),
    /// Packed blackhole table in the Python wire format
    /// (msgpack dict `{hash: {source, until, reason}}`).
    pub blackholes: Vec<u8>,
}

/// Whether a request from `remote_identity` is allowed
/// (Python `ALLOW_LIST` on the management destination).
pub fn identity_allowed(
    remote_identity: Option<&crate::identity::Identity>,
    allowed: &[crate::hash::AddressHash],
) -> bool {
    match remote_identity {
        Some(identity) => allowed.contains(&identity.address_hash),
        None => false,
    }
}

/// Build the `/status` response
/// (Python `remote_status_handler`: `[interface_stats]` plus
/// `[link_count]` when requested).
pub fn status_response(snapshot: &ManagementSnapshot, include_links: bool) -> Vec<u8> {
    let stats = encode_interface_stats(&snapshot.stats);

    let mut out = Vec::new();
    if include_links {
        mp::write_array_len(&mut out, 2).ok();
        out.extend_from_slice(&stats);
        mp::write_u64(
            &mut out,
            snapshot.link_counts.1 as u64 + snapshot.link_counts.2 as u64,
        )
        .ok();
    } else {
        mp::write_array_len(&mut out, 1).ok();
        out.extend_from_slice(&stats);
    }
    out
}

/// Build the `/path` "table" response, optionally filtered by destination
/// hash and max hops (Python `remote_path_handler`).
pub fn path_table_response(
    snapshot: &ManagementSnapshot,
    destination: Option<&[u8]>,
    max_hops: Option<u64>,
) -> Vec<u8> {
    let filtered: Vec<_> = snapshot
        .paths
        .iter()
        .filter(|path| {
            destination
                .map(|dest| path.destination.as_slice() == dest)
                .unwrap_or(true)
        })
        .filter(|path| max_hops.map(|max| path.hops as u64 <= max).unwrap_or(true))
        .cloned()
        .collect();

    encode_path_table(&filtered)
}

/// Build the `/path` "rates" response (Python `get_rate_table`; no rate
/// table parity yet, so the response is an empty list).
pub fn rates_response(_snapshot: &ManagementSnapshot, _destination: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    mp::write_array_len(&mut out, 0).ok();
    out
}

/// Build the fixed management destination names.
pub fn remote_management_name() -> DestinationName {
    DestinationName::new("rnstransport", "remote.management")
}

pub fn probe_name() -> DestinationName {
    DestinationName::new("rnstransport", "probe")
}

pub fn blackhole_info_name() -> DestinationName {
    DestinationName::new("rnstransport", "info.blackhole")
}

/// Encode a msgpack list of interface stat maps for `/status` responses
/// (Python `Reticulum.get_interface_stats` list-of-dicts shape).
pub fn encode_interface_stats(stats: &[crate::iface::InterfaceStats]) -> Vec<u8> {
    let mut out = Vec::new();
    mp::write_array_len(&mut out, stats.len() as u32).ok();

    for stat in stats {
        mp::write_map_len(&mut out, 7).ok();
        mp::write_str(&mut out, "name").ok();
        mp::write_str(&mut out, &stat.name).ok();
        mp::write_str(&mut out, "type").ok();
        mp::write_str(&mut out, &stat.kind).ok();
        mp::write_str(&mut out, "status").ok();
        mp::write_str(&mut out, if stat.online { "online" } else { "offline" }).ok();
        mp::write_str(&mut out, "bitrate").ok();
        // Python reports the configured bitrate adaptation; the daemon
        // reports the nominal rate. Adapting here keeps the key present.
        mp::write_u64(
            &mut out,
            crate::iface::control::ANNOUNCE_CAP as u64 * 31_250,
        )
        .ok();
        mp::write_str(&mut out, "sent").ok();
        mp::write_u64(&mut out, stat.sent).ok();
        mp::write_str(&mut out, "received").ok();
        mp::write_u64(&mut out, stat.received).ok();
        mp::write_str(&mut out, "txb").ok();
        mp::write_u64(&mut out, stat.tx_bytes).ok();
    }

    out
}

/// Encode a msgpack `/path` "table" response from path table snapshot
/// entries (Python `Reticulum.get_path_table` dict shape).
pub fn encode_path_table(paths: &[crate::transport::PathTableSnapshotEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    mp::write_array_len(&mut out, paths.len() as u32).ok();

    for path in paths {
        mp::write_map_len(&mut out, 4).ok();
        mp::write_str(&mut out, "hash").ok();
        mp::write_bin(&mut out, path.destination.as_slice()).ok();
        mp::write_str(&mut out, "hops").ok();
        mp::write_u8(&mut out, path.hops).ok();
        mp::write_str(&mut out, "via").ok();
        mp::write_bin(&mut out, path.via.as_slice()).ok();
        mp::write_str(&mut out, "interface").ok();
        mp::write_bin(&mut out, path.iface.as_slice()).ok();
    }

    out
}

/// Decode a `/status` or `/path` request payload
/// (Python sends msgpack lists like `[True]` or
/// `["table", <hash>, <max_hops>]`).
pub enum ManagementRequest {
    Status {
        include_links: bool,
    },
    PathTable {
        destination: Option<Vec<u8>>,
        max_hops: Option<u64>,
    },
    Rates {
        destination: Option<Vec<u8>>,
    },
    Unknown,
}

pub fn decode_management_request(data: &[u8]) -> ManagementRequest {
    use rmpv::{Value, decode::read_value};

    let mut cursor = std::io::Cursor::new(data);
    let value = match read_value(&mut cursor) {
        Ok(value) => value,
        Err(_) => return ManagementRequest::Unknown,
    };

    let Value::Array(items) = value else {
        return ManagementRequest::Unknown;
    };

    match items.first() {
        Some(Value::String(command)) => match command.as_str() {
            Some("table") => ManagementRequest::PathTable {
                destination: items.get(1).and_then(value_bytes),
                max_hops: items.get(2).and_then(value_u64),
            },
            Some("rates") => ManagementRequest::Rates {
                destination: items.get(1).and_then(value_bytes),
            },
            _ => ManagementRequest::Unknown,
        },
        Some(Value::Boolean(include_links)) => ManagementRequest::Status {
            include_links: *include_links,
        },
        _ => ManagementRequest::Status {
            include_links: false,
        },
    }
}

fn value_bytes(value: &rmpv::Value) -> Option<Vec<u8>> {
    match value {
        rmpv::Value::Binary(bytes) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn value_u64(value: &rmpv::Value) -> Option<u64> {
    value.as_u64()
}

/// Encode a blackhole-list response
/// (Python `blackhole_list_handler`: the packed `blackholed_identities`
/// dict, msgpack `{hash: {"source", "until", "reason"}}`).
pub fn encode_blackhole_list(packed_table: &[u8]) -> Vec<u8> {
    packed_table.to_vec()
}

/// Build the remote-management inbound destination
/// (Python `Transport.remote_management_destination`).
#[allow(dead_code)]
pub fn remote_management_destination(
    identity: &crate::identity::PrivateIdentity,
) -> SingleInputDestination {
    SingleInputDestination::new(identity.clone(), remote_management_name())
}

/// Build the probe inbound destination
/// (Python `Transport.probe_destination`: no links, PROVE_ALL).
pub fn probe_destination(identity: &crate::identity::PrivateIdentity) -> SingleInputDestination {
    let mut destination = SingleInputDestination::new(identity.clone(), probe_name());
    destination.set_accepts_links(false);
    destination.set_proof_strategy(crate::destination::ProofStrategy::All);
    destination
}

/// Build the blackhole-info inbound destination
/// (Python `Transport.blackhole_destination`).
#[allow(dead_code)]
pub fn blackhole_info_destination(
    identity: &crate::identity::PrivateIdentity,
) -> SingleInputDestination {
    SingleInputDestination::new(identity.clone(), blackhole_info_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_request_decoding() {
        // Python sends [True]
        let mut data = Vec::new();
        mp::write_array_len(&mut data, 1).ok();
        mp::write_bool(&mut data, true).ok();

        match decode_management_request(&data) {
            ManagementRequest::Status { include_links } => assert!(include_links),
            _ => panic!("expected status request"),
        }
    }

    #[test]
    fn path_request_decoding() {
        // Python sends ["table", <hash bytes>, <max_hops>]
        let mut data = Vec::new();
        mp::write_array_len(&mut data, 3).ok();
        mp::write_str(&mut data, "table").ok();
        mp::write_bin(&mut data, &[1u8; 16]).ok();
        mp::write_u64(&mut data, 16).ok();

        match decode_management_request(&data) {
            ManagementRequest::PathTable {
                destination,
                max_hops,
            } => {
                assert_eq!(destination.as_deref(), Some(&[1u8; 16][..]));
                assert_eq!(max_hops, Some(16));
            }
            _ => panic!("expected path table request"),
        }
    }

    #[test]
    fn blackhole_list_encoding_passthrough() {
        // The handler serves the packed Python-format table verbatim.
        let mut table = Vec::new();
        mp::write_map_len(&mut table, 1).ok();
        mp::write_bin(&mut table, &[7u8; 16]).ok();
        mp::write_map_len(&mut table, 3).ok();
        mp::write_str(&mut table, "source").ok();
        mp::write_bin(&mut table, &[1u8; 16]).ok();
        mp::write_str(&mut table, "until").ok();
        mp::write_nil(&mut table).ok();
        mp::write_str(&mut table, "reason").ok();
        mp::write_nil(&mut table).ok();

        let encoded = encode_blackhole_list(&table);
        assert_eq!(encoded, table);

        // Decode with rmpv: the wire shape is the Python dict.
        let mut cursor = std::io::Cursor::new(&encoded);
        let value = rmpv::decode::read_value(&mut cursor).ok().unwrap();
        let rmpv::Value::Map(pairs) = value else {
            panic!("expected msgpack map");
        };
        assert_eq!(pairs.len(), 1);
        let (key, entry) = &pairs[0];
        assert_eq!(
            key,
            &rmpv::Value::Binary(vec![7u8; 16].into_iter().collect())
        );
        let rmpv::Value::Map(entry_pairs) = entry else {
            panic!("expected entry map");
        };
        let keys: Vec<_> = entry_pairs
            .iter()
            .map(|(k, _)| k.as_str().unwrap_or_default().to_string())
            .collect();
        assert!(keys.contains(&"source".to_string()));
        assert!(keys.contains(&"until".to_string()));
        assert!(keys.contains(&"reason".to_string()));
    }
}
