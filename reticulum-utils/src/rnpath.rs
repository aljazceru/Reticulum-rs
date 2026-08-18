//! `rnpath` — path lookup utility (subset of `RNS/Utilities/rnpath.py`):
//! request a path to a destination and report hops/next hop, or dump the
//! local path table.
//!
//! Python reference behaviour (default mode):
//! ```text
//! Path to <hash> requested
//! Path found, destination <hash> is 2 hops away via <via> on <iface>
//! ```
//! or `Path not found` after the timeout, exiting with code 1.

use std::time::Duration;

use reticulum::destination::DestinationDesc;
use reticulum::hash::AddressHash;
use reticulum::transport::Transport;

use crate::common::prettyhexrep;

/// Default timeout for path requests (Python `Transport.PATH_REQUEST_TIMEOUT`
/// is 15 s; rnpath uses it as the default `-w` value).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Result of a successful path lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResult {
    pub destination: AddressHash,
    pub hops: u8,
    pub via: AddressHash,
    pub iface: AddressHash,
}

impl PathResult {
    /// Render like Python `rnpath`:
    /// `Path found, destination <hash> is N hops away via <via> on <iface>`.
    pub fn render(&self) -> String {
        let plural = if self.hops == 1 { "" } else { "s" };
        format!(
            "Path found, destination {} is {} hop{} away via {} on Interface[{}]",
            prettyhexrep(self.destination.as_slice()),
            self.hops,
            plural,
            prettyhexrep(self.via.as_slice()),
            self.iface.to_hex_string()
        )
    }
}

/// Wait until a path to `destination` is known, requesting it first when it
/// is not. Returns `None` on timeout (Python prints "Path not found").
pub async fn wait_for_path(
    transport: &Transport,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<PathResult> {
    if transport.has_path(destination).await {
        return path_result(transport, destination).await;
    }

    transport.request_path(destination, None, None).await;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if transport.has_path(destination).await {
            return path_result(transport, destination).await;
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn path_result(transport: &Transport, destination: &AddressHash) -> Option<PathResult> {
    let hops = transport.hops_to(destination).await?;
    let (via, iface) = transport.next_hop(destination).await?;
    Some(PathResult { destination: *destination, hops, via, iface })
}

/// Snapshot the path table, optionally filtered by destination and a max
/// hop count, sorted by (interface, hops) like Python `rnpath -t`.
pub async fn path_table(
    transport: &Transport,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
) -> Vec<PathResult> {
    let mut entries: Vec<PathResult> = transport
        .path_table_snapshot()
        .await
        .into_iter()
        .filter(|entry| filter.map(|f| entry.destination == *f).unwrap_or(true))
        .filter(|entry| max_hops.map(|max| entry.hops <= max).unwrap_or(true))
        .map(|entry| PathResult {
            destination: entry.destination,
            hops: entry.hops,
            via: entry.via,
            iface: entry.iface,
        })
        .collect();
    entries.sort_by_key(|entry| (entry.iface.to_hex_string(), entry.hops));
    entries
}

/// Render a path table like Python `rnpath -t`:
/// `<hash> is N hops away via <via> on <iface>`.
pub fn render_table(entries: &[PathResult]) -> String {
    let mut out = String::new();
    for entry in entries {
        let plural = if entry.hops == 1 { "" } else { "s" };
        out.push_str(&format!(
            "{} is {} hop{} away via {} on Interface[{}]\n",
            prettyhexrep(entry.destination.as_slice()),
            entry.hops,
            plural,
            prettyhexrep(entry.via.as_slice()),
            entry.iface.to_hex_string()
        ));
    }
    out
}

/// Wait for an announce for `destination` and return the destination
/// description (needed to establish links, e.g. in `rncp`).
pub async fn wait_for_destination(
    transport: &Transport,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<DestinationDesc> {
    if let Some(dest) = transport.get_out_destination(destination).await {
        return Some(dest.lock().await.desc);
    }

    // Subscribe BEFORE issuing the path request: on a fast local or
    // shared-instance path, the response announce can be processed
    // before a receiver created after the request would exist.
    let mut announces = transport.recv_announces().await;

    transport.request_path(destination, None, None).await;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }

        // Re-check in case the announce was processed between the
        // request and the first poll (and thus never emitted to us).
        if let Some(dest) = transport.get_out_destination(destination).await {
            return Some(dest.lock().await.desc);
        }

        let Ok(Ok(event)) = tokio::time::timeout(remaining, announces.recv()).await else {
            return None;
        };
        let desc = event.destination.lock().await.desc;
        if &desc.address_hash == destination {
            return Some(desc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_result_render() {
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 1,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
        };
        assert!(result.render().contains("is 1 hop away"));
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 3,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
        };
        assert!(result.render().contains("is 3 hops away"));
    }
}
