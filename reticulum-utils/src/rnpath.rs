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
    /// Interface label from a shared-instance path table. Local snapshots
    /// leave this empty and render `Interface[<hash>]`.
    pub iface_name: Option<String>,
}

impl PathResult {
    /// Render like Python `rnpath`:
    /// `Path found, destination <hash> is N hops away via <via> on <iface>`.
    pub fn render(&self) -> String {
        let plural = if self.hops == 1 { "" } else { "s" };
        format!(
            "Path found, destination {} is {} hop{} away via {} on {}",
            prettyhexrep(self.destination.as_slice()),
            self.hops,
            plural,
            prettyhexrep(self.via.as_slice()),
            self.on_interface()
        )
    }

    pub fn on_interface(&self) -> String {
        match &self.iface_name {
            Some(name) => name.clone(),
            None => format!("Interface[{}]", self.iface.to_hex_string()),
        }
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

    // Slow links need longer than the default timeout for a full round
    // trip: never wait less than the medium path timeout
    // (Python `rnpath`: `timeout = max(timeout,
    // reticulum.get_medium_path_timeout())`).
    let timeout = timeout.max(transport.medium_path_timeout().await);
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
    Some(PathResult {
        destination: *destination,
        hops,
        via,
        iface,
        iface_name: None,
    })
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
            iface_name: None,
        })
        .collect();
    entries.sort_by(|left, right| {
        left.on_interface()
            .cmp(&right.on_interface())
            .then(left.hops.cmp(&right.hops))
    });
    entries
}

/// Path rows from a shared-instance `path_table` response.
pub fn paths_from_rpc(value: &rmpv::Value) -> Result<Vec<PathResult>, String> {
    let rows = value
        .as_array()
        .ok_or_else(|| "path table is not an array".to_string())?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let destination = rpc_hash(row, "hash")?;
        let via = rpc_hash(row, "via")?;
        let hops =
            rpc_u64(row, "hops").ok_or_else(|| "path table entry is missing hops".to_string())?;
        let interface = rpc_str(row, "interface").unwrap_or_else(|| "None".to_string());
        entries.push(PathResult {
            destination,
            hops: hops as u8,
            via,
            iface: AddressHash::new([0; 16]),
            iface_name: Some(interface),
        });
    }
    entries.sort_by(|left, right| {
        left.on_interface()
            .cmp(&right.on_interface())
            .then(left.hops.cmp(&right.hops))
    });
    Ok(entries)
}

fn rpc_field<'a>(row: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    row.as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn rpc_hash(row: &rmpv::Value, key: &str) -> Result<AddressHash, String> {
    let value = rpc_field(row, key).ok_or_else(|| format!("path table entry is missing {key}"))?;
    let bytes = value
        .as_slice()
        .ok_or_else(|| format!("path table {key} is not bytes"))?;
    AddressHash::new_from_raw_slice(bytes)
        .ok_or_else(|| format!("path table {key} has the wrong length"))
}

fn rpc_u64(row: &rmpv::Value, key: &str) -> Option<u64> {
    let value = rpc_field(row, key)?;
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
}

fn rpc_str(row: &rmpv::Value, key: &str) -> Option<String> {
    rpc_field(row, key).and_then(|value| value.as_str().map(str::to_string))
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
            entry.on_interface()
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
            iface_name: None,
        };
        assert!(result.render().contains("is 1 hop away"));
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 3,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
            iface_name: None,
        };
        assert!(result.render().contains("is 3 hops away"));
    }
}
