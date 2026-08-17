//! `rnstatus` — instance status utility (subset of
//! `RNS/Utilities/rnstatus.py`, local mode).
//!
//! Prints the interface stats table, the local path table, link counts and
//! the transport instance identity hash. Remote mode (querying another
//! transport instance over a management link) is not implemented yet.

use reticulum::transport::Transport;
use serde::Serialize;

/// Human-readable byte size (Python `RNS.prettysize`).
pub fn pretty_size(num: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut value = num as f64;
    let mut unit = 0;
    while value.abs() >= 1000.0 && unit < units.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", units[unit])
    } else {
        format!("{value:.2} {}", units[unit])
    }
}

/// One row of the interface table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IfaceRow {
    pub name: String,
    pub kind: String,
    pub status: &'static str,
    pub mode: &'static str,
    pub bitrate: String,
    pub tx: String,
    pub rx: String,
}

/// Snapshot of everything `rnstatus` displays.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub instance_name: String,
    pub identity_hash: String,
    pub interfaces: Vec<IfaceRow>,
    pub paths: Vec<crate::rnpath::PathResult>,
    pub link_counts: reticulum::transport::LinkCounts,
    pub transport_enabled: bool,
}

#[derive(Serialize)]
struct LinkCountsJson {
    link_table: usize,
    inbound: usize,
    outbound: usize,
}

#[derive(Serialize)]
struct StatusJson<'a> {
    instance_name: &'a str,
    transport_id: &'a str,
    interfaces: &'a [IfaceRow],
    paths: Vec<PathEntryJson>,
    link_counts: LinkCountsJson,
}

#[derive(Serialize)]
struct PathEntryJson {
    hash: String,
    hops: u8,
    via: String,
    interface: String,
}

impl StatusReport {
    pub fn render(&self) -> String {
        let mut out = String::new();

        // Interface table, mirroring the Python column set
        // (Name, Status, Mode, Bitrate, TX, RX, ...).
        out.push_str(&format!(
            "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10}\n",
            "Name", "Type", "Status", "Mode", "Bitrate", "TX", "RX"
        ));
        out.push_str(&"-".repeat(98));
        out.push('\n');
        for iface in &self.interfaces {
            out.push_str(&format!(
                "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10}\n",
                iface.name,
                iface.kind,
                iface.status,
                iface.mode,
                iface.bitrate,
                iface.tx,
                iface.rx
            ));
        }
        if self.interfaces.is_empty() {
            out.push_str("(no interfaces)\n");
        }

        out.push('\n');
        if self.transport_enabled {
            out.push_str(&format!(
                " Transport Instance {} running\n",
                self.identity_hash
            ));
        } else {
            out.push_str(&format!(
                " Standalone instance {} (transport mode disabled)\n",
                self.identity_hash
            ));
        }

        let counts = &self.link_counts;
        let plural = if counts.link_table == 1 { "y" } else { "ies" };
        out.push_str(&format!(
            " {} entr{} in link table ({} inbound / {} outbound active links)\n",
            counts.link_table, plural, counts.inbound, counts.outbound
        ));

        out.push('\n');
        out.push_str(&format!(" Path table ({} entries):\n", self.paths.len()));
        if self.paths.is_empty() {
            out.push_str("   No information available\n");
        } else {
            out.push_str("  ");
            out.push_str(&crate::rnpath::render_table(&self.paths).replace('\n', "\n  "));
        }
        out
    }

    pub fn to_json(&self) -> String {
        let json = StatusJson {
            instance_name: &self.instance_name,
            transport_id: &self.identity_hash,
            interfaces: &self.interfaces,
            paths: self
                .paths
                .iter()
                .map(|entry| PathEntryJson {
                    hash: crate::common::prettyhexrep(entry.destination.as_slice()),
                    hops: entry.hops,
                    via: crate::common::prettyhexrep(entry.via.as_slice()),
                    interface: entry.iface.to_hex_string(),
                })
                .collect(),
            link_counts: LinkCountsJson {
                link_table: self.link_counts.link_table,
                inbound: self.link_counts.inbound,
                outbound: self.link_counts.outbound,
            },
        };
        serde_json::to_string_pretty(&json).unwrap_or_default()
    }
}

/// Collect the status report for a local transport.
///
/// `transport_enabled` should reflect whether the instance routes for others
/// (Python only prints "Transport Instance … running" when it does).
pub async fn collect(transport: &Transport, transport_enabled: bool) -> StatusReport {
    let interfaces = crate::common::interface_stats(transport)
        .await
        .into_iter()
        .map(|stats| IfaceRow {
            name: stats.name,
            kind: stats.kind,
            status: if stats.online { "Up" } else { "Down" },
            // Interface modes and configured bitrates are not tracked yet.
            mode: "Full",
            bitrate: "Unknown".to_string(),
            tx: pretty_size(stats.tx_bytes),
            rx: pretty_size(stats.rx_bytes),
        })
        .collect();

    StatusReport {
        instance_name: transport.instance_name().await,
        identity_hash: crate::common::prettyhexrep(transport.identity_hash().await.as_slice()),
        interfaces,
        paths: crate::rnpath::path_table(transport, None, None).await,
        link_counts: transport.link_counts().await,
        transport_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_sizes() {
        assert_eq!(pretty_size(0), "0 B");
        assert_eq!(pretty_size(999), "999 B");
        assert_eq!(pretty_size(1500), "1.50 KB");
        assert_eq!(pretty_size(5_000_000), "5.00 MB");
    }

    #[test]
    fn render_contains_transport_instance() {
        let report = StatusReport {
            instance_name: "test".to_string(),
            identity_hash: "<aabb>".to_string(),
            interfaces: vec![IfaceRow {
                name: "Interface[aa]".to_string(),
                kind: "UdpInterface".to_string(),
                status: "Up",
                mode: "Full",
                bitrate: "Unknown".to_string(),
                tx: "0 B".to_string(),
                rx: "0 B".to_string(),
            }],
            paths: vec![],
            link_counts: Default::default(),
            transport_enabled: true,
        };
        let text = report.render();
        assert!(text.contains("Transport Instance <aabb> running"));
        assert!(text.contains("Name"));
        assert!(text.contains("Interface[aa]"));
        assert!(text.contains("No information available"));
    }
}
