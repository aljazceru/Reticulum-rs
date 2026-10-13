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
    /// Announces sent/received (Python 1.5.0 `rnstatus` traffic stats).
    pub announces: String,
    /// Path requests sent/received.
    pub path_requests: String,
    /// Protocol violations / IFAC violations / filter hits.
    pub violations: String,
}

/// Snapshot of everything `rnstatus` displays.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub instance_name: String,
    pub identity_hash: String,
    /// Inbound queue pressure: total, per-class heights, per-class drops
    /// (Python 1.5.0 `rnstatus` queue pressure statistics).
    pub queue_pressure: (usize, [usize; 4], [u64; 4]),
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
            "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10} {:<20} {:<8} {:<16}\n",
            "Name",
            "Type",
            "Status",
            "Mode",
            "Bitrate",
            "TX",
            "RX",
            "Announces",
            "PRs",
            "Violations"
        ));
        out.push_str(&"-".repeat(150));
        out.push('\n');
        for iface in &self.interfaces {
            out.push_str(&format!(
                "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10} {:<20} {:<8} {:<16}\n",
                iface.name,
                iface.kind,
                iface.status,
                iface.mode,
                iface.bitrate,
                iface.tx,
                iface.rx,
                iface.announces,
                iface.path_requests,
                iface.violations
            ));
        }
        if self.interfaces.is_empty() {
            out.push_str("(no interfaces)\n");
        }

        out.push_str(&format!(
            "Inbound queue pressure: {} items (data {}, announce {}, PR {}, IL {}), dropped {}\n",
            self.queue_pressure.0,
            self.queue_pressure.1[0],
            self.queue_pressure.1[1],
            self.queue_pressure.1[2],
            self.queue_pressure.1[3],
            self.queue_pressure.2.iter().sum::<u64>(),
        ));

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
                    interface: entry.on_interface(),
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
            announces: format!(
                "{}/{} ({}/{})",
                stats.announces_sent,
                stats.announces_received,
                pretty_size(stats.announce_bytes_sent),
                pretty_size(stats.announce_bytes_received),
            ),
            path_requests: format!(
                "{}/{}",
                stats.path_requests_sent, stats.path_requests_received
            ),
            violations: format!(
                "{}/{} (filter {})",
                stats.protocol_violations, stats.ifac_violations, stats.packet_filter_hits
            ),
        })
        .collect();

    StatusReport {
        instance_name: transport.instance_name().await,
        identity_hash: crate::common::prettyhexrep(transport.identity_hash().await.as_slice()),
        queue_pressure: transport.inbound_queue_snapshot().await,
        interfaces,
        paths: crate::rnpath::path_table(transport, None, None).await,
        link_counts: transport.link_counts().await,
        transport_enabled,
    }
}

/// Status of a reachable shared instance. Callers that required the shared
/// instance use this instead of the local transport snapshot.
pub async fn collect_shared(
    config_dir: &std::path::Path,
    transport: &Transport,
) -> Result<StatusReport, String> {
    let stats = crate::common::shared_rpc(config_dir, get_request("interface_stats", None)).await?;
    let paths = crate::common::shared_rpc(
        config_dir,
        get_request("path_table", Some(("max_hops", rmpv::Value::Nil))),
    )
    .await?;
    let link_count = crate::common::shared_rpc(config_dir, get_request("link_count", None)).await?;
    let active =
        crate::common::shared_rpc(config_dir, get_request("active_link_count", None)).await?;

    let interfaces = map_field(&stats, "interfaces")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "interface stats are missing interfaces".to_string())?
        .iter()
        .filter_map(iface_row)
        .collect();

    let transport_id = map_field(&stats, "transport_id").and_then(|value| value.as_slice());
    let identity_hash = match transport_id {
        Some(bytes) => crate::common::prettyhexrep(bytes),
        None => crate::common::prettyhexrep(transport.identity_hash().await.as_slice()),
    };

    Ok(StatusReport {
        instance_name: transport.instance_name().await,
        identity_hash,
        queue_pressure: (
            field_usize(&stats, "rxqt"),
            [
                field_usize(&stats, "rxqd"),
                field_usize(&stats, "rxqa"),
                field_usize(&stats, "rxqp"),
                field_usize(&stats, "rxqil"),
            ],
            [
                field_u64(&stats, "rxqdd"),
                field_u64(&stats, "rxqad"),
                field_u64(&stats, "rxqpd"),
                field_u64(&stats, "rxqild"),
            ],
        ),
        interfaces,
        paths: crate::rnpath::paths_from_rpc(&paths)?,
        link_counts: reticulum::transport::LinkCounts {
            link_table: value_usize(&link_count),
            inbound: value_usize(&active),
            outbound: 0,
        },
        transport_enabled: transport_id.is_some(),
    })
}

fn get_request(path: &str, extra: Option<(&str, rmpv::Value)>) -> rmpv::Value {
    let mut map = vec![(
        rmpv::Value::from("get"),
        rmpv::Value::from(path.to_string()),
    )];
    if let Some((key, value)) = extra {
        map.push((rmpv::Value::from(key), value));
    }
    rmpv::Value::Map(map)
}

fn iface_row(value: &rmpv::Value) -> Option<IfaceRow> {
    let name = field_str(value, "name")?;
    let kind = field_str(value, "type").unwrap_or_default();
    let online = map_field(value, "status").and_then(|item| item.as_bool()) == Some(true);
    let mode = mode_label(field_u64(value, "mode"));
    let bitrate = field_u64(value, "bitrate");
    Some(IfaceRow {
        name,
        kind,
        status: if online { "Up" } else { "Down" },
        mode,
        bitrate: if bitrate == 0 {
            "Unknown".to_string()
        } else {
            bitrate.to_string()
        },
        tx: pretty_size(field_u64(value, "txb")),
        rx: pretty_size(field_u64(value, "rxb")),
        announces: format!(
            "{}/{} ({}/{})",
            field_u64(value, "atxc"),
            field_u64(value, "arxc"),
            pretty_size(field_u64(value, "atxb")),
            pretty_size(field_u64(value, "arxb")),
        ),
        path_requests: format!("{}/{}", field_u64(value, "ptxc"), field_u64(value, "prxc")),
        violations: format!(
            "{}/{} (filter {})",
            field_u64(value, "protocol_violations"),
            field_u64(value, "ifac_violations"),
            field_u64(value, "packet_filter_hits")
        ),
    })
}

fn mode_label(mode: u64) -> &'static str {
    match mode {
        0x02 => "PtP",
        0x03 => "AP",
        0x04 => "Roaming",
        0x05 => "Boundary",
        0x06 => "Gateway",
        0x07 => "Internal",
        _ => "Full",
    }
}

fn map_field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn field_str(value: &rmpv::Value, key: &str) -> Option<String> {
    map_field(value, key).and_then(|item| item.as_str().map(str::to_string))
}

fn field_u64(value: &rmpv::Value, key: &str) -> u64 {
    map_field(value, key).and_then(value_u64).unwrap_or(0)
}

fn field_usize(value: &rmpv::Value, key: &str) -> usize {
    field_u64(value, key) as usize
}

fn value_usize(value: &rmpv::Value) -> usize {
    value_u64(value).unwrap_or(0) as usize
}

fn value_u64(value: &rmpv::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
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
                announces: "0/0 (0 B/0 B)".to_string(),
                path_requests: "0/0".to_string(),
                violations: "0/0 (filter 0)".to_string(),
            }],
            paths: vec![],
            link_counts: Default::default(),
            transport_enabled: true,
            queue_pressure: (0, [0; 4], [0; 4]),
        };
        let text = report.render();
        assert!(text.contains("Transport Instance <aabb> running"));
        assert!(text.contains("Name"));
        assert!(text.contains("Interface[aa]"));
        assert!(text.contains("No information available"));
    }
}
