//! `rnstatus` — instance status utility (`RNS/Utilities/rnstatus.py`).
//!
//! The column report ([`collect`] / [`StatusReport::render`]) is the local
//! snapshot used by the integration tests. Operator output for a running
//! daemon comes from [`fetch_status`] over the shared-instance RPC, and
//! from [`remote_status`] over a management link.

use std::path::Path;
use std::time::Duration;

use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
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
    /// Shared-instance active link count. `None` for a local report.
    pub active_links: Option<usize>,
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
        } else if self.active_links.is_none() {
            out.push_str(&format!(
                " Standalone instance {} (transport mode disabled)\n",
                self.identity_hash
            ));
        }

        let counts = &self.link_counts;
        let plural = if counts.link_table == 1 { "y" } else { "ies" };
        if let Some(active) = self.active_links {
            out.push_str(&format!(
                " {} entr{} in link table ({} active)\n",
                counts.link_table, plural, active
            ));
        } else {
            out.push_str(&format!(
                " {} entr{} in link table ({} inbound / {} outbound active links)\n",
                counts.link_table, plural, counts.inbound, counts.outbound
            ));
        }

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
        active_links: None,
    }
}

/// Status of a reachable shared instance. Callers that required the shared
/// instance use this instead of the local transport snapshot.
pub async fn collect_shared(
    config_dir: &std::path::Path,
    _transport: &Transport,
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
        None => String::new(),
    };

    Ok(StatusReport {
        instance_name: String::new(),
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
            inbound: 0,
            outbound: 0,
        },
        transport_enabled: transport_id.is_some(),
        active_links: Some(value_usize(&active)),
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

/// Which parts of a daemon status report to print.
#[derive(Debug, Clone, Default)]
pub struct StatusView {
    pub show_all: bool,
    pub link_stats: bool,
    pub totals: bool,
    pub pps: bool,
    pub queues: bool,
    pub profiling: bool,
    pub discovered_only: bool,
    pub show_stale: bool,
    pub show_unknown: bool,
    pub json: bool,
    pub name_filter: Option<String>,
}

/// Status of the shared instance described by `config_dir`.
pub async fn fetch_status(config_dir: &Path, view: &StatusView) -> Result<String, String> {
    let stats = crate::common::shared_rpc(config_dir, get_request("interface_stats", None)).await?;
    if !stats.is_map() {
        return Err("Could not get RNS status".to_string());
    }
    if view.discovered_only {
        return Ok(render_discovered(config_dir, &stats, view));
    }
    let (link_count, active) = if view.link_stats {
        let links = crate::common::shared_rpc(config_dir, get_request("link_count", None)).await?;
        let active =
            crate::common::shared_rpc(config_dir, get_request("active_link_count", None)).await?;
        (Some(value_usize(&links)), Some(value_usize(&active)))
    } else {
        (None, None)
    };
    let profiling = if view.profiling {
        Some(crate::common::shared_rpc(config_dir, get_request("profiling_results", None)).await?)
    } else {
        None
    };
    if view.json {
        return Ok(crate::common::msgpack_json(&stats));
    }
    Ok(render_report(
        &stats,
        view,
        link_count,
        active,
        profiling.as_ref(),
    ))
}

/// Attach, detach, or reload one interface (`manage` RPC).
pub async fn manage_interface(
    config_dir: &Path,
    action: &str,
    name: &str,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("manage"),
                rmpv::Value::from(format!("{action}_interface")),
            ),
            (
                rmpv::Value::from("name"),
                rmpv::Value::from(name.to_string()),
            ),
        ]),
    )
    .await?;
    let past = match action {
        "attach" => "attached",
        "detach" => "detached",
        "reload" => "reloaded",
        other => other,
    };
    match value.as_bool() {
        Some(true) => Ok(format!("Interface {name} was {past}")),
        Some(false) => Err(format!("Could not {action} interface {name}")),
        None if value.is_nil() => Err(format!("The interface {name} does not exist")),
        None => Err(format!("Unknown error while {action}ing interface {name}")),
    }
}

/// Status of a remote transport over `rnstransport.remote.management`.
pub async fn remote_status(
    transport: &Transport,
    identity_hash: &AddressHash,
    identity: &PrivateIdentity,
    view: &StatusView,
    timeout: Duration,
) -> Result<String, String> {
    let destination =
        crate::rnpath::named_destination("rnstransport", "remote.management", identity_hash);
    let payload = pack_value(&rmpv::Value::Array(vec![
        rmpv::Value::Boolean(view.link_stats),
        rmpv::Value::Boolean(view.profiling),
    ]))?;
    let bytes = crate::rnpath::remote_request(
        transport,
        &destination,
        Some(identity),
        "/status",
        &payload,
        timeout,
    )
    .await?;
    let mut cursor = bytes.as_slice();
    let value = rmpv::decode::read_value(&mut cursor).map_err(|err| err.to_string())?;
    let (stats, link_count, profiling) = split_remote_status(&value).ok_or_else(|| {
        format!(
            "Could not get RNS status from remote transport instance {}",
            crate::common::prettyhexrep(identity_hash.as_slice())
        )
    })?;
    if view.json {
        return Ok(crate::common::msgpack_json(&stats));
    }
    let link_count = if view.link_stats { link_count } else { None };
    Ok(render_report(
        &stats,
        view,
        link_count,
        None,
        profiling.as_ref(),
    ))
}

fn split_remote_status(
    value: &rmpv::Value,
) -> Option<(rmpv::Value, Option<usize>, Option<rmpv::Value>)> {
    let items = value.as_array()?;
    let stats = match items.first()? {
        item if item.is_map() => item.clone(),
        item if item.as_array().is_some() => {
            rmpv::Value::Map(vec![(rmpv::Value::from("interfaces"), item.clone())])
        }
        _ => return None,
    };
    let link_count = items.get(1).and_then(value_u64).map(|count| count as usize);
    let profiling = items.get(2).cloned().filter(|item| !item.is_nil());
    Some((stats, link_count, profiling))
}

fn pack_value(value: &rmpv::Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value).map_err(|err| err.to_string())?;
    Ok(buf)
}

fn render_report(
    stats: &rmpv::Value,
    view: &StatusView,
    link_count: Option<usize>,
    active: Option<usize>,
    profiling: Option<&rmpv::Value>,
) -> String {
    let mut out = String::new();
    if let Some(interfaces) = map_field(stats, "interfaces").and_then(|value| value.as_array()) {
        for iface in interfaces {
            if let Some(block) = render_interface(iface, view) {
                out.push('\n');
                out.push_str(&block);
            }
        }
    }
    let transport_id = map_field(stats, "transport_id").and_then(|value| value.as_slice());
    let lstr = link_summary(link_count, active, transport_id.is_some(), view.link_stats);
    if view.totals {
        out.push_str(&render_totals(stats, view.pps));
    }
    if view.queues {
        out.push_str(&render_queues(stats));
    }
    if let Some(profiling) = profiling
        .filter(|value| value.is_map() && !value.as_map().is_some_and(|rows| rows.is_empty()))
    {
        out.push_str("\n Profiling    :\n");
        out.push_str(&format_profiling(profiling));
    }
    if let Some(bytes) = transport_id {
        out.push_str(&format!(
            "\n Transport Instance {} running\n",
            crate::common::prettyhexrep(bytes)
        ));
        if let Some(network) = map_field(stats, "network_id").and_then(|value| value.as_slice()) {
            out.push_str(&format!(
                " Network Identity   {}\n",
                crate::common::prettyhexrep(network)
            ));
        }
        if let Some(probe) = map_field(stats, "probe_responder").and_then(|value| value.as_slice())
        {
            out.push_str(&format!(
                " Probe responder at {} active\n",
                crate::common::prettyhexrep(probe)
            ));
        }
        if let Some(uptime) = map_field(stats, "transport_uptime").and_then(as_f64) {
            out.push_str(&format!(
                " Uptime is {}{lstr}\n",
                crate::common::pretty_time(uptime)
            ));
        }
    } else if !lstr.is_empty() {
        out.push('\n');
        out.push_str(&lstr);
        out.push('\n');
    }
    out.push('\n');
    out
}

fn link_summary(
    link_count: Option<usize>,
    active: Option<usize>,
    transport: bool,
    enabled: bool,
) -> String {
    if !enabled {
        return String::new();
    }
    let Some(count) = link_count else {
        return String::new();
    };
    let plural = if count == 1 { "y" } else { "ies" };
    let mut text = if transport {
        format!(", {count} entr{plural} in link table")
    } else {
        format!(" {count} entr{plural} in link table")
    };
    if let Some(active) = active.filter(|count| *count > 0) {
        text = format!("{text} ({active} active)");
    }
    text
}

fn render_interface(iface: &rmpv::Value, view: &StatusView) -> Option<String> {
    let name = field_str(iface, "name")?;
    if hidden_interface(&name, iface, view.show_all) {
        return None;
    }
    if let Some(filter) = &view.name_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return None;
        }
    }
    let mut out = format!(" {name}\n");
    out.push_str(&format!("    Status    : {}\n", status_text(iface)));
    if let Some(clients) = clients_line(&name, iface) {
        out.push_str(&format!("    {clients}\n"));
    }
    if show_mode(&name) {
        out.push_str(&format!("    Mode      : {}\n", mode_text(iface)));
    }
    if map_field(iface, "txdrp").is_some_and(truthy) {
        let drops = field_u64(iface, "txdrp");
        out.push_str(&format!(
            "    TX Drops  : {drops} ({})\n",
            pretty_size(field_u64(iface, "txdrb"))
        ));
    }
    if let Some(bitrate) = map_field(iface, "bitrate").filter(|value| !value.is_nil()) {
        let mtu = match map_field(iface, "mtu") {
            Some(value) if !value.is_nil() => display_num(value),
            Some(_) => "None".to_string(),
            None => String::new(),
        };
        if mtu.is_empty() {
            out.push_str(&format!(
                "    Rate      : {}\n",
                speed_str(as_f64(bitrate).unwrap_or(0.0))
            ));
        } else {
            out.push_str(&format!(
                "    Rate      : {}, MTU {mtu}\n",
                speed_str(as_f64(bitrate).unwrap_or(0.0))
            ));
        }
    }
    if let (Some(short), Some(long)) = (
        map_field(iface, "airtime_short"),
        map_field(iface, "airtime_long"),
    ) {
        out.push_str(&format!(
            "    Airtime   : {}% (15s), {}% (1h)\n",
            display_num(short),
            display_num(long)
        ));
    }
    if let (Some(short), Some(long)) = (
        map_field(iface, "channel_load_short"),
        map_field(iface, "channel_load_long"),
    ) {
        out.push_str(&format!(
            "    Ch. Load  : {}% (15s), {}% (1h)\n",
            display_num(short),
            display_num(long)
        ));
    }
    let violations = field_u64(iface, "protocol_violations");
    let ifac = field_u64(iface, "ifac_violations");
    if map_field(iface, "protocol_violations").is_some() && (violations > 0 || ifac > 0) {
        let pv = if violations > 0 {
            format!("{violations} protocol")
        } else {
            String::new()
        };
        let joiner = if violations > 0 && ifac > 0 { ", " } else { "" };
        let iv = if ifac > 0 {
            format!("{ifac} IFAC")
        } else {
            String::new()
        };
        out.push_str(&format!("    Violatns. : {pv}{joiner}{iv}\n"));
    }
    if map_field(iface, "packet_filter_hits").is_some_and(truthy) {
        out.push_str(&format!(
            "    Flt. Hits : {}\n",
            field_u64(iface, "packet_filter_hits")
        ));
    }
    out.push_str(&traffic_lines(iface));
    Some(out)
}

fn status_text(iface: &rmpv::Value) -> String {
    let up = match map_field(iface, "status") {
        Some(value) => match value.as_bool() {
            Some(up) => up,
            None => {
                let text = value.as_str().unwrap_or("");
                text.eq_ignore_ascii_case("online")
                    || text.eq_ignore_ascii_case("up")
                    || text.eq_ignore_ascii_case("true")
            }
        },
        None => false,
    };
    let mut text = if up {
        "Up".to_string()
    } else {
        "Down".to_string()
    };
    if let Some(gravity) = map_field(iface, "gravity").filter(|value| truthy(value)) {
        text.push_str(&format!(", gravity {}", display_num(gravity)));
    }
    text
}

fn clients_line(name: &str, iface: &rmpv::Value) -> Option<String> {
    let clients = map_field(iface, "clients")?;
    if clients.is_nil() {
        return None;
    }
    let count = value_u64(clients).unwrap_or(0);
    if name.starts_with("Shared Instance[") {
        let count = count.saturating_sub(1);
        let spec = if count == 1 { " program" } else { " programs" };
        Some(format!("Serving   : {count}{spec}"))
    } else {
        Some(format!("Clients   : {count}"))
    }
}

fn show_mode(name: &str) -> bool {
    !(name.starts_with("Shared Instance[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("LocalInterface["))
}

fn mode_text(iface: &rmpv::Value) -> String {
    let mut text = match field_u64(iface, "mode") {
        0x02 => "Point-to-Point",
        0x03 => "Access Point",
        0x04 => "Roaming",
        0x05 => "Boundary",
        0x06 => "Gateway",
        0x07 => "Internal",
        _ => "Full",
    }
    .to_string();
    if map_field(iface, "announces_to_internal").and_then(|value| value.as_bool()) == Some(true) {
        text.push_str(" (a>i)");
    }
    text
}

fn hidden_interface(name: &str, iface: &rmpv::Value, show_all: bool) -> bool {
    if show_all {
        return false;
    }
    if name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer")
    {
        return true;
    }
    name.starts_with("I2PInterface[")
        && map_field(iface, "i2p_connectable").and_then(|value| value.as_bool()) == Some(false)
}

fn traffic_lines(iface: &rmpv::Value) -> String {
    let mut tx = format!("↑{}", pretty_size(field_u64(iface, "txb")));
    let mut rx = format!("↓{}", pretty_size(field_u64(iface, "rxb")));
    let width = tx.chars().count().max(rx.chars().count()).max(10);
    pad_to(&mut tx, width);
    pad_to(&mut rx, width);
    if map_field(iface, "rxs").is_some() && map_field(iface, "txs").is_some() {
        tx.push_str(&format!(
            "  {}",
            pretty_speed(field_u64(iface, "txs") as f64)
        ));
        rx.push_str(&format!(
            "  {}",
            pretty_speed(field_u64(iface, "rxs") as f64)
        ));
    }
    if map_field(iface, "txbuffered").is_some_and(truthy) {
        let stalled =
            if map_field(iface, "txstalled").and_then(|value| value.as_bool()) == Some(true) {
                ", stalled"
            } else {
                ""
            };
        tx.push_str(&format!(
            " ({} waiting{stalled})",
            pretty_size(field_u64(iface, "txbuffered"))
        ));
    }
    format!("    Traffic   : {tx}\n                {rx}\n")
}

fn render_totals(stats: &rmpv::Value, pps: bool) -> String {
    let mut tx = format!("↑{}", pretty_size(field_u64(stats, "txb")));
    let mut rx = format!("↓{}", pretty_size(field_u64(stats, "rxb")));
    let width = tx.chars().count().max(rx.chars().count());
    pad_to(&mut tx, width);
    pad_to(&mut rx, width);
    tx.push_str(&format!(
        "  {}",
        pretty_speed(field_u64(stats, "txs") as f64)
    ));
    rx.push_str(&format!(
        "  {}",
        pretty_speed(field_u64(stats, "rxs") as f64)
    ));
    if pps {
        tx.push_str(&format!(
            ", {}",
            pretty_unit(field_u64(stats, "txpps") as f64, "pps")
        ));
        rx.push_str(&format!(
            ", {}",
            pretty_unit(field_u64(stats, "rxpps") as f64, "pps")
        ));
    }
    format!("\n Totals       : {tx}\n                {rx}\n")
}

fn render_queues(stats: &rmpv::Value) -> String {
    format!(
        "\n Qu. Pressure : {}\n                {}\n                {}\n                {}\n                {}\n",
        queue_line(stats, "tqpressure", "total", "rxqt", "rxqtd"),
        queue_line(stats, "dqpressure", "data", "rxqd", "rxqdd"),
        queue_line(stats, "aqpressure", "announce", "rxqa", "rxqad"),
        queue_line(stats, "pqpressure", "path request", "rxqp", "rxqpd"),
        queue_line(stats, "ilqpressure", "ingress limiter", "rxqil", "rxqild"),
    )
}

fn queue_line(stats: &rmpv::Value, pressure: &str, label: &str, pkts: &str, drops: &str) -> String {
    let fraction = map_field(stats, pressure).and_then(as_f64).unwrap_or(0.0) * 100.0;
    let dropped = field_u64(stats, drops);
    let dropped = if dropped > 0 {
        format!(", {dropped} dropped")
    } else {
        String::new()
    };
    format!(
        "{fraction:.1}% {label}, {} pkts{dropped}",
        field_u64(stats, pkts)
    )
}

fn render_discovered(config_dir: &Path, stats: &rmpv::Value, view: &StatusView) -> String {
    let entries = discovery_entries(config_dir, stats);
    if view.json {
        return crate::common::msgpack_json(&rmpv::Value::Array(entries));
    }
    let mut out = format!(
        "\n{:<25} {:<10}   {:<10} {:<12} {:<7} {:<16} {:<15}\n",
        "Name", "Type", "Status", "Last Heard", "Value", "Running", "Location"
    );
    out.push_str(&"-".repeat(110));
    out.push('\n');
    let now = crate::common::unix_now();
    for entry in entries {
        if let Some(line) = discovery_row(&entry, view, now) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

fn discovery_entries(config_dir: &Path, stats: &rmpv::Value) -> Vec<rmpv::Value> {
    if let Some(rows) = map_field(stats, "discovered").and_then(|value| value.as_array()) {
        if !rows.is_empty() {
            return rows.clone();
        }
    }
    let dir = config_dir
        .join("storage")
        .join("discovery")
        .join("interfaces");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if let Ok(value) = rmpv::decode::read_value(&mut bytes.as_slice()) {
            if value.is_map() {
                out.push(value);
            }
        }
    }
    out
}

fn discovery_row(entry: &rmpv::Value, view: &StatusView, now: f64) -> Option<String> {
    let name = field_str(entry, "name").unwrap_or_default();
    if let Some(filter) = &view.name_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return None;
        }
    }
    let status = discovery_status(entry, now);
    if status == "removed" || (status == "stale" && !view.show_stale) {
        return None;
    }
    let impl_name = field_str(entry, "impl_name").unwrap_or_default();
    let version = field_str(entry, "version").unwrap_or_default();
    let has_impl = !impl_name.is_empty() && !version.is_empty();
    if !has_impl && !view.show_unknown {
        return None;
    }
    let impl_str = if has_impl {
        clip_impl(&format!("{impl_name} {version}"))
    } else {
        "Unknown".to_string()
    };
    let kind = field_str(entry, "type")
        .unwrap_or_default()
        .replace("Interface", "");
    let shown = match status.as_str() {
        "available" => "✓ Available".to_string(),
        "unknown" => "? Unknown".to_string(),
        "stale" => "× Stale".to_string(),
        other => other.to_string(),
    };
    let heard = map_field(entry, "last_heard")
        .and_then(as_f64)
        .unwrap_or(now);
    let name = clip_name(&name);
    Some(format!(
        "{:<25} {:<10} {:<12} {:<12} {:<7} {:<16} {:<15}",
        name,
        kind,
        shown,
        heard_text(now - heard),
        display_num(map_field(entry, "value").unwrap_or(&rmpv::Value::Nil)),
        impl_str,
        location_text(entry),
    ))
}

fn discovery_status(entry: &rmpv::Value, now: f64) -> String {
    if let Some(text) = map_field(entry, "status").and_then(|value| value.as_str()) {
        return text.to_string();
    }
    let heard = map_field(entry, "last_heard")
        .and_then(as_f64)
        .unwrap_or(0.0);
    let age = now - heard;
    if age > 7.0 * 86_400.0 {
        "removed".to_string()
    } else if age > 3.0 * 86_400.0 {
        "stale".to_string()
    } else if age > 86_400.0 {
        "unknown".to_string()
    } else {
        "available".to_string()
    }
}

fn heard_text(diff: f64) -> String {
    if diff < 60.0 {
        "Just now".to_string()
    } else if diff < 3_600.0 {
        format!("{}m ago", (diff / 60.0) as u64)
    } else if diff < 86_400.0 {
        format!("{}h ago", (diff / 3_600.0) as u64)
    } else {
        format!("{}d ago", (diff / 86_400.0) as u64)
    }
}

fn location_text(entry: &rmpv::Value) -> String {
    match (
        map_field(entry, "latitude").and_then(as_f64),
        map_field(entry, "longitude").and_then(as_f64),
    ) {
        (Some(lat), Some(lon)) => format!("{}, {}", trim_coord(lat), trim_coord(lon)),
        _ => "N/A".to_string(),
    }
}

fn trim_coord(value: f64) -> String {
    let rounded = (value * 10_000.0).round() / 10_000.0;
    let mut text = format!("{rounded:.4}");
    while text.contains('.') && text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text
}

fn clip_name(name: &str) -> String {
    if name.chars().count() > 24 {
        let mut out: String = name.chars().take(24).collect();
        out.push('…');
        out
    } else {
        name.to_string()
    }
}

fn clip_impl(text: &str) -> String {
    if text.chars().count() > 16 {
        let mut out: String = text.chars().take(15).collect();
        out.push('…');
        out
    } else {
        text.to_string()
    }
}

fn format_profiling(results: &rmpv::Value) -> String {
    let Some(rows) = results.as_map() else {
        return String::new();
    };
    let mut out = String::new();
    for (_, tag) in rows {
        if profile_super(tag).is_none() {
            out.push_str(&profile_tree(tag, results, 0));
        }
    }
    out
}

fn profile_tree(tag: &rmpv::Value, results: &rmpv::Value, level: usize) -> String {
    let mut out = profile_tag(tag, level + 1);
    out.push('\n');
    let name = field_str(tag, "name").unwrap_or_default();
    if let Some(rows) = results.as_map() {
        for (_, child) in rows {
            if profile_super(child).as_deref() == Some(name.as_str()) {
                out.push_str(&profile_tree(child, results, level + 1));
            }
        }
    }
    out
}

fn profile_tag(tag: &rmpv::Value, level: usize) -> String {
    let ind = "  ".repeat(level);
    let name = field_str(tag, "name").unwrap_or_default();
    let Some(stats_all) = map_field(tag, "stats_all").filter(|value| value.is_map()) else {
        return format!(" {ind}{name}");
    };
    let threads = field_u64(stats_all, "threads");
    let plural = if threads == 1 { "" } else { "s" };
    let mut out = format!(" {ind}{name}\n");
    out.push_str(&format!(
        " {ind}  Samples  : {} from {threads} thread{plural}\n",
        field_u64(stats_all, "count")
    ));
    out.push_str(&format!(
        " {ind}              {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15}\n",
        "Mean", "Median", "Min", "Max", "St. dev", "Total"
    ));
    out.push_str(&profile_window(&ind, "Stats    ", stats_all));
    for (key, label) in [
        ("stats_1m", " 0-1m    "),
        ("stats_5m", " 1-5m    "),
        ("stats_30m", " 5-30m    "),
        ("stats_60m", "30-60m    "),
    ] {
        if let Some(window) = map_field(tag, key).filter(|value| value.is_map()) {
            out.push_str(&profile_window(&ind, label, window));
        }
    }
    out
}

fn profile_window(ind: &str, label: &str, window: &rmpv::Value) -> String {
    format!(
        " {ind}  {label}: ({:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15})\n",
        short_time(map_field(window, "mean")),
        short_time(map_field(window, "median")),
        short_time(map_field(window, "min")),
        short_time(map_field(window, "max")),
        short_time(map_field(window, "stdev")),
        short_time(map_field(window, "sum")),
    )
}

fn profile_super(tag: &rmpv::Value) -> Option<String> {
    map_field(tag, "super").and_then(|value| value.as_str().map(str::to_string))
}

fn short_time(value: Option<&rmpv::Value>) -> String {
    let Some(value) = value else {
        return "-----".to_string();
    };
    if value.is_nil() {
        return "-----".to_string();
    }
    pretty_short_time(as_f64(value).unwrap_or(0.0))
}

fn pretty_short_time(seconds: f64) -> String {
    let mut micros = seconds * 1_000_000.0;
    if !micros.is_finite() {
        return "0us".to_string();
    }
    let neg = micros < 0.0;
    micros = micros.abs();
    let whole_seconds = (micros / 1_000_000.0) as u64;
    micros %= 1_000_000.0;
    let millis = (micros / 1_000.0) as u64;
    micros %= 1_000.0;
    let mut parts = Vec::new();
    if whole_seconds > 0 {
        parts.push(format!("{whole_seconds}s"));
    }
    if millis > 0 {
        parts.push(format!("{millis}ms"));
    }
    if micros > 0.0 {
        let rounded = micros.round();
        if (rounded - rounded.trunc()).abs() < 1e-6 {
            parts.push(format!("{}µs", rounded as u64));
        } else {
            parts.push(format!("{rounded}µs"));
        }
    }
    if parts.is_empty() {
        return "0us".to_string();
    }
    let text = parts.join(" ");
    if neg {
        format!("-{text}")
    } else {
        text
    }
}

fn speed_str(num: f64) -> String {
    let units = ["", "k", "M", "G", "T", "P", "E", "Z"];
    let mut num = num;
    for unit in units {
        if num.abs() < 1_000.0 {
            return format!("{num:3.2} {unit}bps");
        }
        num /= 1_000.0;
    }
    format!("{num:.2} Ybps")
}

fn pretty_speed(num: f64) -> String {
    format!("{}ps", pretty_unit(num / 8.0, "b"))
}

fn pretty_unit(num: f64, suffix: &str) -> String {
    let mut num = if suffix == "b" { num * 8.0 } else { num };
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    for unit in units {
        if num.abs() < 1_000.0 {
            if unit.is_empty() {
                return format!("{num:.0} {unit}{suffix}");
            }
            return format!("{num:.2} {unit}{suffix}");
        }
        num /= 1_000.0;
    }
    format!("{num:.2} Y{suffix}")
}

fn pad_to(text: &mut String, width: usize) {
    while text.chars().count() < width {
        text.push(' ');
    }
}

fn display_num(value: &rmpv::Value) -> String {
    if let Some(number) = value.as_i64() {
        return number.to_string();
    }
    if let Some(number) = value.as_u64() {
        return number.to_string();
    }
    if let Some(number) = as_f64(value) {
        return format!("{number}");
    }
    "None".to_string()
}

fn as_f64(value: &rmpv::Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_i64()
            .map(|item| item as f64)
            .or_else(|| value.as_u64().map(|item| item as f64))
    })
}

fn truthy(value: &rmpv::Value) -> bool {
    match value {
        rmpv::Value::Nil => false,
        rmpv::Value::Boolean(item) => *item,
        rmpv::Value::Integer(item) => item.as_i64() != Some(0),
        rmpv::Value::F32(item) => *item != 0.0,
        rmpv::Value::F64(item) => *item != 0.0,
        rmpv::Value::String(item) => item.as_str().is_some_and(|text| !text.is_empty()),
        rmpv::Value::Binary(item) => !item.is_empty(),
        rmpv::Value::Array(item) => !item.is_empty(),
        rmpv::Value::Map(item) => !item.is_empty(),
        rmpv::Value::Ext(_, item) => !item.is_empty(),
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
                announces: "0/0 (0 B/0 B)".to_string(),
                path_requests: "0/0".to_string(),
                violations: "0/0 (filter 0)".to_string(),
            }],
            paths: vec![],
            link_counts: Default::default(),
            transport_enabled: true,
            active_links: None,
            queue_pressure: (0, [0; 4], [0; 4]),
        };
        let text = report.render();
        assert!(text.contains("Transport Instance <aabb> running"));
        assert!(text.contains("Name"));
        assert!(text.contains("Interface[aa]"));
        assert!(text.contains("No information available"));
    }
}
