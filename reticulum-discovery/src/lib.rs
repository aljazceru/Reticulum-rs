//! Reticulum network interface discovery — Python `RNS/Discovery.py`
//! parity (Phase 6.6).
//!
//! * [`InterfaceAnnouncer`] periodically announces discoverable interfaces
//!   on the fixed SINGLE destination `rnstransport.discovery.interface`,
//!   with an LXMF work-function stamp over the packed interface
//!   description (Python `InterfaceAnnouncer`)
//! * [`InterfaceDiscovery`] listens for those announces, validates the
//!   stamps (required value), tracks discovered interfaces with
//!   staleness statuses, and can auto-connect to discovered TCP
//!   interfaces (Python `InterfaceDiscovery` + `connect_discovered`)
//! * [`BlackholeUpdater`] pulls blackhole lists from configured sources
//!   over links to their `rnstransport.info.blackhole` `/list` handlers
//!   (Python `Discovery.BlackholeUpdater`)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use tokio::sync::{Mutex, RwLock};

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::{AddressHash, Hash};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;

/// LXMF stamp expand rounds used by interface discovery
/// (Python `InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS`).
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 20;

/// Default required stamp value for accepting discovery announces
/// (Python `InterfaceAnnouncer.DEFAULT_STAMP_VALUE`).
pub const DEFAULT_STAMP_VALUE: u32 = 16;

/// Default announcer job interval in seconds
/// (Python `InterfaceAnnouncer.JOB_INTERVAL`).
pub const ANNOUNCER_INTERVAL: Duration = Duration::from_secs(60);

/// Default discovery announce interval per interface
/// (Python `Interface.discovery_announce_interval`).
pub const DISCOVERY_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60 * 30);

/// Interface types eligible for discovery
/// (Python `InterfaceAnnouncer.DISCOVERABLE_INTERFACE_TYPES`).
pub const DISCOVERABLE_TYPES: [&str; 7] = [
    "BackboneInterface",
    "TCPServerInterface",
    "TCPClientInterface",
    "RNodeInterface",
    "WeaveInterface",
    "I2PInterface",
    "KISSInterface",
];

/// Flag bit: encrypted payload (Python `FLAG_ENCRYPTED`).
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// The fixed discovery destination name
/// (Python `Destination(..., APP_NAME, "discovery", "interface")`).
pub fn discovery_destination_name() -> DestinationName {
    DestinationName::new("rnstransport", "discovery.interface")
}

/// One announced, discoverable interface (Python discovery `info` map).
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface type (`DISCOVERABLE_TYPES`).
    pub interface_type: String,
    /// Whether the announcing node has transport enabled.
    pub transport: bool,
    /// Truncated hash of the announcing transport instance.
    pub transport_id: AddressHash,
    /// Human-readable name of the interface.
    pub name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    /// Reachable host for connectable types (IP or hostname).
    pub reachable_on: Option<String>,
    /// Reachable port for connectable types.
    pub port: Option<u16>,
    /// Optional radio parameters (RNode/KISS/Weave).
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreadingfactor: Option<u8>,
    pub codingrate: Option<String>,
    pub channel: Option<u64>,
    pub modulation: Option<String>,
    /// IFAC credentials published alongside the interface.
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
}

impl InterfaceInfo {
    /// Pack the description as msgpack
    /// (Python `info` dict with short string keys).
    pub fn pack(&self) -> Vec<u8> {
        use rmp::encode as mp;

        let mut field_count = 7;
        if self.reachable_on.is_some() { field_count += 1; }
        if self.port.is_some() { field_count += 1; }
        if self.frequency.is_some() { field_count += 1; }
        if self.bandwidth.is_some() { field_count += 1; }
        if self.spreadingfactor.is_some() { field_count += 1; }
        if self.codingrate.is_some() { field_count += 1; }
        if self.channel.is_some() { field_count += 1; }
        if self.modulation.is_some() { field_count += 1; }
        if self.ifac_netname.is_some() { field_count += 1; }
        if self.ifac_netkey.is_some() { field_count += 1; }

        let mut out = Vec::new();
        mp::write_map_len(&mut out, field_count as u32).ok();

        mp::write_str(&mut out, "type").ok();
        mp::write_str(&mut out, &self.interface_type).ok();

        mp::write_str(&mut out, "transport").ok();
        mp::write_bool(&mut out, self.transport).ok();

        mp::write_str(&mut out, "transport_id").ok();
        mp::write_bin(&mut out, self.transport_id.as_slice()).ok();

        mp::write_str(&mut out, "name").ok();
        match &self.name {
            Some(name) => mp::write_str(&mut out, name).ok(),
            None => mp::write_nil(&mut out).ok(),
        };

        for (key, value) in [
            ("latitude", self.latitude),
            ("longitude", self.longitude),
            ("height", self.height),
        ] {
            mp::write_str(&mut out, key).ok();
            match value {
                Some(value) => {
                    mp::write_f64(&mut out, value).ok();
                }
                None => {
                    mp::write_nil(&mut out).ok();
                }
            }
        }

        if let Some(host) = &self.reachable_on {
            mp::write_str(&mut out, "reachable_on").ok();
            mp::write_str(&mut out, host).ok();
        }
        if let Some(port) = self.port {
            mp::write_str(&mut out, "port").ok();
            mp::write_u64(&mut out, port as u64).ok();
        }
        if let Some(frequency) = self.frequency {
            mp::write_str(&mut out, "frequency").ok();
            mp::write_u64(&mut out, frequency).ok();
        }
        if let Some(bandwidth) = self.bandwidth {
            mp::write_str(&mut out, "bandwidth").ok();
            mp::write_u64(&mut out, bandwidth).ok();
        }
        if let Some(sf) = self.spreadingfactor {
            mp::write_str(&mut out, "spreadingfactor").ok();
            mp::write_u8(&mut out, sf).ok();
        }
        if let Some(cr) = &self.codingrate {
            mp::write_str(&mut out, "codingrate").ok();
            mp::write_str(&mut out, cr).ok();
        }
        if let Some(channel) = self.channel {
            mp::write_str(&mut out, "channel").ok();
            mp::write_u64(&mut out, channel).ok();
        }
        if let Some(modulation) = &self.modulation {
            mp::write_str(&mut out, "modulation").ok();
            mp::write_str(&mut out, modulation).ok();
        }
        if let Some(netname) = &self.ifac_netname {
            mp::write_str(&mut out, "ifac_netname").ok();
            mp::write_str(&mut out, netname).ok();
        }
        if let Some(netkey) = &self.ifac_netkey {
            mp::write_str(&mut out, "ifac_netkey").ok();
            mp::write_str(&mut out, netkey).ok();
        }

        out
    }

    /// Unpack a description (Python `InterfaceAnnounceHandler` field
    /// validation).
    pub fn unpack(packed: &[u8]) -> Option<Self> {
        let mut cursor = std::io::Cursor::new(packed);
        let value = rmpv::decode::read_value(&mut cursor).ok()?;
        let rmpv::Value::Map(entries) = value else {
            return None;
        };

        let mut fields: HashMap<String, rmpv::Value> = HashMap::new();
        for (key, value) in entries {
            let key = key.as_str()?.to_string();
            fields.insert(key, value);
        }

        let interface_type = fields.get("type")?.as_str()?.to_string();
        if !DISCOVERABLE_TYPES.contains(&interface_type.as_str()) {
            return None;
        }

        let transport = match fields.get("transport")? {
            rmpv::Value::Boolean(value) => *value,
            _ => return None,
        };

        let transport_id_bytes = match fields.get("transport_id")? {
            rmpv::Value::Binary(bytes) => bytes,
            _ => return None,
        };
        let transport_id = AddressHash::new_from_slice(transport_id_bytes);

        let str_field = |key: &str| -> Option<String> {
            fields.get(key).and_then(|v| v.as_str()).map(str::to_string)
        };
        let float_field = |key: &str| -> Option<f64> {
            match fields.get(key) {
                Some(rmpv::Value::F64(value)) => Some(*value),
                _ => None,
            }
        };
        let u64_field = |key: &str| -> Option<u64> {
            fields.get(key).and_then(|v| v.as_u64())
        };

        Some(Self {
            interface_type,
            transport,
            transport_id,
            name: str_field("name"),
            latitude: float_field("latitude"),
            longitude: float_field("longitude"),
            height: float_field("height"),
            reachable_on: str_field("reachable_on"),
            port: u64_field("port").map(|p| p as u16),
            frequency: u64_field("frequency"),
            bandwidth: u64_field("bandwidth"),
            spreadingfactor: u64_field("spreadingfactor").map(|v| v as u8),
            codingrate: str_field("codingrate"),
            channel: u64_field("channel"),
            modulation: str_field("modulation"),
            ifac_netname: str_field("ifac_netname"),
            ifac_netkey: str_field("ifac_netkey"),
        })
    }

    /// Hash identifying this interface description
    /// (Python `infohash = full_hash(packed)`).
    pub fn info_hash(&self) -> Hash {
        Hash::new_from_slice(&self.pack())
    }
}

/// Build the discovery announce payload for one interface:
/// `flags || packed_info || stamp` (Python
/// `InterfaceAnnouncer.get_interface_announce_data` without location
/// scripts and network-identity encryption).
pub fn build_discovery_payload(info: &InterfaceInfo, stamp_value: u32) -> Option<Vec<u8>> {
    let packed = info.pack();
    let info_hash = Hash::new_from_slice(&packed);

    let workblock =
        lxmf::stamper::stamp_workblock_with_rounds(info_hash.as_slice(), WORKBLOCK_EXPAND_ROUNDS);
    let mut rng = OsRng;
    let (stamp, value) =
        lxmf::stamper::generate_stamp_against_workblock(&workblock, stamp_value, &mut rng);
    let stamp = stamp?;

    let mut payload = vec![0u8]; // flags: no encryption
    payload.extend_from_slice(&packed);
    payload.extend_from_slice(&stamp);

    let _ = value;
    Some(payload)
}

/// Validate a received discovery announce payload and extract the
/// interface description (Python `InterfaceAnnounceHandler
/// .received_announce`).
pub fn validate_discovery_payload(
    payload: &[u8],
    required_value: u32,
) -> Option<(InterfaceInfo, u64)> {
    if payload.len() <= lxmf::stamper::STAMP_SIZE + 1 {
        return None;
    }

    let _flags = payload[0];
    let body = &payload[1..];

    let stamp = &body[body.len() - lxmf::stamper::STAMP_SIZE..];
    let packed = &body[..body.len() - lxmf::stamper::STAMP_SIZE];

    let info_hash = Hash::new_from_slice(packed);
    let workblock =
        lxmf::stamper::stamp_workblock_with_rounds(info_hash.as_slice(), WORKBLOCK_EXPAND_ROUNDS);
    let value = lxmf::stamper::stamp_value(&workblock, stamp);
    if !lxmf::stamper::stamp_valid(stamp, required_value, &workblock) {
        return None;
    }

    Some((InterfaceInfo::unpack(packed)?, value))
}

/// Status of a discovered interface
/// (Python `THRESHOLD_*` based statuses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveredStatus {
    Available,
    Unknown,
    Stale,
}

impl DiscoveredStatus {
    fn from_age(age: Duration) -> Self {
        // Python: THRESHOLD_REMOVE 2h, THRESHOLD_STALE 30m, THRESHOLD_UNKNOWN 5m
        if age > Duration::from_secs(30 * 60) {
            Self::Stale
        } else if age > Duration::from_secs(5 * 60) {
            Self::Unknown
        } else {
            Self::Available
        }
    }
}

/// A tracked discovered interface (Python persisted `info` record).
#[derive(Debug, Clone)]
pub struct DiscoveredInterface {
    pub info: InterfaceInfo,
    /// Hash of the announcing network identity.
    pub network_id: Hash,
    /// Stamp value of the accepted announce.
    pub value: u64,
    pub hops: u8,
    pub discovered: tokio::time::Instant,
    pub last_heard: tokio::time::Instant,
    pub heard_count: usize,
}

impl DiscoveredInterface {
    pub fn status(&self) -> DiscoveredStatus {
        DiscoveredStatus::from_age(self.last_heard.elapsed())
    }

    /// Stable endpoint hash for duplicate detection
    /// (Python `endpoint_hash`).
    pub fn endpoint_hash(&self) -> Hash {
        let mut material = self.info.pack();
        material.extend_from_slice(self.network_id.as_slice());
        Hash::new_from_slice(&material)
    }
}

/// The interface announcer: periodically announces one due discoverable
/// interface on the shared discovery destination
/// (Python `InterfaceAnnouncer`).
pub struct InterfaceAnnouncer {
    transport: Arc<Transport>,
    destination: Arc<Mutex<SingleInputDestination>>,
    interfaces: RwLock<Vec<AnnouncedInterface>>,
    stamp_value: u32,
    interval: Duration,
}

/// Registration of one local discoverable interface.
#[derive(Debug, Clone)]
pub struct AnnouncedInterface {
    pub info: InterfaceInfo,
    pub announce_interval: Duration,
    pub last_announced: Option<tokio::time::Instant>,
}

impl InterfaceAnnouncer {
    /// Create the discovery destination on the transport and start the
    /// announcer job.
    pub async fn start(
        transport: &Arc<Transport>,
        identity: &PrivateIdentity,
        stamp_value: u32,
        interval: Duration,
    ) -> Arc<Self> {
        let destination = transport
            .add_destination(identity.clone(), discovery_destination_name())
            .await;

        let announcer = Arc::new(Self {
            transport: transport.clone(),
            destination,
            interfaces: RwLock::new(Vec::new()),
            stamp_value,
            interval,
        });

        let runner = announcer.clone();
        tokio::spawn(async move { runner.job().await });

        announcer
    }

    /// Register a local interface for discovery announces.
    pub async fn announce_interface(&self, info: InterfaceInfo) {
        self.interfaces.write().await.push(AnnouncedInterface {
            info,
            announce_interval: DISCOVERY_ANNOUNCE_INTERVAL,
            last_announced: None,
        });
    }

    async fn job(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.interval).await;

            let due = {
                let mut interfaces = self.interfaces.write().await;
                let now = tokio::time::Instant::now();
                let mut selected: Option<usize> = None;

                for (index, entry) in interfaces.iter().enumerate() {
                    let due = match entry.last_announced {
                        Some(at) => now - at > entry.announce_interval,
                        None => true,
                    };
                    if due {
                        // announce the most overdue interface
                        let candidate_last = entry.last_announced;
                        let better = match selected {
                            None => true,
                            Some(current) => {
                                let other = interfaces[current].last_announced;
                                candidate_last < other
                            }
                        };
                        if better {
                            selected = Some(index);
                        }
                    }
                }

                selected.map(|index| {
                    interfaces[index].last_announced = Some(now);
                    interfaces[index].info.clone()
                })
            };

            let Some(info) = due else { continue };

            match build_discovery_payload(&info, self.stamp_value) {
                Some(payload) => {
                    log::debug!(
                        "discovery: announcing interface {} ({} bytes)",
                        info.name.as_deref().unwrap_or(&info.interface_type),
                        payload.len()
                    );
                    self.transport
                        .send_announce(&self.destination, Some(&payload))
                        .await;
                }
                None => log::error!("discovery: could not generate announce payload"),
            }
        }
    }
}

/// The interface discovery listener: validates announces, tracks the
/// discovered table and optionally auto-connects to TCP interfaces
/// (Python `InterfaceDiscovery`).
pub struct InterfaceDiscovery {
    transport: Arc<Transport>,
    required_value: u32,
    discovered: RwLock<Vec<DiscoveredInterface>>,
    autoconnect: RwLock<bool>,
    max_autoconnected: RwLock<usize>,
}

impl InterfaceDiscovery {
    /// Start listening for discovery announces on the transport.
    pub async fn start(
        transport: &Arc<Transport>,
        required_value: u32,
        autoconnect: bool,
    ) -> Arc<Self> {
        let discovery = Arc::new(Self {
            transport: transport.clone(),
            required_value,
            discovered: RwLock::new(Vec::new()),
            autoconnect: RwLock::new(autoconnect),
            max_autoconnected: RwLock::new(8),
        });

        let runner = discovery.clone();
        tokio::spawn(async move { runner.listen().await });

        discovery
    }

    async fn listen(self: Arc<Self>) {
        let mut announces = self.transport.subscribe_announces(&["discovery"]).await;

        loop {
            let Ok(event) = announces.recv().await else { return };

            let payload = event.app_data.as_slice();
            if payload.is_empty() {
                continue;
            }

            let network_id = {
                let destination = event.destination.lock().await;
                Hash::new_from_slice(destination.desc.identity.to_bytes().as_slice())
            };

            let hops = self
                .transport
                .hops_to(&event.destination.lock().await.desc.address_hash)
                .await
                .unwrap_or(u8::MAX);

            let Some((info, value)) = validate_discovery_payload(payload, self.required_value)
            else {
                log::debug!("discovery: ignoring announce with insufficient stamp value");
                continue;
            };

            let mut table = self.discovered.write().await;
            match table
                .iter_mut()
                .find(|entry| entry.info.info_hash() == info.info_hash())
            {
                Some(entry) => {
                    entry.last_heard = tokio::time::Instant::now();
                    entry.heard_count += 1;
                    entry.value = value;
                }
                None => {
                    log::debug!(
                        "discovery: discovered {} (stamp value {value})",
                        info.name.as_deref().unwrap_or(&info.interface_type)
                    );
                    table.push(DiscoveredInterface {
                        info,
                        network_id,
                        value,
                        hops,
                        discovered: tokio::time::Instant::now(),
                        last_heard: tokio::time::Instant::now(),
                        heard_count: 0,
                    });
                }
            }
        }
    }

    /// Snapshot of the discovered interfaces (Python
    /// `list_discovered_interfaces`), expired entries removed.
    pub async fn list(&self) -> Vec<DiscoveredInterface> {
        let mut table = self.discovered.write().await;
        let before = table.len();
        table.retain(|entry| entry.last_heard.elapsed() < Duration::from_secs(2 * 60 * 60));
        let removed = before - table.len();
        if removed > 0 {
            log::debug!("discovery: removed {removed} stale discovered interfaces");
        }
        table.sort_by(|a, b| {
            (a.value, a.last_heard).partial_cmp(&(b.value, b.last_heard)).unwrap_or(std::cmp::Ordering::Equal)
        });
        table.clone()
    }

    /// Connect to all available discovered TCP interfaces
    /// (Python `connect_discovered` + `autoconnect`; Python only
    /// auto-connects Backbone interfaces, here TCP servers and
    /// backbones both connect).
    pub async fn connect_discovered(&self) -> usize {
        if !*self.autoconnect.read().await {
            return 0;
        }

        let table = self.list().await;
        let mut connected = 0;

        for entry in table {
            if entry.status() != DiscoveredStatus::Available {
                continue;
            }
            if !matches!(
                entry.info.interface_type.as_str(),
                "TCPServerInterface" | "BackboneInterface"
            ) {
                continue;
            }
            let (Some(host), Some(port)) = (entry.info.reachable_on.clone(), entry.info.port)
            else {
                continue;
            };

            // Skip interfaces we are already connected to.
            let _endpoint = entry.endpoint_hash();
            let exists = {
                let manager = self.transport.iface_manager();
                let manager = manager.lock().await;
                manager
                    .stats()
                    .iter()
                    .any(|stat| stat.kind == "TcpClient" && stat.name.contains(&format!("{host}:{port}")))
            };
            if exists {
                continue;
            }

            let manager = self.transport.iface_manager();
            let mut manager = manager.lock().await;
            let address = format!("{host}:{port}");
            let ifac_address = manager.spawn(
                TcpClient::new(address.clone()),
                TcpClient::spawn,
            );
            manager.set_iface_name(&ifac_address, &format!("discovered {address}"));

            if let (Some(netname), Some(netkey)) =
                (entry.info.ifac_netname.clone(), entry.info.ifac_netkey.clone())
            {
                manager.set_iface_ifac(&ifac_address, Some(&netname), Some(&netkey), 8);
            }

            log::info!("discovery: auto-connected to {address}");
            connected += 1;

            if connected >= *self.max_autoconnected.read().await {
                break;
            }
        }

        connected
    }

    /// The discovered-interface table length.
    pub async fn discovered_count(&self) -> usize {
        self.discovered.read().await.len()
    }
}

/// Blackhole list updater: links to the
/// `rnstransport.info.blackhole` destinations of configured source
/// identities, requests `/list` and merges the reported identities into
/// the local blackhole table (Python `Discovery.BlackholeUpdater`).
pub struct BlackholeUpdater {
    transport: Arc<Transport>,
    sources: RwLock<Vec<Hash>>,
    interval: Duration,
    /// Announced blackhole destinations by announcing network identity.
    announced: RwLock<HashMap<Hash, reticulum::destination::DestinationDesc>>,
}

impl BlackholeUpdater {
    pub async fn start(
        transport: &Arc<Transport>,
        sources: Vec<Hash>,
        interval: Duration,
    ) -> Arc<Self> {
        let updater = Arc::new(Self {
            transport: transport.clone(),
            sources: RwLock::new(sources),
            interval,
            announced: RwLock::new(HashMap::new()),
        });

        let tracker = updater.clone();
        tokio::spawn(async move { tracker.track_announces().await });

        let runner = updater.clone();
        tokio::spawn(async move { runner.job().await });

        updater
    }

    async fn job(self: Arc<Self>) {
        // Python waits INITIAL_WAIT before the first round.
        tokio::time::sleep(Duration::from_secs(5)).await;

        loop {
            let sources = self.sources.read().await.clone();
            for source in sources {
                let material = source.as_slice();
                let _ = material;

                // Look up the announced blackhole destination of the
                // source from the announce stream.
                if let Some(desc) = self.blackhole_destination_of(&source).await {
                    if let Err(error) = self.update_from(desc).await {
                        log::debug!("blackhole updater: {error:?}");
                    }
                } else {
                    log::debug!("blackhole updater: no known path for source {source}");
                }
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Find the announced `rnstransport.info.blackhole` destination of a
    /// source identity from the tracked announce stream.
    async fn blackhole_destination_of(
        &self,
        source: &Hash,
    ) -> Option<reticulum::destination::DestinationDesc> {
        let destinations = self.announced.read().await;
        destinations.get(source).cloned()
    }

    /// Track announces of `rnstransport.info.blackhole` destinations by
    /// announcing identity.
    async fn track_announces(self: Arc<Self>) {
        let mut announces = self.transport.recv_announces().await;

        loop {
            let Ok(event) = announces.recv().await else { return };

            let desc = {
                let destination = event.destination.lock().await;
                let name = destination.desc.name;
                let identity = destination.desc.identity;
                let address_hash = destination.desc.address_hash;

                let wanted = reticulum::destination::DestinationName::new(
                    "rnstransport",
                    "info.blackhole",
                );
                if name.hash.as_slice() != wanted.hash.as_slice() {
                    continue;
                }

                reticulum::destination::DestinationDesc {
                    identity,
                    address_hash,
                    name,
                }
            };

            let network_id = Hash::new_from_slice(desc.identity.to_bytes().as_slice());
            self.announced.write().await.insert(network_id, desc);
            log::debug!("blackhole updater: tracking published blackhole list {desc}");
        }
    }

    async fn update_from(
        &self,
        desc: reticulum::destination::DestinationDesc,
    ) -> Result<(), reticulum::error::RnsError> {
        let link = self.transport.link(desc).await;

        // Wait for activation.
        let mut events = self.transport.out_link_events();
        let activated = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;
        match activated {
            Ok(Ok(_)) => {}
            _ => {
                let _ = self.transport.link_close(*link.lock().await.id()).await;
                return Err(reticulum::error::RnsError::LinkNotReady);
            }
        }

        let rid = self
            .transport
            .request(&link, "/list", &[])
            .await?;
        let response = self
            .transport
            .await_request_response(rid, Duration::from_secs(10))
            .await;

        let _ = self.transport.link_close(*link.lock().await.id()).await;

        let Some(response) = response else {
            return Err(reticulum::error::RnsError::LinkNotReady);
        };

        // Merge every reported identity into the blackhole table.
        let mut cursor = std::io::Cursor::new(&response);
        let Ok(rmpv::Value::Array(items)) = rmpv::decode::read_value(&mut cursor) else {
            return Ok(());
        };

        let own = self.transport.identity_hash().await;
        let blackholes = self.transport.blackholes();
        let mut added = 0;
        for item in items {
            if let rmpv::Value::Binary(bytes) = item {
                let identity = AddressHash::new_from_slice(&bytes);
                let mut blackholes = blackholes.write().await;
                if !blackholes.is_blackholed(&identity) {
                    blackholes.blackhole(identity, own);
                    added += 1;
                }
            }
        }

        if added > 0 {
            log::debug!("blackhole updater: merged {added} blackholed identities");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_pack_unpack_roundtrip() {
        let info = InterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            transport: true,
            transport_id: AddressHash::new_from_slice(&[7u8; 16]),
            name: Some("node".to_string()),
            latitude: Some(55.5),
            longitude: Some(12.5),
            height: None,
            reachable_on: Some("127.0.0.1".to_string()),
            port: Some(4434),
            frequency: Some(868_000_000),
            bandwidth: Some(125_000),
            spreadingfactor: Some(9),
            codingrate: Some("5/6".to_string()),
            channel: None,
            modulation: Some("lora".to_string()),
            ifac_netname: None,
            ifac_netkey: None,
        };

        let packed = info.pack();
        let unpacked = InterfaceInfo::unpack(&packed).expect("unpack");
        assert_eq!(unpacked.interface_type, info.interface_type);
        assert_eq!(unpacked.port, Some(4434));
        assert_eq!(unpacked.reachable_on.as_deref(), Some("127.0.0.1"));
        assert_eq!(unpacked.name.as_deref(), Some("node"));
        assert_eq!(unpacked.frequency, Some(868_000_000));
    }
}
