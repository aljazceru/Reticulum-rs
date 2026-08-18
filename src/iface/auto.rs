//! AutoInterface, a port of `RNS/Interfaces/AutoInterface.py` (v1.4.2):
//! IPv6 link-local multicast peer discovery and direct UDP unicast data.
//!
//! * Discovery group address derived from `group_id` (default
//!   `"reticulum"`): `sha256(group_id)` split into 7 groups,
//!   `"ff" + <temporary|permanent> + <scope> + ":0:" + "{:02x}"...` -
//!   see [`mcast_discovery_address`].
//! * Discovery port 29716 (`DEFAULT_DISCOVERY_PORT`); unicast discovery
//!   on `discovery_port + 1`; data on `DEFAULT_DATA_PORT` 42671.
//! * Peer beacons are `sha256(group_id || link_local_address_string)`
//!   sent to the multicast group every `ANNOUNCE_INTERVAL` (1.6s) plus
//!   reverse-unicast beacons every `reverse_peering_interval` (~5.2s);
//!   received beacons are authenticated by recomputing the token over the
//!   *source address string* (`discovery_handler`).
//! * Data path is direct UDP unicast to the peer's link-local address on
//!   the data port (`AutoInterfacePeer`), with the Python `mif_deque`
//!   duplicate suppression for peers reachable over several interfaces.
//!
//! Currently Linux-only (interface enumeration via `/proc/net/if_inet6`,
//! IPv6 multicast, abstract-socket-free); the pure logic (address
//! derivation, beacon tokens) is platform-independent and unit-tested.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::hash::Hash;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;
use super::InterfaceManager;

/// `AutoInterface.DEFAULT_DISCOVERY_PORT`
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;
/// `AutoInterface.DEFAULT_DATA_PORT`
pub const DEFAULT_DATA_PORT: u16 = 42671;
/// `AutoInterface.DEFAULT_GROUP_ID`
pub const DEFAULT_GROUP_ID: &str = "reticulum";

/// `AutoInterface.HW_MTU`
pub const HW_MTU: usize = 1196;

/// `AutoInterface.PEERING_TIMEOUT`
pub const PEERING_TIMEOUT: Duration = Duration::from_secs(22);
/// `AutoInterface.ANNOUNCE_INTERVAL`
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1600);
/// `AutoInterface.PEER_JOB_INTERVAL`
pub const PEER_JOB_INTERVAL: Duration = Duration::from_secs(4);
/// `AutoInterface.MCAST_ECHO_TIMEOUT`
pub const MCAST_ECHO_TIMEOUT: Duration = Duration::from_millis(6500);

/// `AutoInterface.MULTI_IF_DEQUE_LEN`
const MULTI_IF_DEQUE_LEN: usize = 48;
/// `AutoInterface.MULTI_IF_DEQUE_TTL`
const MULTI_IF_DEQUE_TTL: Duration = Duration::from_millis(750);

/// Interface names never adopted (`AutoInterface.ALL_IGNORE_IFS`)
const ALL_IGNORE_IFS: &[&str] = &["lo0"];

/// `discovery_scope` configuration (`AutoInterface.SCOPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoveryScope {
    #[default]
    Link,
    Admin,
    Site,
    Organisation,
    Global,
}

impl DiscoveryScope {
    fn id(self) -> char {
        match self {
            Self::Link => '2',
            Self::Admin => '4',
            Self::Site => '5',
            Self::Organisation => '8',
            Self::Global => 'e',
        }
    }

    /// Parse a configuration value like Python's constructor.
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "admin" => Self::Admin,
            "site" => Self::Site,
            "organisation" | "organization" => Self::Organisation,
            "global" => Self::Global,
            _ => Self::Link,
        }
    }
}

/// `multicast_address_type` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MulticastAddressType {
    #[default]
    Temporary,
    Permanent,
}

impl MulticastAddressType {
    fn id(self) -> char {
        match self {
            Self::Temporary => '1',
            Self::Permanent => '0',
        }
    }

    /// Parse a configuration value like Python's constructor.
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "permanent" => Self::Permanent,
            _ => Self::Temporary,
        }
    }
}

/// Derive the multicast discovery address for a `group_id` exactly like
/// `AutoInterface.__init__`:
///
/// ```text
/// g  = sha256(group_id)
/// gt = "0" + 7x ":" + "{:02x}".format(g[i+1] + (g[i] << 8)) for i in 0,2,..12
/// mcast_discovery_address = "ff" + type + scope + ":" + gt
/// ```
pub fn mcast_discovery_address(
    group_id: &str,
    scope: DiscoveryScope,
    address_type: MulticastAddressType,
) -> String {
    let group_hash = Hash::new_from_slice(group_id.as_bytes()).to_bytes();

    let mut address = String::from("ff");
    address.push(address_type.id());
    address.push(scope.id());
    address.push(':');

    address.push('0');
    // six groups from g[2..14] (Python g[3]+(g[2]<<8), g[5]+(g[4]<<8), ...)
    for i in (2..14).step_by(2) {
        let group = u16::from(group_hash[i + 1]) + (u16::from(group_hash[i]) << 8);
        address.push_str(&format!(":{group:02x}"));
    }

    address
}

/// The discovery/peering token for a link-local address:
/// `sha256(group_id || link_local_address_string)` (`peer_announce`).
pub fn discovery_token(group_id: &str, link_local_addr: &Ipv6Addr) -> [u8; 32] {
    let mut data = Vec::with_capacity(group_id.len() + 46);
    data.extend_from_slice(group_id.as_bytes());
    data.extend_from_slice(link_local_addr.to_string().as_bytes());

    Hash::new_from_slice(&data).to_bytes()
}

/// Verify a received discovery datagram against its source address
/// (`discovery_handler`): the first `HASHLENGTH/8` bytes must equal the
/// token computed over `group_id` and the source address string.
pub fn verify_discovery_token(group_id: &str, src: &Ipv6Addr, data: &[u8]) -> bool {
    if data.len() < 32 {
        return false;
    }

    discovery_token(group_id, src) == data[..32]
}

/// A kernel interface with an adopted IPv6 link-local address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLocalIface {
    pub name: String,
    pub ifindex: u32,
    pub link_local: Ipv6Addr,
}

/// Enumerate suitable interfaces with IPv6 link-local addresses, a port of
/// the `__init__` interface scan: parse `/proc/net/if_inet6`, keep the last
/// `fe80::` address of each interface (like Python overwriting
/// `adopted_interfaces[ifname]`), honour the `devices` allow-list and the
/// `ignored_devices` deny-list, and optionally restrict to one specific
/// link-local address (`adopt`, used by the tests on hosts with several
/// link-local addresses per interface).
pub fn suitable_interfaces(
    devices: &[String],
    ignored_devices: &[String],
    adopt: Option<Ipv6Addr>,
) -> Vec<LinkLocalIface> {
    let mut adopted: Vec<LinkLocalIface> = Vec::new();

    let proc = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(proc) => proc,
        Err(err) => {
            log::warn!("auto: couldn't read /proc/net/if_inet6: {err}");
            return Vec::new();
        }
    };

    for line in proc.lines() {
        // format: <address 32 hex> <ifindex> <prefixlen> <scope> <flags> <name>
        let mut fields = line.split_whitespace();
        let (Some(address), Some(ifindex), Some(_prefix), Some(scope), Some(_flags), Some(name)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };

        if !address.starts_with("fe80") || scope != "20" {
            continue;
        }

        if ALL_IGNORE_IFS.contains(&name) || ignored_devices.iter().any(|i| i == name) {
            continue;
        }

        if !devices.is_empty() && !devices.iter().any(|device| device == name) {
            continue;
        }

        let Ok(link_local) = parse_expanded_ipv6(address) else {
            continue;
        };

        if let Some(adopt) = adopt {
            if link_local != adopt {
                continue;
            }
        }

        // last address wins, like the Python loop
        if let Some(entry) = adopted.iter_mut().find(|entry| entry.name == name) {
            entry.link_local = link_local;
            entry.ifindex = ifindex.parse().unwrap_or(entry.ifindex);
        } else {
            adopted.push(LinkLocalIface {
                name: name.to_string(),
                ifindex: ifindex.parse().unwrap_or(0),
                link_local,
            });
        }
    }

    if adopt.is_some() && !adopted.is_empty() {
        adopted.truncate(1);
    }

    adopted
}

/// Parse the 32 hexadecimal characters of `/proc/net/if_inet6` into an
/// `Ipv6Addr` (yielding the same compressed string form Python gets from
/// `netinfo.ifaddresses`).
fn parse_expanded_ipv6(hex: &str) -> Result<Ipv6Addr, ()> {
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }

    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }

    Ok(Ipv6Addr::from(bytes))
}

/// Duplicate suppression for data arriving over several interfaces
/// (`mif_deque` / `mif_deque_times` in `AutoInterfacePeer.process_incoming`).
#[derive(Debug, Default)]
struct MultiIfDeque {
    entries: VecDeque<(Hash, tokio::time::Instant)>,
}

impl MultiIfDeque {
    /// Returns `true` when the data is new (and records it).
    fn check(&mut self, data: &[u8]) -> bool {
        let hash = Hash::new_from_slice(data);
        let now = tokio::time::Instant::now();

        let hit = self
            .entries
            .iter()
            .any(|(entry, time)| *entry == hash && now < *time + MULTI_IF_DEQUE_TTL);

        if hit {
            return false;
        }

        self.entries.push_back((hash, now));
        while self.entries.len() > MULTI_IF_DEQUE_LEN {
            self.entries.pop_front();
        }

        true
    }
}

/// AutoInterface configuration (Python constructor options).
#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    pub group_id: String,
    pub discovery_port: u16,
    pub data_port: u16,
    pub discovery_scope: DiscoveryScope,
    pub multicast_address_type: MulticastAddressType,
    /// Allow-list of interface names (`devices`); empty adopts every
    /// suitable interface.
    pub devices: Vec<String>,
    /// Deny-list of interface names (`ignored_devices`).
    pub ignored_devices: Vec<String>,
    /// Restrict to one specific link-local address (test hook for hosts
    /// with several `fe80::` addresses on one interface).
    pub adopt: Option<Ipv6Addr>,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            group_id: DEFAULT_GROUP_ID.to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            discovery_scope: DiscoveryScope::default(),
            multicast_address_type: MulticastAddressType::default(),
            devices: Vec::new(),
            ignored_devices: Vec::new(),
            adopt: None,
        }
    }
}

impl AutoInterfaceConfig {
    pub fn new(group_id: impl Into<String>) -> Self {
        Self {
            group_id: group_id.into(),
            ..Self::default()
        }
    }

    pub fn discovery_address(&self) -> String {
        mcast_discovery_address(
            &self.group_id,
            self.discovery_scope,
            self.multicast_address_type,
        )
    }

    pub fn unicast_discovery_port(&self) -> u16 {
        self.discovery_port + 1
    }
}

enum AutoEvent {
    Discovery {
        data: Vec<u8>,
        src: SocketAddrV6,
        ifname: String,
    },
    Data {
        data: Vec<u8>,
        src: SocketAddrV6,
    },
}

struct PeerEntry {
    ifname: String,
    last_heard: tokio::time::Instant,
    last_outbound: tokio::time::Instant,
    address: super::AddressHash,
    data_tx: mpsc::Sender<Vec<u8>>,
}

/// One peered remote AutoInterface (`AutoInterfacePeer`): sends datagrams
/// directly to the peer's link-local data port and receives its datagrams
/// through the parent data sockets.
pub struct AutoPeer {
    peer_addr: SocketAddrV6,
    socket: Arc<UdpSocket>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl AutoPeer {
    pub fn new(
        peer_addr: SocketAddrV6,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            peer_addr,
            socket,
            data_rx: Some(data_rx),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();

        let peer_addr = context.inner.lock().unwrap().peer_addr;
        let socket = context.inner.lock().unwrap().socket.clone();

        let (rx_channel, mut tx_channel) = context.channel.split();

        let mut data_rx = context
            .inner
            .lock()
            .unwrap()
            .data_rx
            .take()
            .expect("auto peer data channel already consumed");

        stats.set_online(true);

        loop {
            enum Event {
                Tx(Box<super::TxMessage>),
                Rx(Vec<u8>),
            }

            let event = tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = iface_stop.cancelled() => break,
                message = tx_channel.recv() => match message {
                    Some(message) => Event::Tx(Box::new(message)),
                    None => break,
                },
                datagram = data_rx.recv() => match datagram {
                    Some(datagram) => Event::Rx(datagram),
                    None => break,
                },
            };

            match event {
                Event::Tx(message) => {
                    let packet = message.packet;
                    let mut buffer = [0u8; 2048];
                    let mut output = OutputBuffer::new(&mut buffer[..]);
                    if packet.serialize(&mut output).is_ok() {
                        let ifac = channel_ifac.read().expect("ifac lock").clone();
                        let wire = crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
                        if socket.send_to(&wire, peer_addr).await.is_ok() {
                            stats.count_tx(wire.len());
                        }
                    }
                }
                Event::Rx(datagram) => {
                    let plain = {
                        let ifac = channel_ifac.read().expect("ifac lock").clone();
                        match crate::iface::ifac::decode(&datagram, ifac.as_deref()) {
                            Some(plain) => plain,
                            None => {
                                log::debug!(
                                    "auto_interface: dropping packet with invalid access code"
                                );
                                continue;
                            }
                        }
                    };
                    match Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
                        Ok(packet) => {
                            stats.count_rx(datagram.len());
                            let _ = rx_channel
                                .send(RxMessage {
                                    address: iface_address,
                                    packet,
                                })
                                .await;
                        }
                        Err(_) => log::debug!("auto: couldn't decode packet from {peer_addr}"),
                    }
                }
            }
        }

        stats.set_online(false);
        iface_stop.cancel();
    }
}

impl Interface for AutoPeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// The AutoInterface itself: discovery sockets, beacon job and peer
/// management. Spawned into the [`InterfaceManager`] for statistics; the
/// actual data interfaces are [`AutoPeer`]s spawned per discovered peer.
pub struct AutoInterface {
    config: AutoInterfaceConfig,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl AutoInterface {
    pub fn new(
        config: AutoInterfaceConfig,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            config,
            iface_manager,
        }
    }

    pub fn config(&self) -> &AutoInterfaceConfig {
        &self.config
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let cancel = context.cancel.clone();
        let stats = context.channel.stats.clone();

        let config = context.inner.lock().unwrap().config.clone();
        let iface_manager = context.inner.lock().unwrap().iface_manager.clone();

        // The parent AutoInterface's access code: all traffic is carried by
        // spawned AutoPeer interfaces, so each peer must inherit it or the
        // configured networkname/passphrase protection silently applies to
        // nothing (Python AutoPeer copies the parent's ifac_* attributes).
        let parent_ifac = *context.channel.ifac.read().expect("ifac lock");

        // The AutoInterface itself never carries data (Python
        // `process_outgoing` is a pass); drain manager tx messages, peers
        // are separate interfaces.
        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));
        let drain_task = tokio::spawn(async move {
            loop {
                let mut tx_channel = tx_channel.lock().await;
                match tx_channel.recv().await {
                    Some(_) => {}
                    None => break,
                }
            }
        });

        let ifaces = suitable_interfaces(&config.devices, &config.ignored_devices, config.adopt);

        if ifaces.is_empty() {
            log::warn!(
                "auto: could not autoconfigure, no suitable interfaces with IPv6 link-local addresses"
            );
            drain_task.abort();
            return;
        }

        let discovery_address: Ipv6Addr = config
            .discovery_address()
            .parse()
            .expect("valid multicast discovery address");

        let mut peers: HashMap<Ipv6Addr, PeerEntry> = HashMap::new();
        let mut mif_deque = MultiIfDeque::default();

        let (event_tx, mut event_rx) = mpsc::channel::<AutoEvent>(64);

        let mut own_addresses: Vec<Ipv6Addr> = Vec::new();
        let mut beacon_sockets: Vec<(String, u32, Arc<UdpSocket>)> = Vec::new();

        for iface in &ifaces {
            log::info!(
                "auto: selecting link-local address {} for interface {}",
                iface.link_local,
                iface.name
            );

            own_addresses.push(iface.link_local);

            let scope = SocketAddrV6::new(iface.link_local, 0, 0, iface.ifindex);

            // multicast discovery socket bound to the group address
            // (Python binds mcast_discovery_address%ifname:discovery_port)
            let mcast_bind = SocketAddrV6::new(
                discovery_address,
                config.discovery_port,
                0,
                if config.discovery_scope == DiscoveryScope::Link {
                    iface.ifindex
                } else {
                    0
                },
            );
            let mcast_socket =
                match udp6_bind(&mcast_bind, true, Some((discovery_address, iface.ifindex))) {
                    Ok(socket) => socket,
                    Err(err) => {
                        log::warn!(
                            "auto: couldn't bind multicast discovery socket on {}: {err}",
                            iface.name
                        );
                        continue;
                    }
                };

            spawn_rx_loop(
                cancel.clone(),
                mcast_socket,
                iface.name.clone(),
                AutoLoopKind::Discovery,
                event_tx.clone(),
            );

            // unicast discovery socket on discovery_port + 1
            let unicast_bind = SocketAddrV6::new(
                iface.link_local,
                config.unicast_discovery_port(),
                0,
                iface.ifindex,
            );
            match udp6_bind(&unicast_bind, false, None) {
                Ok(socket) => {
                    spawn_rx_loop(
                        cancel.clone(),
                        socket,
                        iface.name.clone(),
                        AutoLoopKind::Discovery,
                        event_tx.clone(),
                    );
                }
                Err(err) => {
                    log::warn!(
                        "auto: couldn't bind unicast discovery socket on {}: {err}",
                        iface.name
                    );
                }
            }

            // data socket on the data port
            let data_bind = SocketAddrV6::new(iface.link_local, config.data_port, 0, iface.ifindex);
            match udp6_bind(&data_bind, false, None) {
                Ok(socket) => {
                    spawn_rx_loop(
                        cancel.clone(),
                        socket,
                        iface.name.clone(),
                        AutoLoopKind::Data,
                        event_tx.clone(),
                    );
                }
                Err(err) => {
                    log::warn!("auto: couldn't bind data socket on {}: {err}", iface.name);
                }
            }

            // shared outbound socket for beacons and peer data
            let beacon_socket = match udp6_bind(&scope, false, None) {
                Ok(socket) => socket,
                Err(err) => {
                    log::warn!(
                        "auto: couldn't bind outbound socket on {}: {err}",
                        iface.name
                    );
                    continue;
                }
            };
            set_multicast_if(&beacon_socket, iface.ifindex);
            beacon_sockets.push((iface.name.clone(), iface.ifindex, beacon_socket));
        }

        if beacon_sockets.is_empty() {
            log::warn!("auto: could not configure any interface");
            drain_task.abort();
            return;
        }

        // discovery token per interface (our own link-local address)
        let tokens: HashMap<u32, [u8; 32]> = ifaces
            .iter()
            .map(|iface| {
                (
                    iface.ifindex,
                    discovery_token(&config.group_id, &iface.link_local),
                )
            })
            .collect();

        // peer beacons: send discovery token to the multicast group
        for (_, ifindex, socket) in &beacon_sockets {
            let cancel = cancel.clone();
            let Some(token) = tokens.get(ifindex) else {
                continue;
            };
            let token = *token;
            let socket = socket.clone();
            let destination =
                SocketAddrV6::new(discovery_address, config.discovery_port, 0, *ifindex);

            tokio::spawn(async move {
                loop {
                    let _ = socket.send_to(&token, destination).await;

                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(ANNOUNCE_INTERVAL) => {}
                    }
                }
            });
        }

        let reverse_peering_interval =
            Duration::from_secs_f64(ANNOUNCE_INTERVAL.as_secs_f64() * 3.25);

        stats.set_online(true);
        log::info!(
            "auto: discovering peers for {:.2} seconds...",
            ANNOUNCE_INTERVAL.as_secs_f64() * 1.2
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,

                event = event_rx.recv() => {
                    let Some(event) = event else { break };

                    match event {
                        AutoEvent::Discovery { data, src, ifname } => {
                            if verify_discovery_token(&config.group_id, src.ip(), &data) {
                                let src_addr = *src.ip();

                                if own_addresses.contains(&src_addr) {
                                    // multicast echo of our own beacon
                                    log::debug!("auto: multicast echo on {ifname}");
                                } else {
                                    Self::add_peer(
                                        &config,
                                        &iface_manager,
                                        &beacon_sockets,
                                        &mut peers,
                                        src_addr,
                                        &ifname,
                                    )
                                    .await;
                                }
                            } else {
                                log::debug!(
                                    "auto: received peering packet on {ifname} from {}, but authentication hash was incorrect",
                                    src.ip()
                                );
                            }
                        }
                        AutoEvent::Data { data, src } => {
                            let src_addr = *src.ip();

                            if let Some(peer) = peers.get_mut(&src_addr) {
                                if mif_deque.check(&data) {
                                    peer.last_heard = tokio::time::Instant::now();
                                    let _ = peer.data_tx.send(data).await;
                                }
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(PEER_JOB_INTERVAL) => {
                    let now = tokio::time::Instant::now();

                    // remove timed out peers
                    let timed_out: Vec<Ipv6Addr> = peers
                        .iter()
                        .filter(|(_, peer)| now > peer.last_heard + PEERING_TIMEOUT)
                        .map(|(addr, _)| *addr)
                        .collect();

                    for addr in timed_out {
                        if let Some(peer) = peers.remove(&addr) {
                            log::debug!("auto: removed peer {addr} on {}", peer.ifname);
                            iface_manager.lock().await.stop_iface(&peer.address);
                        }
                    }

                    // reverse peering packets (reverse_announce): our own
                    // discovery token, unicast to the peer
                    for (addr, peer) in peers.iter_mut() {
                        if now > peer.last_outbound + reverse_peering_interval {
                            peer.last_outbound = now;

                            if let Some((_, ifindex, socket)) = beacon_sockets
                                .iter()
                                .find(|(ifname, _, _)| *ifname == peer.ifname)
                            {
                                if let Some(token) = tokens.get(ifindex) {
                                    let destination = SocketAddrV6::new(
                                        *addr,
                                        config.unicast_discovery_port(),
                                        0,
                                        *ifindex,
                                    );
                                    let _ = socket.send_to(token, destination).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        stats.set_online(false);
        for (_, peer) in peers.drain() {
            iface_manager.lock().await.stop_iface(&peer.address);
        }

        drain_task.abort();
    }

    async fn add_peer(
        config: &AutoInterfaceConfig,
        iface_manager: &Arc<tokio::sync::Mutex<InterfaceManager>>,
        beacon_sockets: &[(String, u32, Arc<UdpSocket>)],
        peers: &mut HashMap<Ipv6Addr, PeerEntry>,
        addr: Ipv6Addr,
        ifname: &str,
        parent_ifac: &Option<Arc<crate::iface::ifac::IfacKey>>,
    ) {
        if let Some(peer) = peers.get_mut(&addr) {
            // refresh_peer
            peer.last_heard = tokio::time::Instant::now();
            return;
        }

        let Some((_, ifindex, socket)) = beacon_sockets.iter().find(|(name, _, _)| name == ifname)
        else {
            return;
        };

        let peer_addr = SocketAddrV6::new(addr, config.data_port, 0, *ifindex);

        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

        let peer = AutoPeer::new(peer_addr, socket.clone(), data_rx);

        let name = format!("AutoPeer[{ifname}/{addr}]");
        let mut manager = iface_manager.lock().await;
        let address = manager.spawn_named(name, peer, AutoPeer::spawn);
        if let Some(key) = parent_ifac.clone() {
            manager.with_iface_ifac(&address, |slot| {
                *slot.write().expect("ifac lock") = Some(key);
            });
        }
        drop(manager);

        let now = tokio::time::Instant::now();
        peers.insert(
            addr,
            PeerEntry {
                ifname: ifname.to_string(),
                last_heard: now,
                last_outbound: now,
                address,
                data_tx,
            },
        );

        log::debug!("auto: added peer {addr} on {ifname}");
    }
}

impl Interface for AutoInterface {
    fn mtu() -> usize {
        HW_MTU
    }
}

enum AutoLoopKind {
    Discovery,
    Data,
}

fn spawn_rx_loop(
    cancel: tokio_util::sync::CancellationToken,
    socket: Arc<UdpSocket>,
    ifname: String,
    kind: AutoLoopKind,
    event_tx: mpsc::Sender<AutoEvent>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; HW_MTU + 128];

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = socket.recv_from(&mut buffer) => match result {
                    Ok((size, SocketAddr::V6(src))) => {
                        let event = match kind {
                            AutoLoopKind::Discovery => AutoEvent::Discovery {
                                data: buffer[..size].to_vec(),
                                src,
                                ifname: ifname.clone(),
                            },
                            AutoLoopKind::Data => AutoEvent::Data {
                                data: buffer[..size].to_vec(),
                                src,
                            },
                        };

                        if event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::debug!("auto: socket error on {ifname}: {err}");
                        break;
                    }
                }
            }
        }
    });
}

/// Create a tokio UDP socket bound to `addr` (IPv6), optionally joining a
/// multicast group on `interface` first.
fn udp6_bind(
    addr: &SocketAddrV6,
    reuse_port: bool,
    join: Option<(Ipv6Addr, u32)>,
) -> Result<Arc<UdpSocket>, std::io::Error> {
    use socket2::{Domain, Protocol, SockAddr, Socket as RawSocket, Type};

    let socket = RawSocket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;

    socket.bind(&SockAddr::from(*addr))?;

    if let Some((group, ifindex)) = join {
        socket.join_multicast_v6(&group, ifindex)?;
    }

    let socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(socket)?;

    Ok(Arc::new(socket))
}

/// Set `IPV6_MULTICAST_IF` on a tokio socket (beacon transmissions).
fn set_multicast_if(socket: &UdpSocket, ifindex: u32) {
    use socket2::SockRef;

    if let Err(err) = SockRef::from(socket).set_multicast_if_v6(ifindex) {
        log::warn!("auto: couldn't set multicast interface {ifindex}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcast_address_matches_python_reference() {
        // Python AutoInterface with group "reticulum" (defaults):
        //   ff12:0:d70b:fb1c:16e4:5e39:485e:31e1
        assert_eq!(
            mcast_discovery_address(
                "reticulum",
                DiscoveryScope::Link,
                MulticastAddressType::Temporary
            ),
            "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1"
        );

        // group "rstest":
        //   ff12:0:5113:b862:4c6f:e1fa:8d3c:c5f6
        assert_eq!(
            mcast_discovery_address(
                "rstest",
                DiscoveryScope::Link,
                MulticastAddressType::Temporary
            ),
            "ff12:0:5113:b862:4c6f:e1fa:8d3c:c5f6"
        );

        // permanent/site scope: ff05:0:5113:b862:4c6f:e1fa:8d3c:c5f6
        assert_eq!(
            mcast_discovery_address(
                "rstest",
                DiscoveryScope::Site,
                MulticastAddressType::Permanent
            ),
            "ff05:0:5113:b862:4c6f:e1fa:8d3c:c5f6"
        );
    }

    #[test]
    fn discovery_token_matches_python_reference() {
        // Python: RNS.Identity.full_hash(b"reticulum"+b"fe80::1")
        let expected: [u8; 32] = [
            0x97, 0xb2, 0x55, 0x76, 0x74, 0x9e, 0xa9, 0x36, 0xb0, 0xd8, 0xa8, 0x53, 0x6f, 0xfa,
            0xf4, 0x42, 0xd1, 0x57, 0xcf, 0x47, 0xd4, 0x60, 0xdc, 0xf1, 0x3c, 0x48, 0xb7, 0xbd,
            0x18, 0xb6, 0xc1, 0x63,
        ];
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(discovery_token("reticulum", &addr), expected);

        // Python: RNS.Identity.full_hash(b"rstest"+b"fe80::2")
        let expected: [u8; 32] = [
            0x50, 0x3c, 0x85, 0x3b, 0xdf, 0x31, 0xda, 0xc7, 0xda, 0x54, 0xfa, 0x3f, 0xec, 0x30,
            0x88, 0x82, 0x1d, 0x63, 0xda, 0x08, 0x6e, 0x0b, 0x88, 0xa6, 0xba, 0xa5, 0x22, 0x78,
            0xcd, 0x79, 0x74, 0x0d,
        ];
        let addr: Ipv6Addr = "fe80::2".parse().unwrap();
        assert_eq!(discovery_token("rstest", &addr), expected);
    }

    #[test]
    fn verify_token_rejects_forged_beacons() {
        let addr: Ipv6Addr = "fe80::42".parse().unwrap();
        let token = discovery_token("reticulum", &addr);

        assert!(verify_discovery_token("reticulum", &addr, &token));
        // wrong source address
        let other: Ipv6Addr = "fe80::43".parse().unwrap();
        assert!(!verify_discovery_token("reticulum", &other, &token));
        // wrong group id
        assert!(!verify_discovery_token("other", &addr, &token));
        // short data
        assert!(!verify_discovery_token("reticulum", &addr, &token[..16]));
    }

    #[test]
    fn parse_expanded_ipv6_from_proc() {
        let addr = parse_expanded_ipv6("fe800000000000000000000000000001").unwrap();
        assert_eq!(addr.to_string(), "fe80::1");

        assert!(parse_expanded_ipv6("fe8000000000000000000000000000").is_err());
    }

    #[test]
    fn mif_deque_suppresses_duplicates() {
        let mut deque = MultiIfDeque::default();

        assert!(deque.check(b"packet"));
        assert!(!deque.check(b"packet"));
        assert!(deque.check(b"other"));
        assert!(!deque.check(b"other"));
    }
}
