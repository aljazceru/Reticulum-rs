use std::path::PathBuf;

use clap::Parser;
use reticulum::hash::AddressHash;
use reticulum::iface::local::LocalServer;
use reticulum::iface::local::SharedInstanceAddress;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;
use reticulum::storage::FsStorage;
use tokio::signal;

#[cfg(all(feature = "iface-auto", target_os = "linux"))]
use reticulum::iface::auto::AutoInterface;
#[cfg(all(feature = "iface-auto", target_os = "linux"))]
use reticulum::iface::auto::AutoInterfaceConfig;
#[cfg(all(feature = "iface-auto", target_os = "linux"))]
use reticulum::iface::auto::DiscoveryScope;
#[cfg(all(feature = "iface-auto", target_os = "linux"))]
use reticulum::iface::auto::MulticastAddressType;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::CsmaParams;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::KissInterface;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::SerialPortConfig;
#[cfg(feature = "iface-pipe")]
use reticulum::iface::pipe::PipeInterface;
#[cfg(feature = "iface-serial")]
use reticulum::iface::serial::SerialInterface;

use reticulum_daemon::config::{Config, InterfaceConfig};

/// File the daemon identity is persisted to (hex format, see
/// `reticulum_utils::common::save_private_identity`), relative to the config
/// directory. Python stores the transport identity under
/// `storage/identities` in raw-key format; we keep the daemon identity at
/// the config-dir root in hex so `rn id -i <configdir>/identity` can inspect
/// it.
const IDENTITY_FILE: &str = "identity";

fn parse_management_allowed(values: &[String]) -> Result<Vec<AddressHash>, String> {
    values
        .iter()
        .map(|value| {
            if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("invalid remote management identity hash: {value}"));
            }
            AddressHash::new_from_hex_string(value)
                .map_err(|_| format!("invalid remote management identity hash: {value}"))
        })
        .collect()
}

/// Resolve Python and native RNode endpoints consistently: an explicit TCP
/// setting wins; otherwise a port with a tcp:// prefix is a TCP target and
/// every other port value is a serial path.
#[cfg(feature = "iface-rnode")]
fn rnode_endpoint<'a>(
    tcp: &'a Option<String>,
    port: &'a Option<String>,
) -> (Option<&'a str>, Option<&'a str>) {
    if let Some(tcp) = tcp.as_deref() {
        return (Some(tcp), None);
    }
    match port.as_deref() {
        Some(port) if port.starts_with("tcp://") => (Some(&port[6..]), None),
        Some(port) => (None, Some(port)),
        None => (None, None),
    }
}

/// Reticulum-rs daemon
#[derive(Parser)]
#[clap(version)]
#[clap(args_conflicts_with_subcommands = true)]
pub struct Command {
    /// Reticulum config directory
    #[arg(short, long)]
    pub config_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub convert_config: Option<Subcommand>,
}

#[derive(clap::Subcommand)]
pub enum Subcommand {
    /// Convert a Python Reticulum config file to TOML
    ConvertConfig {
        /// Path to the Python Reticulum config file
        config_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = Command::parse();
    if let Some(subcommand) = cmd.convert_config {
        match subcommand {
            Subcommand::ConvertConfig { config_file } => {
                return reticulum_daemon::config::migrate_config(&config_file);
            }
        }
    }

    let (config, config_path) = Config::load(cmd.config_dir.as_deref())?;
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(format!("{:?}", config.logging.loglevel)),
    )
    .init();

    log::info!("Configuration loaded from: {}", config_path.display());
    log::info!("Reticulum daemon starting");

    // Load (or create + persist) the daemon identity so the instance — and
    // every destination derived from it — stays stable across restarts
    // (Phase 7.4). The daemon announces nothing by default.
    let identity_path = config_path.join(IDENTITY_FILE);
    let (identity, created) = reticulum_utils::common::load_or_create_private_identity(&identity_path)
        .map_err(|err| format!("could not load daemon identity: {err}"))?;
    log::info!(
        "{} daemon identity {} at {}",
        if created { "Generated" } else { "Loaded" },
        reticulum_utils::common::prettyhexrep(identity.address_hash().as_slice()),
        identity_path.display()
    );

    let instance_name = config
        .reticulum
        .instance_name
        .clone()
        .unwrap_or_else(|| "rns-daemon".to_string());
    log::info!("Instance name: {instance_name}");

    let transport = std::sync::Arc::new(
        TransportConfig::new(&instance_name, &identity, config.reticulum.enable_transport)
            .set_retransmit(config.reticulum.enable_transport)
            .set_storage(std::sync::Arc::new(FsStorage::new(
                config_path.join("storage").to_string_lossy().into_owned(),
            )))
            .build(),
    );
    transport
        .load_known_destinations()
        .await
        .map_err(|error| format!("could not load known destinations: {error:?}"))?;

    let iface_manager = transport.iface_manager();

    // Local shared instance (Python `Reticulum.__start_local_interface`):
    // TCP on 127.0.0.1:shared_instance_port (`shared_instance_type = tcp`)
    // or the abstract unix domain socket `\0rns/<instance_name>` on
    // platforms supporting them.
    if config.reticulum.share_instance {
        let instance_name = config
            .reticulum
            .instance_name
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let address = if config
            .reticulum
            .shared_instance_type
            .eq_ignore_ascii_case("tcp")
        {
            SharedInstanceAddress::tcp(config.reticulum.shared_instance_port)
        } else if cfg!(unix) {
            SharedInstanceAddress::unix_abstract(instance_name)
        } else {
            SharedInstanceAddress::tcp(config.reticulum.shared_instance_port)
        };

        log::info!("Starting shared instance interface: LocalServer on {address:?}");
        iface_manager.lock().await.spawn(
            LocalServer::new(address, iface_manager.clone()),
            LocalServer::spawn,
        );
    }

    for iface in &config.interfaces {
        let enabled = match &iface.config {
            InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
            InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
            InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
            InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
            InterfaceConfig::I2PInterface { enabled, .. } => *enabled,
            InterfaceConfig::BackboneInterface { enabled, .. } => *enabled,
            InterfaceConfig::BackboneClientInterface { enabled, .. } => *enabled,
            InterfaceConfig::RNodeInterface { enabled, .. } => *enabled,
            InterfaceConfig::RNodeMultiInterface { enabled, .. } => *enabled,
            InterfaceConfig::BLEInterface { enabled, .. } => *enabled,
            InterfaceConfig::KISSInterface { enabled, .. } => *enabled,
            InterfaceConfig::AX25KISSInterface { enabled, .. } => *enabled,
            InterfaceConfig::SerialInterface { enabled, .. } => *enabled,
            InterfaceConfig::PipeInterface { enabled, .. } => *enabled,
            InterfaceConfig::LocalInterface { enabled, .. } => *enabled,
            InterfaceConfig::Unsupported => false,
        };

        if !enabled {
            continue;
        }

        match &iface.config {
            InterfaceConfig::TCPServerInterface {
                bind_host,
                bind_port,
                ..
            } => {
                let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
                log::info!(
                    "Enabling interface '{}': TCP Server on {}",
                    iface.name,
                    addr
                );
                let address = iface_manager.lock().await.spawn(
                    TcpServer::new(addr, iface_manager.clone()),
                    TcpServer::spawn,
                );
                configure_iface(&iface_manager, &address, iface).await;
            }
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
                log::info!(
                    "Enabling interface '{}': TCP Client to {}",
                    iface.name,
                    addr
                );
                let address = iface_manager
                    .lock()
                    .await
                    .spawn(TcpClient::new(addr), TcpClient::spawn);
                configure_iface(&iface_manager, &address, iface).await;
            }
            InterfaceConfig::UDPInterface {
                listen_ip,
                listen_port,
                forward_ip,
                forward_port,
                ..
            } => {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!(
                    "Enabling interface '{}': UDP {}→{}",
                    iface.name,
                    bind_addr,
                    forward_addr
                );
                let address = iface_manager.lock().await.spawn(
                    UdpInterface::new(bind_addr, Some(forward_addr), false),
                    UdpInterface::spawn,
                );
                configure_iface(&iface_manager, &address, iface).await;
            }
            InterfaceConfig::AutoInterface {
                group_id,
                discovery_port,
                data_port,
                discovery_scope,
                multicast_address_type,
                devices,
                ignored_devices,
                ..
            } => {
                #[cfg(all(feature = "iface-auto", target_os = "linux"))]
                {
                    let mut auto_config = AutoInterfaceConfig {
                        group_id: group_id.clone(),
                        discovery_port: *discovery_port,
                        data_port: *data_port,
                        ..AutoInterfaceConfig::default()
                    };

                    if let Some(scope) = discovery_scope {
                        auto_config.discovery_scope = DiscoveryScope::parse(&scope);
                    }
                    if let Some(address_type) = multicast_address_type {
                        auto_config.multicast_address_type =
                            MulticastAddressType::parse(&address_type);
                    }
                    if let Some(devices) = devices {
                        auto_config.devices = devices
                            .split(',')
                            .map(str::trim)
                            .filter(|device| !device.is_empty())
                            .map(str::to_string)
                            .collect();
                    }
                    if let Some(ignored) = ignored_devices {
                        auto_config.ignored_devices = ignored
                            .split(',')
                            .map(str::trim)
                            .filter(|device| !device.is_empty())
                            .map(str::to_string)
                            .collect();
                    }

                    log::info!(
                        "Enabling interface '{}': AutoInterface group '{}' on discovery port {}",
                        iface.name,
                        auto_config.group_id,
                        auto_config.discovery_port
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        AutoInterface::new(auto_config, iface_manager.clone()),
                        AutoInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, iface).await;
                }

                #[cfg(not(all(feature = "iface-auto", target_os = "linux")))]
                {
                    let _ = (
                        group_id,
                        discovery_port,
                        data_port,
                        discovery_scope,
                        multicast_address_type,
                        devices,
                        ignored_devices,
                    );
                    log::warn!(
                        "Interface '{}' type 'AutoInterface' requires building the daemon with --features iface-auto (Linux only)",
                        iface.name
                    );
                }
            }
            InterfaceConfig::I2PInterface { peers, connectable, sam_address, .. } => {
                #[cfg(feature = "iface-i2p")]
                {
                    let sam_addr = sam_address
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1:7656".to_string());

                    if *connectable {
                        log::info!(
                            "Enabling interface '{}': I2P server (connectable) via SAM {}",
                            iface.name,
                            sam_addr
                        );
                        let session_id = format!("{}-{}", iface.name, std::process::id());
                        let address = iface_manager.lock().await.spawn_named(
                            &iface.name,
                            reticulum::iface::i2p::I2pServer::new(
                                sam_addr.clone(),
                                session_id,
                                iface_manager.clone(),
                            ),
                            reticulum::iface::i2p::I2pServer::spawn,
                        );
                        // Apply mode/bitrate/IFAC to the connectable server
                        // so spawned inbound peers inherit the protection.
                        configure_iface(&iface_manager, &address, iface).await;
                    }

                    for (index, peer) in peers.iter().enumerate() {
                        log::info!(
                            "Enabling interface '{}': I2P peer {index} via SAM {}",
                            iface.name,
                            sam_addr
                        );
                        let session_id = format!("{}-{}-{index}", iface.name, std::process::id());
                        let address = iface_manager.lock().await.spawn_named(
                            format!("{}-peer-{index}", iface.name),
                            reticulum::iface::i2p::I2pPeer::new_initiator(
                                &sam_addr,
                                &session_id,
                                peer,
                            )
                            .with_manager(iface_manager.clone()),
                            reticulum::iface::i2p::I2pPeer::spawn,
                        );
                        configure_iface(&iface_manager, &address, iface).await;
                    }

                    if !*connectable && peers.is_empty() {
                        log::warn!(
                            "Interface '{}' (I2P) has neither connectable = yes nor peers",
                            iface.name
                        );
                    }
                }

                #[cfg(not(feature = "iface-i2p"))]
                {
                    let _ = (peers, connectable, sam_address);
                    log::warn!(
                        "Interface '{}' type 'I2PInterface' requires building the daemon with --features iface-i2p",
                        iface.name
                    );
                }
            }
            InterfaceConfig::BackboneInterface {
                listen_ip, bind_port, block_fast_flapping, fast_flapping_threshold,
                fast_flapping_grace, fast_flapping_block_time, ..
            } => {
                let addr = format!("{}:{}", listen_ip.trim_end_matches(':'), bind_port);

                let table = reticulum::iface::backbone::FastFlapTable::new(
                    *block_fast_flapping,
                    fast_flapping_threshold
                        .map(|seconds| std::time::Duration::from_secs_f64(seconds.max(0.1)))
                        .unwrap_or(reticulum::iface::backbone::FAST_FLAP_THRESHOLD),
                    fast_flapping_grace
                        .unwrap_or(reticulum::iface::backbone::FAST_FLAP_GRACE),
                    fast_flapping_block_time
                        .map(|minutes| std::time::Duration::from_secs_f64(minutes.max(0.1) * 60.0))
                        .unwrap_or(reticulum::iface::backbone::FAST_FLAP_EXPIRY),
                );

                log::info!("Enabling interface '{}': Backbone server on {}", iface.name, addr);
                let address = iface_manager.lock().await.spawn_named(
                    &iface.name,
                    reticulum::iface::backbone::BackboneServer::new(
                        addr,
                        iface_manager.clone(),
                        std::sync::Arc::new(tokio::sync::Mutex::new(table)),
                    ),
                    reticulum::iface::backbone::BackboneServer::spawn,
                );
                configure_iface(&iface_manager, &address, iface).await;
            }
            InterfaceConfig::BackboneClientInterface { target_ip, target_port, .. } => {
                let addr = format!("{}:{}", target_ip.trim_end_matches(':'), target_port);
                log::info!("Enabling interface '{}': Backbone client to {}", iface.name, addr);
                let address = iface_manager.lock().await.spawn_named(
                    &iface.name,
                    reticulum::iface::backbone::BackboneClient::new(addr)
                        .with_manager(iface_manager.clone()),
                    reticulum::iface::backbone::BackboneClient::spawn,
                );
                configure_iface(&iface_manager, &address, iface).await;
            }
            InterfaceConfig::RNodeInterface { port, tcp, speed, frequency, bandwidth, txpower, spreadingfactor, codingrate, st_alock, lt_alock, flow_control, .. } => {
                #[cfg(feature = "iface-rnode")]
                {
                    let config = reticulum::iface::rnode::RnodeRadioConfig {
                        frequency: *frequency,
                        bandwidth: *bandwidth,
                        txpower: *txpower,
                        spreadingfactor: *spreadingfactor,
                        codingrate: *codingrate,
                        st_alock: *st_alock,
                        lt_alock: *lt_alock,
                    };

                    let (tcp, port) = rnode_endpoint(tcp, port);
                    let interface = if let Some(tcp) = tcp {
                        log::info!(
                            "Enabling interface '{}': RNode over TCP {tcp} at {frequency} Hz",
                            iface.name
                        );
                        Some(reticulum::iface::rnode::RnodeInterface::tcp(tcp, config))
                    } else if let Some(port) = port {
                        log::info!(
                            "Enabling interface '{}': RNode on {port} at {speed} baud, {frequency} Hz",
                            iface.name
                        );
                        #[cfg(feature = "iface-serial")]
                        {
                            Some(reticulum::iface::rnode::RnodeInterface::serial(port, *speed, config))
                        }
                        #[cfg(not(feature = "iface-serial"))]
                        {
                            log::warn!(
                                "Interface '{}' RNode serial mode requires building with --features iface-serial",
                                iface.name
                            );
                            None
                        }
                    } else {
                        log::error!("Interface '{}' (RNode) needs a port or tcp target", iface.name);
                        None
                    };

                    if let Some(interface) = interface {
                        let address = iface_manager.lock().await.spawn_named(
                            &iface.name,
                            interface
                                .with_flow_control(*flow_control)
                                .with_manager(iface_manager.clone()),
                            reticulum::iface::rnode::RnodeInterface::spawn,
                        );
                        configure_iface(&iface_manager, &address, iface).await;
                    }
                }

                #[cfg(not(feature = "iface-rnode"))]
                {
                    let _ = (port, tcp, speed, frequency, bandwidth, txpower, spreadingfactor, codingrate, st_alock, lt_alock, flow_control);
                    log::warn!(
                        "Interface '{}' type 'RNodeInterface' requires building the daemon with --features iface-rnode",
                        iface.name
                    );
                }
            }
            InterfaceConfig::RNodeMultiInterface { port, tcp, speed, subinterfaces, .. } => {
                #[cfg(feature = "iface-rnode")]
                {
                    use reticulum::iface::rnode::{RnodeMultiInterface, RnodeVport};

                    let vports: Vec<RnodeVport> = subinterfaces
                        .iter()
                        .map(|sub| RnodeVport {
                            index: sub.vport,
                            config: reticulum::iface::rnode::RnodeRadioConfig {
                                frequency: sub.frequency,
                                bandwidth: sub.bandwidth,
                                txpower: sub.txpower,
                                spreadingfactor: sub.spreadingfactor,
                                codingrate: sub.codingrate,
                                st_alock: sub.st_alock,
                                lt_alock: sub.lt_alock,
                            },
                        })
                        .collect();

                    let (tcp, port) = rnode_endpoint(tcp, port);
                    let interface = if let Some(tcp) = tcp {
                        log::info!(
                            "Enabling interface '{}': RNodeMulti over TCP {tcp} with {} virtual ports",
                            iface.name,
                            vports.len()
                        );
                        Some(RnodeMultiInterface::tcp(tcp, vports, iface_manager.clone()))
                    } else if let Some(port) = port {
                        log::info!(
                            "Enabling interface '{}': RNodeMulti on {port} at {speed} baud with {} virtual ports",
                            iface.name,
                            vports.len()
                        );
                        #[cfg(feature = "iface-serial")]
                        {
                            Some(RnodeMultiInterface::serial(port, *speed, vports, iface_manager.clone()))
                        }
                        #[cfg(not(feature = "iface-serial"))]
                        {
                            log::warn!(
                                "Interface '{}' RNodeMulti serial mode requires building with --features iface-serial",
                                iface.name
                            );
                            None
                        }
                    } else {
                        log::error!("Interface '{}' (RNodeMulti) needs a port or tcp target", iface.name);
                        None
                    };

                    if let Some(interface) = interface {
                        let address = iface_manager.lock().await.spawn_named(
                            &iface.name,
                            interface,
                            RnodeMultiInterface::spawn,
                        );
                        configure_iface(&iface_manager, &address, iface).await;
                    }
                }

                #[cfg(not(feature = "iface-rnode"))]
                {
                    let _ = (port, tcp, speed, subinterfaces);
                    log::warn!(
                        "Interface '{}' type 'RNodeMultiInterface' requires building the daemon with --features iface-rnode",
                        iface.name
                    );
                }
            }
            InterfaceConfig::BLEInterface { .. } => {
                log::warn!(
                    "Interface '{}' type 'BLEInterface' is not yet supported",
                    iface.name
                );
            }
            InterfaceConfig::KISSInterface {
                port,
                speed,
                databits,
                parity,
                stopbits,
                preamble,
                txtail,
                persistence,
                slottime,
                flow_control,
                ..
            } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                        *databits,
                        parity.clone(),
                        *stopbits,
                    );
                    let csma = CsmaParams::new(*preamble, *txtail, *persistence, *slottime);

                    log::info!(
                        "Enabling interface '{}': KISS on {port} at {speed} baud (csma preamble={preamble} txtail={txtail} persistence={persistence} slottime={slottime})",
                        iface.name
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        KissInterface::new(serial, csma, *flow_control),
                        KissInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, iface).await;
                }

                #[cfg(not(feature = "iface-serial"))]
                {
                    let _ = (
                        speed,
                        databits,
                        parity,
                        stopbits,
                        preamble,
                        txtail,
                        persistence,
                        slottime,
                        flow_control,
                    );
                    log::warn!(
                        "Interface '{}' type 'KISSInterface' on port {port} requires building the daemon with --features iface-serial",
                        iface.name
                    );
                }
            }
            InterfaceConfig::SerialInterface {
                port,
                speed,
                databits,
                parity,
                stopbits,
                ..
            } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                        *databits,
                        parity.clone(),
                        *stopbits,
                    );

                    log::info!(
                        "Enabling interface '{}': Serial (HDLC) on {port} at {speed} baud",
                        iface.name
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        SerialInterface::new(serial),
                        SerialInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, iface).await;
                }

                #[cfg(not(feature = "iface-serial"))]
                {
                    let _ = (speed, databits, parity, stopbits);
                    log::warn!(
                        "Interface '{}' type 'SerialInterface' on port {port} requires building the daemon with --features iface-serial",
                        iface.name
                    );
                }
            }
            InterfaceConfig::PipeInterface {
                command,
                respawn_delay,
                ..
            } => {
                #[cfg(feature = "iface-pipe")]
                {
                    let respawn_delay =
                        std::time::Duration::from_secs_f64(respawn_delay.max(0.0) as f64);

                    log::info!(
                        "Enabling interface '{}': Pipe command '{command}' (respawn delay {respawn_delay:?})",
                        iface.name
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        PipeInterface::new(command).with_respawn_delay(respawn_delay),
                        PipeInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, iface).await;
                }

                #[cfg(not(feature = "iface-pipe"))]
                {
                    let _ = respawn_delay;
                    log::warn!(
                        "Interface '{}' type 'PipeInterface' (command '{command}') requires building the daemon with --features iface-pipe",
                        iface.name
                    );
                }
            }
            InterfaceConfig::LocalInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                // A local shared-instance listener declared as an interface
                // (Python handles this via [reticulum] share_instance; the
                // daemon also accepts it explicitly here).
                if listen_ip == "127.0.0.1" {
                    log::info!(
                        "Enabling interface '{}': Local shared instance on 127.0.0.1:{listen_port}",
                        iface.name
                    );
                    iface_manager.lock().await.spawn_named(
                        &iface.name,
                        LocalServer::new(
                            SharedInstanceAddress::tcp(*listen_port),
                            iface_manager.clone(),
                        ),
                        LocalServer::spawn,
                    );
                } else {
                    log::warn!(
                        "Interface '{}' type 'LocalInterface': shared instances always listen on 127.0.0.1 (got {listen_ip})",
                        iface.name
                    );
                }
            }
            InterfaceConfig::AX25KISSInterface {
                callsign,
                ssid,
                port,
                speed,
                databits,
                parity,
                stopbits,
                preamble,
                txtail,
                persistence,
                slottime,
                flow_control,
                ..
            } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                        *databits,
                        parity.clone(),
                        *stopbits,
                    );
                    let csma = CsmaParams::new(*preamble, *txtail, *persistence, *slottime);

                    match KissInterface::new_ax25(
                        callsign.clone(),
                        *ssid,
                        serial,
                        csma,
                        *flow_control,
                    ) {
                        Ok(interface) => {
                            log::info!(
                                "Enabling interface '{}': AX.25 KISS {callsign}-{ssid} on {port} at {speed} baud",
                                iface.name
                            );
                            iface_manager.lock().await.spawn_named(
                                &iface.name,
                                interface,
                                KissInterface::spawn,
                            );
                        }
                        Err(_) => {
                            log::error!(
                                "Interface '{}': invalid callsign '{callsign}' or ssid {ssid}, not enabling",
                                iface.name
                            );
                        }
                    }
                }

                #[cfg(not(feature = "iface-serial"))]
                {
                    let _ = (
                        callsign,
                        ssid,
                        speed,
                        databits,
                        parity,
                        stopbits,
                        preamble,
                        txtail,
                        persistence,
                        slottime,
                        flow_control,
                    );
                    log::warn!(
                        "Interface '{}' type 'AX25KISSInterface' on port {port} requires building the daemon with --features iface-serial",
                        iface.name
                    );
                }
            }
            InterfaceConfig::Unsupported => {
                log::warn!("Interface '{}' uses an unsupported type", iface.name);
            }
        }
    }

    // Network interface discovery (Python RNS/Discovery.py): enabled
    // when any interface is configured `discoverable`.
    let discoverable: Vec<_> = config
        .interfaces
        .iter()
        .filter(|iface| iface.discoverable)
        .collect();

    if !discoverable.is_empty() {
        let transport_identity = transport.identity_private();
        let announcer = reticulum_discovery::InterfaceAnnouncer::start(
            &transport,
            &transport_identity,
            reticulum_discovery::DEFAULT_STAMP_VALUE,
            reticulum_discovery::ANNOUNCER_INTERVAL,
        )
        .await;

        let transport_id = transport.identity_hash().await;
        for iface in &discoverable {
            let info = discovery_info_for(iface, &config, transport_id);
            if let Some(info) = info {
                log::info!(
                    "Announcing interface '{}' as discoverable {}",
                    iface.name,
                    info.interface_type
                );
                announcer.announce_interface(info).await;
            } else {
                log::warn!(
                    "Interface '{}' is discoverable but its type has no discovery mapping yet",
                    iface.name
                );
            }
        }

        // Listen for other nodes' discovery announces.
        reticulum_discovery::InterfaceDiscovery::start(
            &transport,
            reticulum_discovery::DEFAULT_STAMP_VALUE,
            false,
        )
        .await;
    }

    // Management destinations (Python Transport.start: probe and remote
    // management destinations when enabled in the configuration).
    if config.reticulum.probe_destination {
        transport.enable_probe_destination().await;
    }

    if config.reticulum.remote_management {
        let allowed = parse_management_allowed(&config.reticulum.remote_management_allowed)?;
        for allowed in allowed {
            transport.remote_management_allow(allowed).await;
        }
        let destination = transport.enable_remote_management().await;
        log::info!(
            "Remote management enabled on {}",
            destination.lock().await.desc.address_hash
        );
    }

    log::info!("Reticulum instance running, interfaces initialized");

    // Clean shutdown on SIGINT (Ctrl-C), and SIGTERM where available
    // (not on Windows).
    #[cfg(unix)]
    {
        let sigterm = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut term) => term.recv().await,
                Err(err) => {
                    log::warn!("could not listen for SIGTERM: {err}");
                    std::future::pending::<Option<()>>().await
                }
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = sigterm => {},
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.ok();
    }

    log::info!("Shutdown signal received, cleaning up");
    drop(transport);
    Ok(())
}

/// Apply per-interface common options after spawning
/// (Python `Reticulum._add_interface`: mode, bitrate, IFAC derivation).
async fn configure_iface(
    iface_manager: &std::sync::Arc<tokio::sync::Mutex<reticulum::iface::InterfaceManager>>,
    address: &reticulum::hash::AddressHash,
    iface: &reticulum_daemon::config::NamedInterface,
) {
    let manager = iface_manager.lock().await;

    if let Some(mode) = iface
        .mode
        .as_deref()
        .and_then(reticulum::iface::InterfaceMode::from_name)
    {
        manager.set_iface_mode(address, mode);
    } else if let Some(mode) = iface.mode.as_deref() {
        log::warn!(
            "Interface '{}' has unknown mode '{mode}', keeping default",
            iface.name
        );
    }

    if let Some(bitrate) = iface.bitrate {
        manager.set_iface_bitrate(address, bitrate);
    }

    if iface.networkname.is_some() || iface.passphrase.is_some() {
        let size = iface
            .ifac_size
            .map(|bits| (bits / 8).max(reticulum::iface::ifac::IFAC_MIN_SIZE))
            .unwrap_or(reticulum::iface::ifac::DEFAULT_IFAC_SIZE);

        if let Err(error) = manager.set_iface_ifac(
            address,
            iface.networkname.as_deref(),
            iface.passphrase.as_deref(),
            size,
        ) {
            log::error!(
                "Interface '{}' has an invalid IFAC configuration: {error:?}",
                iface.name
            );
        }

        log::info!(
            "Interface '{}' is access-code protected (ifac size {size} bytes)",
            iface.name
        );
    }
}

/// Build the discovery description of a discoverable interface
/// (Python `InterfaceAnnouncer.get_interface_announce_data`).
fn discovery_info_for(
    iface: &reticulum_daemon::config::NamedInterface,
    config: &reticulum_daemon::config::Config,
    transport_id: reticulum::hash::AddressHash,
) -> Option<reticulum_discovery::InterfaceInfo> {
    use reticulum_daemon::config::InterfaceConfig;

    let interface_type = match &iface.config {
        InterfaceConfig::TCPServerInterface { .. } => "TCPServerInterface",
        InterfaceConfig::KISSInterface { .. } => "KISSInterface",
        _ => return None,
    };

    let (reachable_on, port) = match &iface.config {
        InterfaceConfig::TCPServerInterface { bind_port, .. } => {
            (iface.reachable_on.clone(), Some(*bind_port))
        }
        _ => (None, None),
    };

    let _ = config;

    Some(reticulum_discovery::InterfaceInfo {
        interface_type: interface_type.to_string(),
        transport: config.reticulum.enable_transport,
        transport_id,
        name: iface.discovery_name.clone().or(Some(iface.name.clone())),
        latitude: None,
        longitude: None,
        height: None,
        reachable_on,
        port,
        frequency: None,
        bandwidth: None,
        spreadingfactor: None,
        codingrate: None,
        channel: None,
        modulation: None,
        ifac_netname: None,
        ifac_netkey: None,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_management_allowed;

    #[test]
    fn management_hashes_are_all_validated_before_use() {
        let valid = vec!["00112233445566778899aabbccddeeff".to_string()];
        assert_eq!(parse_management_allowed(&valid).unwrap().len(), 1);
        assert!(parse_management_allowed(&[]).unwrap().is_empty());
        assert!(parse_management_allowed(&[
            valid[0].clone(),
            "not-a-valid-hash".to_string(),
        ])
        .is_err());
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn rnode_endpoints_normalize_python_and_native_forms() {
        use super::rnode_endpoint;

        let tcp = Some("native.example:7633".to_string());
        let serial = Some("/dev/ttyUSB0".to_string());
        assert_eq!(
            rnode_endpoint(&tcp, &serial),
            (Some("native.example:7633"), None)
        );

        let tcp = None;
        let migrated = Some("tcp://127.0.0.1:7633".to_string());
        assert_eq!(
            rnode_endpoint(&tcp, &migrated),
            (Some("127.0.0.1:7633"), None)
        );

        let serial = Some("/dev/ttyACM0".to_string());
        assert_eq!(rnode_endpoint(&tcp, &serial), (None, Some("/dev/ttyACM0")));
    }
}
