use std::path::PathBuf;

use clap::Parser;
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::local::LocalServer;
use reticulum::iface::local::SharedInstanceAddress;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;
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
#[cfg(feature = "iface-serial")]
use reticulum::iface::serial::SerialInterface;
#[cfg(feature = "iface-pipe")]
use reticulum::iface::pipe::PipeInterface;

use reticulum_daemon::config::{Config, InterfaceConfig};

/// File the daemon identity is persisted to (hex format, see
/// `reticulum_utils::common::save_private_identity`), relative to the config
/// directory. Python stores the transport identity under
/// `storage/identities` in raw-key format; we keep the daemon identity at
/// the config-dir root in hex so `rn id -i <configdir>/identity` can inspect
/// it.
const IDENTITY_FILE: &str = "identity";

/// Reticulum-rs daemon
#[derive(Parser)]
#[clap(version)]
#[clap(args_conflicts_with_subcommands=true)]
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
        config_file: PathBuf
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = Command::parse();
    if let Some(subcommand) = cmd.convert_config {
        match subcommand {
            Subcommand::ConvertConfig { config_file } => {
                return reticulum_daemon::config::migrate_config(&config_file)
            }
        }
    }

    let (config, config_path) = Config::load(cmd.config_dir.as_deref())?;
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(format!("{:?}", config.logging.loglevel))
    ).init();

    log::info!("Configuration loaded from: {}", config_path.display());
    log::info!("Reticulum daemon starting");

    // Load (or create + persist) the daemon identity so the instance — and
    // every destination derived from it — stays stable across restarts
    // (Phase 7.4). The daemon announces nothing by default.
    let identity_path = config_path.join(IDENTITY_FILE);
    let identity = match reticulum_utils::common::load_private_identity(&identity_path) {
        Ok(identity) => {
            log::info!(
                "Loaded daemon identity {} from {}",
                reticulum_utils::common::prettyhexrep(identity.address_hash().as_slice()),
                identity_path.display()
            );
            identity
        }
        Err(_err) if !identity_path.exists() => {
            let identity = PrivateIdentity::new_from_rand(OsRng);
            reticulum_utils::common::save_private_identity(&identity_path, &identity)?;
            log::info!(
                "Generated new daemon identity {} and persisted it to {}",
                reticulum_utils::common::prettyhexrep(identity.address_hash().as_slice()),
                identity_path.display()
            );
            identity
        }
        Err(err) => return Err(format!("could not load daemon identity: {err}").into()),
    };

    let instance_name = config
        .reticulum
        .instance_name
        .clone()
        .unwrap_or_else(|| "rns-daemon".to_string());
    log::info!("Instance name: {instance_name}");

    let transport = TransportConfig::new(
            &instance_name,
            &identity,
            config.reticulum.enable_transport)
        .set_retransmit(config.reticulum.enable_transport)
        .build();

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

        let address = if config.reticulum.shared_instance_type.eq_ignore_ascii_case("tcp") {
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

    for iface in config.interfaces {
        let enabled = match &iface.config {
            InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
            InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
            InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
            InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
            InterfaceConfig::I2PInterface { enabled, .. } => *enabled,
            InterfaceConfig::RNodeInterface { enabled, .. } => *enabled,
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
            InterfaceConfig::TCPServerInterface { bind_host, bind_port, .. } => {
                let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
                log::info!("Enabling interface '{}': TCP Server on {}", iface.name, addr);
                let address = iface_manager.lock().await.spawn(
                    TcpServer::new(addr, iface_manager.clone()),
                    TcpServer::spawn,
                );
                configure_iface(&iface_manager, &address, &iface).await;
            }
            InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
                log::info!("Enabling interface '{}': TCP Client to {}", iface.name, addr);
                let address = iface_manager.lock().await.spawn(
                    TcpClient::new(addr),
                    TcpClient::spawn,
                );
                configure_iface(&iface_manager, &address, &iface).await;
            }
            InterfaceConfig::UDPInterface { listen_ip, listen_port, forward_ip, forward_port, .. } => {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!("Enabling interface '{}': UDP {}→{}", iface.name, bind_addr, forward_addr);
                let address = iface_manager.lock().await.spawn(
                    UdpInterface::new(bind_addr, Some(forward_addr), false),
                    UdpInterface::spawn,
                );
                configure_iface(&iface_manager, &address, &iface).await;
            }
            InterfaceConfig::AutoInterface { group_id, discovery_port, data_port, discovery_scope, multicast_address_type, devices, ignored_devices, .. } => {
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
                        auto_config.multicast_address_type = MulticastAddressType::parse(&address_type);
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
                    configure_iface(&iface_manager, &address, &iface).await;
                }

                #[cfg(not(all(feature = "iface-auto", target_os = "linux")))]
                {
                    let _ = (group_id, discovery_port, data_port, discovery_scope, multicast_address_type, devices, ignored_devices);
                    log::warn!(
                        "Interface '{}' type 'AutoInterface' requires building the daemon with --features iface-auto (Linux only)",
                        iface.name
                    );
                }
            }
            InterfaceConfig::I2PInterface { .. } => {
                log::warn!("Interface '{}' type 'I2PInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::RNodeInterface { .. } => {
                log::warn!("Interface '{}' type 'RNodeInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::BLEInterface { .. } => {
                log::warn!("Interface '{}' type 'BLEInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::KISSInterface { port, speed, databits, parity, stopbits, preamble, txtail, persistence, slottime, flow_control, .. } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed)
                        .with_format(*databits, parity.clone(), *stopbits);
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
                    configure_iface(&iface_manager, &address, &iface).await;
                }

                #[cfg(not(feature = "iface-serial"))]
                {
                    let _ = (speed, databits, parity, stopbits, preamble, txtail, persistence, slottime, flow_control);
                    log::warn!(
                        "Interface '{}' type 'KISSInterface' on port {port} requires building the daemon with --features iface-serial",
                        iface.name
                    );
                }
            }
            InterfaceConfig::SerialInterface { port, speed, databits, parity, stopbits, .. } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed)
                        .with_format(*databits, parity.clone(), *stopbits);

                    log::info!(
                        "Enabling interface '{}': Serial (HDLC) on {port} at {speed} baud",
                        iface.name
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        SerialInterface::new(serial),
                        SerialInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, &iface).await;
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
            InterfaceConfig::PipeInterface { command, respawn_delay, .. } => {
                #[cfg(feature = "iface-pipe")]
                {
                    let respawn_delay = std::time::Duration::from_secs_f64(respawn_delay.max(0.0) as f64);

                    log::info!(
                        "Enabling interface '{}': Pipe command '{command}' (respawn delay {respawn_delay:?})",
                        iface.name
                    );
                    let address = iface_manager.lock().await.spawn_named(
                        &iface.name,
                        PipeInterface::new(command).with_respawn_delay(respawn_delay),
                        PipeInterface::spawn,
                    );
                    configure_iface(&iface_manager, &address, &iface).await;
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
            InterfaceConfig::LocalInterface { listen_ip, listen_port, .. } => {
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
                        LocalServer::new(SharedInstanceAddress::tcp(*listen_port), iface_manager.clone()),
                        LocalServer::spawn,
                    );
                } else {
                    log::warn!(
                        "Interface '{}' type 'LocalInterface': shared instances always listen on 127.0.0.1 (got {listen_ip})",
                        iface.name
                    );
                }
            }
            InterfaceConfig::AX25KISSInterface { callsign, ssid, port, speed, databits, parity, stopbits, preamble, txtail, persistence, slottime, flow_control, .. } => {
                #[cfg(feature = "iface-serial")]
                {
                    let serial = SerialPortConfig::new(port.clone(), *speed)
                        .with_format(*databits, parity.clone(), *stopbits);
                    let csma = CsmaParams::new(*preamble, *txtail, *persistence, *slottime);

                    match KissInterface::new_ax25(callsign.clone(), *ssid, serial, csma, *flow_control) {
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
                    let _ = (callsign, ssid, speed, databits, parity, stopbits, preamble, txtail, persistence, slottime, flow_control);
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

    log::info!("Reticulum instance running, interfaces initialized");

    // Clean shutdown on SIGINT (Ctrl-C) and SIGTERM.
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

    if let Some(mode) = iface.mode.as_deref().and_then(reticulum::iface::InterfaceMode::from_name) {
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

        manager.set_iface_ifac(
            address,
            iface.networkname.as_deref(),
            iface.passphrase.as_deref(),
            size,
        );

        log::info!(
            "Interface '{}' is access-code protected (ifac size {size} bytes)",
            iface.name
        );
    }
}
