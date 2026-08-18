//! Shared plumbing for the `rn*` tools: config-directory handling, identity
//! file persistence, transport construction from a config directory and
//! formatting helpers.
//!
//! Python reference: `RNS.Reticulum` (config dir + storage layout),
//! `RNS.Utilities/*` (`--config` option, `RNS.prettyhexrep`).

use std::fs;
use std::path::{Path, PathBuf};

use rand_core::OsRng;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

/// Format a hash like Python `RNS.prettyhexrep`: `<aabbcc...>`.
pub fn prettyhexrep(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push('<');
    for byte in bytes {
        out.push_str(&format!("{byte:0>2x}"));
    }
    out.push('>');
    out
}

/// Parse a `<hex>`, bare hex or `/<hex>` string into an address hash.
pub fn parse_hash(input: &str) -> Result<AddressHash, String> {
    let cleaned: String = input
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .to_lowercase();
    if cleaned.len() != 32 {
        return Err(format!(
            "Invalid hash entered, must be 32 hexadecimal characters (16 bytes), got {} characters",
            cleaned.len()
        ));
    }
    AddressHash::new_from_hex_string(&cleaned).map_err(|_| "Invalid hash entered. Check your input.".to_string())
}

/// Resolve the configuration directory: explicit argument, else
/// `$RETICULUM_CONFIG_DIR`, else `~/.reticulum`
/// (Python: `RNS.Reticulum(configdir=...)` default).
pub fn resolve_config_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("RETICULUM_CONFIG_DIR") {
        if !env_dir.is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    dirs_home().join(".reticulum")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Identity files (Phase 1.1 / 7.4)
// ---------------------------------------------------------------------------

/// Error loading an identity file.
#[derive(Debug)]
pub enum IdentityLoadError {
    Io(std::io::Error),
    /// The file content is neither a hex string nor 64 raw key bytes.
    Invalid,
}

impl std::fmt::Display for IdentityLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "could not read identity file: {err}"),
            Self::Invalid => write!(
                f,
                "invalid identity file (expected 128 hex characters or 64 raw key bytes)"
            ),
        }
    }
}

impl std::error::Error for IdentityLoadError {}

/// Save a private identity to `path` as a hex string
/// (`PrivateIdentity::to_hex_string`, 128 hex characters).
///
/// Note: Python `Identity.to_file` writes the same 64 key bytes *raw*;
/// [`load_private_identity`] accepts both formats.
pub fn save_private_identity(path: &Path, identity: &PrivateIdentity) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        use std::io::Write;
        file.write_all(identity.to_hex_string().as_bytes())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, identity.to_hex_string())
    }
}

/// Load a private identity from `path`.
///
/// Two formats are accepted:
///  * hex string (128 characters, `PrivateIdentity::to_hex_string`)
///  * raw 64 bytes (Python `Identity.to_file` output:
///    X25519 private key ‖ Ed25519 signing key, same order as the hex form)
pub fn load_private_identity(path: &Path) -> Result<PrivateIdentity, IdentityLoadError> {
    let bytes = fs::read(path).map_err(IdentityLoadError::Io)?;
    // Hex files are ASCII; Python `Identity.to_file` files are raw binary.
    let as_text = String::from_utf8(bytes.clone()).ok();
    if let Some(text) = as_text {
        let text = text.trim().to_string();
        if text.len() == 128 {
            return PrivateIdentity::new_from_hex_string(&text)
                .map_err(|_| IdentityLoadError::Invalid);
        }
    }
    identity_from_raw_keys(&bytes).ok_or(IdentityLoadError::Invalid)
}

/// Build a [`PrivateIdentity`] from 64 raw key bytes
/// (X25519 private key ‖ Ed25519 signing key), the layout Python
/// `Identity.to_file` writes.
pub fn identity_from_raw_keys(bytes: &[u8]) -> Option<PrivateIdentity> {
    if bytes.len() != 64 {
        return None;
    }
    let mut hex_string = String::with_capacity(128);
    for byte in bytes {
        hex_string.push_str(&format!("{byte:0>2x}"));
    }
    PrivateIdentity::new_from_hex_string(&hex_string).ok()
}

/// Load the identity at `path`, creating (and persisting) a new one when the
/// file does not exist yet. Returns the identity and whether it was created.
pub fn load_or_create_private_identity(path: &Path) -> Result<(PrivateIdentity, bool), IdentityLoadError> {
    if path.exists() {
        return load_private_identity(path).map(|identity| (identity, false));
    }
    let identity = PrivateIdentity::new_from_rand(OsRng);
    save_private_identity(path, &identity).map_err(IdentityLoadError::Io)?;
    Ok((identity, true))
}

// ---------------------------------------------------------------------------
// Transport construction from a config directory
// ---------------------------------------------------------------------------

/// Options for [`build_tool_transport`].
pub struct ToolTransportOptions<'a> {
    /// Config directory (usually from `--config`).
    pub config_dir: &'a Path,
    /// Instance name used in logs (Python `instance_name`).
    pub instance_name: &'a str,
    /// Enable transport (routing) mode.
    pub enable_transport: bool,
    /// Bind a UDP loopback interface on `bind_port` forwarding to
    /// `forward_port`. Used when the config directory has no usable
    /// interfaces (e.g. ad-hoc `rn cp` runs between two machines).
    pub udp_loopback: Option<(u16, u16)>,
}

/// A parsed `[[interfaces]]` entry from the config file.
#[derive(Debug)]
pub struct ConfiguredInterface {
    pub name: String,
    pub kind: InterfaceKind,
    pub enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    TcpServer { bind_host: String, bind_port: u16 },
    TcpClient { target_host: String, target_port: u16 },
    Udp { listen_ip: String, listen_port: u16, forward_ip: String, forward_port: u16 },
    Unsupported(String),
}

/// Read `config.toml` (or `config`) from `config_dir` and list the
/// `[[interfaces]]` entries. Unknown-but-parseable entries are returned as
/// [`InterfaceKind::Unsupported`]; a missing or unparseable config yields an
/// empty list (the tools work fine without one).
pub fn read_configured_interfaces(config_dir: &Path) -> Vec<ConfiguredInterface> {
    let Some(content) = read_config_file(config_dir) else {
        return vec![];
    };
    let Ok(value) = toml::from_str::<toml::Value>(&content) else {
        log::warn!(
            "Could not parse {} as TOML; no interfaces from config",
            config_config_path(config_dir).display()
        );
        return vec![];
    };
    let Some(entries) = value.get("interfaces").and_then(|v| v.as_array()) else {
        return vec![];
    };

    let mut out = Vec::new();
    for entry in entries {
        let table = match entry.as_table() {
            Some(table) => table,
            None => continue,
        };
        let name = table
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_string();
        let enabled = table
            .get("enabled")
            .or_else(|| table.get("interface_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let kind_str = table.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let get = |key: &str| table.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let get_u16 = |key: &str| table.get(key).and_then(|v| v.as_integer()).and_then(|v| u16::try_from(v).ok());

        let listen_host = {
            let host = get("listen_ip");
            if host.is_empty() { get("bind_host") } else { host }
        };
        let kind = match kind_str {
            "TCPServerInterface" => match get_u16("listen_port").or_else(|| get_u16("bind_port")) {
                Some(port) => InterfaceKind::TcpServer { bind_host: listen_host, bind_port: port },
                None => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            "TCPClientInterface" => match get_u16("target_port") {
                Some(port) => InterfaceKind::TcpClient {
                    target_host: get("target_host"),
                    target_port: port,
                },
                _ => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            "UDPInterface" => match (get_u16("listen_port"), get_u16("forward_port")) {
                (Some(listen_port), Some(forward_port)) => InterfaceKind::Udp {
                    listen_ip: get("listen_ip"),
                    listen_port,
                    forward_ip: get("forward_ip"),
                    forward_port,
                },
                _ => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            other => InterfaceKind::Unsupported(other.to_string()),
        };
        out.push(ConfiguredInterface { name, kind, enabled });
    }
    out
}

fn config_config_path(config_dir: &Path) -> PathBuf {
    let toml_path = config_dir.join("config.toml");
    if toml_path.exists() {
        toml_path
    } else {
        config_dir.join("config")
    }
}

fn read_config_file(config_dir: &Path) -> Option<String> {
    let path = config_config_path(config_dir);
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    if toml::from_str::<toml::Value>(&content).is_err() {
        log::warn!(
            "Config at {} is not valid TOML (Python-format configs must be converted with \
             `rs-rnsd convert-config` first); continuing without configured interfaces",
            path.display()
        );
        return None;
    }
    Some(content)
}

/// Build a standalone transport for a tool run: applies the interfaces from
/// `config_dir` (if any) or the explicit `udp_loopback` fallback.
pub async fn build_tool_transport(options: ToolTransportOptions<'_>) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = TransportConfig::new(options.instance_name, &identity, options.enable_transport)
        .set_retransmit(options.enable_transport)
        .build();

    let interfaces = read_configured_interfaces(options.config_dir);
    let mut spawned = 0usize;
    for iface in &interfaces {
        if !iface.enabled {
            log::debug!("Interface '{}' disabled in config", iface.name);
            continue;
        }
        // Interfaces are spawned below without holding the manager lock
        // across awaits of the loop body.
        match &iface.kind {
            InterfaceKind::TcpServer { bind_host, bind_port } => {
                let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
                log::info!("Enabling interface '{}': TCP Server on {}", iface.name, addr);
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(TcpServer::new(addr, transport.iface_manager()), TcpServer::spawn);
                spawned += 1;
            }
            InterfaceKind::TcpClient { target_host, target_port } => {
                let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
                log::info!("Enabling interface '{}': TCP Client to {}", iface.name, addr);
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(TcpClient::new(addr), TcpClient::spawn);
                spawned += 1;
            }
            InterfaceKind::Udp { listen_ip, listen_port, forward_ip, forward_port } => {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!("Enabling interface '{}': UDP {}→{}", iface.name, bind_addr, forward_addr);
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(
                        UdpInterface::new(bind_addr, Some(forward_addr), false),
                        UdpInterface::spawn,
                    );
                spawned += 1;
            }
            InterfaceKind::Unsupported(kind) => {
                log::warn!(
                    "Interface '{}' of type '{}' is not supported yet, skipping",
                    iface.name,
                    kind
                );
            }
        }
    }

    if spawned == 0 {
        if let Some((bind_port, forward_port)) = options.udp_loopback {
            log::info!(
                "No configured interfaces, using UDP loopback 127.0.0.1:{bind_port}→127.0.0.1:{forward_port}"
            );
            transport
                .iface_manager()
                .lock()
                .await
                .spawn(
                    UdpInterface::new(
                        format!("127.0.0.1:{bind_port}"),
                        Some(format!("127.0.0.1:{forward_port}")),
                        false,
                    ),
                    UdpInterface::spawn,
                );
        }
    }

    transport
}

// ---------------------------------------------------------------------------
// Interface stats (rnstatus)
// ---------------------------------------------------------------------------

/// Fetch interface stats for a transport
/// (`Transport::interface_stats`, Phase 5.9: names, kinds, counters and
/// online state — the data source for `rnstatus`).
pub async fn interface_stats(transport: &Transport) -> Vec<reticulum::iface::InterfaceStats> {
    transport.interface_stats().await
}
