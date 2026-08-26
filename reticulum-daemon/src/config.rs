use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(untagged)]
enum StringList {
    List(Vec<String>),
    CommaSeparated(String),
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = match StringList::deserialize(deserializer)? {
        StringList::List(values) => values,
        StringList::CommaSeparated(value) => value.split(',').map(str::to_owned).collect(),
    };
    Ok(values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect())
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub reticulum: ReticulumConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub interfaces: Vec<NamedInterface>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReticulumConfig {
    /// Enable the remote management destination
    /// (Python `enable_remote_management`).
    #[serde(default, alias = "enable_remote_management")]
    pub remote_management: bool,
    /// Publish this node's blackhole list over the
    /// `rnstransport.info.blackhole` destination
    /// (Python `publish_blackhole`).
    #[serde(default)]
    pub publish_blackhole: bool,
    /// Trusted remote blackhole-list publishers, as 32-character hex
    /// identity hashes (Python `blackhole_sources`; non-empty enables
    /// the blackhole updater).
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub blackhole_sources: Vec<String>,
    /// Enable the probe destination (Python `enable_remote_probe`).
    #[serde(default, alias = "respond_to_probes", alias = "enable_remote_probe")]
    pub probe_destination: bool,
    /// Identities permitted to use remote management. Python accepts a
    /// comma-separated string while native TOML commonly uses an array.
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub remote_management_allowed: Vec<String>,
    #[serde(default)]
    pub enable_transport: bool,
    #[serde(default = "default_true")]
    pub share_instance: bool,
    #[serde(default = "default_shared_port")]
    pub shared_instance_port: u16,
    /// `shared_instance_type = tcp|domain` (Python: domain sockets where
    /// available, TCP otherwise).
    #[serde(default = "default_shared_instance_type")]
    pub shared_instance_type: String,
    #[serde(default = "default_control_port")]
    pub instance_control_port: u16,
    #[serde(default)]
    pub panic_on_interface_error: bool,
    #[serde(default)]
    pub instance_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_loglevel")]
    pub loglevel: log::LevelFilter,
}

/// One RNodeMulti virtual port (Python `[[subinterfaces]]` entry).
#[derive(Debug, Deserialize, Serialize)]
pub struct RnodeSubinterface {
    /// Virtual port index.
    pub vport: u8,
    pub frequency: u64,
    pub bandwidth: u32,
    pub txpower: u8,
    pub spreadingfactor: u8,
    pub codingrate: u8,
    #[serde(default)]
    pub st_alock: Option<f32>,
    #[serde(default)]
    pub lt_alock: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NamedInterface {
    pub name: String,
    #[serde(flatten)]
    pub config: InterfaceConfig,
    /// Interface mode (Python `mode`: full/access_point/roaming/boundary/
    /// gateway/point_to_point/internal).
    #[serde(default)]
    pub mode: Option<String>,
    /// Nominal bitrate in bits per second (Python `configured_bitrate`).
    #[serde(default, alias = "configured_bitrate")]
    pub bitrate: Option<u64>,
    /// Interface access code size in bits (Python `ifac_size`).
    #[serde(default)]
    pub ifac_size: Option<usize>,
    /// Access code network name (Python `networkname` / `network_name`).
    #[serde(default, alias = "network_name")]
    pub networkname: Option<String>,
    /// Access code passphrase (Python `passphrase` / `pass_phrase`).
    #[serde(default, alias = "pass_phrase")]
    pub passphrase: Option<String>,
    /// Announce this interface for network discovery
    /// (Python `discoverable`).
    #[serde(default)]
    pub discoverable: bool,
    /// Discovery announce interval in minutes, minimum 5
    /// (Python `announce_interval`).
    #[serde(default, alias = "announce_interval")]
    pub discovery_announce_interval_minutes: Option<u64>,
    /// Discovery announce stamp cost (Python `discovery_stamp_value`).
    #[serde(default)]
    pub discovery_stamp_value: Option<u32>,
    /// Discovery name of the interface (Python `discovery_name`).
    #[serde(default)]
    pub discovery_name: Option<String>,
    /// Externally reachable host for connectable interfaces
    /// (Python `reachable_on`).
    #[serde(default)]
    pub reachable_on: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum InterfaceConfig {
    TCPServerInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(alias = "listen_ip")]
        bind_host: String,
        #[serde(alias = "listen_port")]
        bind_port: u16,
    },
    TCPClientInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        target_host: String,
        target_port: u16,
    },
    UDPInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        listen_ip: String,
        listen_port: u16,
        forward_ip: String,
        forward_port: u16,
    },
    I2PInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        /// Published peers to connect to (base64 destinations).
        #[serde(default, deserialize_with = "deserialize_string_list")]
        peers: Vec<String>,
        /// Accept inbound streams and publish this instance's
        /// destination (Python `connectable`).
        #[serde(default)]
        connectable: bool,
        /// SAM bridge address (default 127.0.0.1:7656).
        sam_address: Option<String>,
    },
    BackboneInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        listen_ip: String,
        #[serde(alias = "listen_port")]
        bind_port: u16,
        /// Block fast-flapping remote connections
        /// (Python `block_fast_flapping`).
        #[serde(default = "default_backbone_flap_block")]
        block_fast_flapping: bool,
        /// Fast-flap threshold in seconds (Python
        /// `fast_flapping_threshold`).
        fast_flapping_threshold: Option<f64>,
        /// Allowed fast flaps before blocking (Python
        /// `fast_flapping_grace`).
        fast_flapping_grace: Option<u32>,
        /// Fast-flap block expiry in minutes (Python
        /// `fast_flapping_block_time`).
        fast_flapping_block_time: Option<f64>,
    },
    BackboneClientInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(alias = "target_host")]
        target_ip: String,
        target_port: u16,
    },
    AutoInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        /// Discovery group id (default "reticulum")
        #[serde(default = "default_group_id")]
        group_id: String,
        /// Multicast discovery port (default 29716)
        #[serde(default = "default_discovery_port")]
        discovery_port: u16,
        /// Unicast data port (default 42671)
        #[serde(default = "default_data_port")]
        data_port: u16,
        /// Discovery scope: link (default), admin, site, organisation, global
        #[serde(default)]
        discovery_scope: Option<String>,
        /// Multicast address type: temporary (default) or permanent
        #[serde(default)]
        multicast_address_type: Option<String>,
        /// Allow-list of interface names (`devices`, comma-separated)
        #[serde(default)]
        devices: Option<String>,
        /// Deny-list of interface names (`ignored_devices`, comma-separated)
        #[serde(default)]
        ignored_devices: Option<String>,
    },
    RNodeInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(alias = "target")]
        port: Option<String>,
        /// TCP device link (Python `tcp` mode).
        tcp: Option<String>,
        #[serde(default = "default_baudrate")]
        speed: u32,
        frequency: u64,
        bandwidth: u32,
        txpower: u8,
        spreadingfactor: u8,
        codingrate: u8,
        /// Short-term airtime lock in percent
        /// (Python `airtime_limit_short_term`).
        #[serde(default)]
        st_alock: Option<f32>,
        /// Long-term airtime lock (Python `airtime_limit_long_term`).
        #[serde(default)]
        lt_alock: Option<f32>,
        #[serde(default)]
        flow_control: bool,
    },
    RNodeMultiInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(alias = "target")]
        port: Option<String>,
        tcp: Option<String>,
        #[serde(default = "default_baudrate")]
        speed: u32,
        /// Virtual port sub-interfaces (Python `[[subinterfaces]]`).
        #[serde(default)]
        subinterfaces: Vec<RnodeSubinterface>,
    },
    BLEInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        enable_peripheral: bool,
        #[serde(default)]
        enable_central: bool,
    },
    KISSInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        port: String,
        #[serde(default = "default_serial_speed")]
        speed: u32,
        #[serde(default = "default_databits")]
        databits: u8,
        #[serde(default = "default_parity")]
        parity: String,
        #[serde(default = "default_stopbits")]
        stopbits: u8,
        #[serde(default = "default_preamble")]
        preamble: u32,
        #[serde(default = "default_txtail")]
        txtail: u32,
        #[serde(default = "default_persistence")]
        persistence: u32,
        #[serde(default = "default_slottime")]
        slottime: u32,
        #[serde(default)]
        flow_control: bool,
    },
    AX25KISSInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        callsign: String,
        ssid: u8,
        port: String,
        #[serde(default = "default_serial_speed")]
        speed: u32,
        #[serde(default = "default_databits")]
        databits: u8,
        #[serde(default = "default_parity")]
        parity: String,
        #[serde(default = "default_stopbits")]
        stopbits: u8,
        #[serde(default = "default_preamble")]
        preamble: u32,
        #[serde(default = "default_txtail")]
        txtail: u32,
        #[serde(default = "default_persistence")]
        persistence: u32,
        #[serde(default = "default_slottime")]
        slottime: u32,
        #[serde(default)]
        flow_control: bool,
    },
    SerialInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        port: String,
        #[serde(default = "default_serial_speed")]
        speed: u32,
        #[serde(default = "default_databits")]
        databits: u8,
        #[serde(default = "default_parity")]
        parity: String,
        #[serde(default = "default_stopbits")]
        stopbits: u8,
    },
    PipeInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        command: String,
        /// Respawn delay in (fractional) seconds when the command exits
        /// (Python `respawn_delay`, default 5)
        #[serde(default = "default_respawn_delay")]
        respawn_delay: f32,
    },
    LocalInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(default = "default_local_ip")]
        listen_ip: String,
        #[serde(default = "default_shared_port")]
        listen_port: u16,
    },
    #[serde(other)]
    Unsupported,
}

fn default_true() -> bool {
    true
}

fn default_backbone_flap_block() -> bool {
    true
}

fn default_baudrate() -> u32 {
    115200
}
fn default_serial_speed() -> u32 {
    9600
}
fn default_databits() -> u8 {
    8
}
fn default_parity() -> String {
    "N".to_string()
}
fn default_stopbits() -> u8 {
    1
}
fn default_local_ip() -> String {
    "127.0.0.1".to_string()
}
fn default_shared_port() -> u16 {
    37428
}
fn default_shared_instance_type() -> String {
    "domain".to_string()
}
fn default_control_port() -> u16 {
    37429
}
fn default_loglevel() -> log::LevelFilter {
    log::LevelFilter::Info
}
// KISS CSMA defaults (KISSInterface.py)
fn default_preamble() -> u32 {
    350
}
fn default_txtail() -> u32 {
    20
}
fn default_persistence() -> u32 {
    64
}
fn default_slottime() -> u32 {
    20
}
fn default_group_id() -> String {
    "reticulum".to_string()
}
fn default_discovery_port() -> u16 {
    29716
}
fn default_data_port() -> u16 {
    42671
}
fn default_respawn_delay() -> f32 {
    5.0
}

pub fn migrate_config(config_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !config_file.exists() {
        eprintln!("Error: File '{}' does not exist", config_file.display());
        std::process::exit(1);
    }
    println!("Reading config from: {}", config_file.display());
    let content = fs::read_to_string(config_file)?;
    if toml::from_str::<Config>(&content).is_ok() {
        println!("File is already a valid TOML config: exiting");
        return Ok(());
    }
    let converted = convert_config(&content);
    // validate
    match toml::from_str::<toml::Value>(&converted) {
        Ok(_) => {}
        Err(err) => {
            eprintln!("error: converted text is not a valid TOML file");
            return Err(err.into());
        }
    }
    if cfg!(debug_assertions) {
        match toml::from_str::<Config>(&converted) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("error: converted text is not a valid rs-rnsd Config file");
                return Err(err.into());
            }
        }
    }
    // in case the passed-in file already has a .toml extension, create a backup to prevent
    // overwriting it
    let new_config_file = if config_file.extension() == Some(OsStr::new("toml")) {
        let backup_path = config_file.with_extension("bak");
        fs::write(&backup_path, &content)?;
        println!("Created backup at: {}", backup_path.display());
        config_file.to_owned()
    } else {
        config_file.with_extension("toml")
    };
    fs::write(&new_config_file, &converted)?;
    println!(
        "✓ Converted config written to: {}",
        new_config_file.display()
    );
    println!();
    println!("Changes made:");
    println!("  - Converted numeric log level to log level string");
    println!("  - Converted True/False/Yes/No → true/false");
    println!("  - Quoted all string values (IPs, hostnames, paths, types)");
    println!("  - Converted [[Interface Name]] → [[interfaces]] with name field");
    println!("  - Normalized indentation");
    println!("  - Preserved all comments");
    Ok(())
}

fn convert_config(content: &str) -> String {
    fn quote_if_needed(line: &str, key: &str) -> String {
        let pattern = format!("{} = ", key);
        let quoted_pattern = format!("{} = \"", key);
        // Already quoted or not present
        if !line.contains(&pattern) || line.contains(&quoted_pattern) {
            return line.to_string();
        }
        // Find the value
        if let Some(pos) = line.find(&pattern) {
            let value_start = pos + pattern.len();
            let rest = &line[value_start..];
            // Python config values are commonly free-form strings. Preserve
            // their full value and any inline comment instead of keeping only
            // the first whitespace-delimited token.
            let (value, comment) = match rest.find(" #") {
                Some(comment_start) => (&rest[..comment_start], &rest[comment_start..]),
                None => (rest, ""),
            };
            let value = value.trim();
            // Don't quote numbers or booleans
            if value.parse::<i64>().is_ok()
                || value.parse::<f64>().is_ok()
                || value == "true"
                || value == "false"
            {
                return line.to_string();
            }
            // Quote the value
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            format!("{}{} = \"{}\"{}", &line[..pos], key, escaped, comment)
        } else {
            line.to_string()
        }
    }

    let mut output = String::new();
    let re_false = Regex::new(r" = \b(No|no|False)\b").unwrap();
    let re_true = Regex::new(r" = \b(Yes|yes|True)\b").unwrap();
    let re_nil = Regex::new(r"^(\w+)\s*=\s*\b(None|none|nil|Nil|null|Null)\b").unwrap();
    let re_loglevel = Regex::new(r"(\bloglevel\s*=\s*)(\d+)\b").unwrap();
    for line in content.lines() {
        let trimmed = line.trim();
        // Empty lines pass through
        if trimmed.is_empty() {
            output.push('\n');
            continue;
        }
        // Skip [interfaces] header - we use [[interfaces]] instead
        if trimmed == "[interfaces]" {
            continue;
        }
        // Detect interface block start
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            let name = trimmed
                .trim_start_matches("[[")
                .trim_end_matches("]]")
                .trim();
            if name != "interfaces" {
                // Convert [[Interface Name]] to [[interfaces]]
                output.push_str("\n[[interfaces]]\n");
                output.push_str(&format!("name = \"{}\"\n", name));
                continue;
            } else {
                output.push_str("\n[[interfaces]]\n");
                continue;
            }
        }
        // Process the line
        let mut converted = trimmed.to_string();
        // Convert booleans
        converted = re_false.replace_all(&converted, " = false").to_string();
        converted = re_true.replace_all(&converted, " = true").to_string();
        // Comment out nil values, as toml does not support them (https://github.com/toml-lang/toml/issues/30)
        if re_nil.is_match(&converted) {
            converted = format!("# {}", converted);
            output.push_str(&converted);
            output.push('\n');
            continue;
        }

        // Convert numeric loglevel
        converted = re_loglevel
            .replace(&converted, |caps: &regex::Captures| {
                let level_num: u8 = caps[2].parse().unwrap();
                let level = python_log_filter(level_num);
                let out = format!("{}{}", &caps[1], level);
                out
            })
            .to_string();

        // Quote unquoted string values (only for non-comments)
        if !converted.starts_with('#') {
            for key in [
                "type", "remote", "target_host", "bind_host", "listen_ip", "forward_ip",
                "peers", "instance_name", "port", "callsign", "parity", "loglevel",
                "group_id", "discovery_scope", "multicast_address_type", "command",
                "reachable_on", "sam_address", "tcp", "networkname", "network_name",
                "passphrase", "pass_phrase", "devices", "ignored_devices",
                "remote_management_allowed",
            ] {
                converted = quote_if_needed(&converted, key);
            }
        }
        output.push_str(&converted);
        output.push('\n');
    }
    output
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            remote_management: false,
            publish_blackhole: false,
            blackhole_sources: Vec::new(),
            probe_destination: false,
            remote_management_allowed: Vec::new(),
            enable_transport: false,
            share_instance: false,
            shared_instance_port: 37428,
            shared_instance_type: default_shared_instance_type(),
            instance_control_port: 37429,
            panic_on_interface_error: false,
            instance_name: None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            loglevel: default_loglevel(),
        }
    }
}

/// Debug-printable description of the shared-instance listener address.
pub struct SharedInstanceDescription<'a> {
    pub kind: &'a str,
    pub port: u16,
    pub instance_name: &'a str,
}

impl std::fmt::Debug for SharedInstanceDescription<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.kind.eq_ignore_ascii_case("tcp") {
            write!(f, "tcp 127.0.0.1:{}", self.port)
        } else if cfg!(unix) {
            write!(f, "domain \\0rns/{}", self.instance_name)
        } else {
            write!(
                f,
                "tcp 127.0.0.1:{} (domain sockets unavailable)",
                self.port
            )
        }
    }
}

impl Config {
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = vec![];
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".config/reticulum"));
            paths.push(home.join(".reticulum"));
        }
        paths.push(PathBuf::from("/etc/reticulum"));
        paths
    }

    pub fn find_existing() -> Option<PathBuf> {
        Self::search_paths()
            .into_iter()
            .find(|p| p.join("config").exists() || p.join("config.toml").exists())
    }

    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .expect("cannot write config: user has no home directory")
            .join(".config/reticulum")
    }

    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config_basename = if path.join("config.toml").exists() {
            "config.toml"
        } else if path.join("config").exists() {
            "config"
        } else {
            let err = format!(
                "no config.toml or config file found in config path {}",
                path.display()
            );
            return Err(err.into());
        };
        let config_file = path.join(config_basename);
        let content = fs::read_to_string(&config_file)?;
        // Unknown keys must warn, never fail (Python __apply_config parity).
        if let Ok(value) = toml::from_str::<toml::Value>(&content) {
            warn_about_unknown_keys(&value);
        }
        let config: Self = match toml::from_str(&content) {
            Ok(config) => config,
            Err(err) => {
                if config_basename == "config.toml" {
                    eprintln!("{config_file:?} is not valid TOML");
                    return Err(err.into());
                } else {
                    // attempt to convert
                    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    eprintln!("Your config file appears to be in Python Reticulum format.");
                    eprintln!("You can use the converter tool to migrate it to standard TOML:");
                    eprintln!();
                    eprintln!(
                        "  cargo run -p reticulum-daemon -- convert-config {}",
                        config_file.display()
                    );
                    eprintln!();
                    eprintln!(
                        "This command will create a backup and convert your config to valid TOML."
                    );
                    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    let converted = convert_config(&content);
                    toml::from_str(&converted)?
                }
            }
        };
        for iface in &config.interfaces {
            if let Some(bits) = iface.ifac_size
                && bits > 512
            {
                return Err(format!(
                    "interface '{}' configures an IFAC of {bits} bits; the maximum is 512",
                    iface.name
                )
                .into());
            }
        }
        if config.reticulum.share_instance {
            let instance_name = config
                .reticulum
                .instance_name
                .clone()
                .unwrap_or_else(|| "default".to_string());
            log::info!(
                "share_instance is enabled: the daemon will listen on a local shared instance ({:?})",
                SharedInstanceDescription {
                    kind: &config.reticulum.shared_instance_type,
                    port: config.reticulum.shared_instance_port,
                    instance_name: &instance_name,
                }
            );
        }
        Ok(config)
    }

    pub fn load(
        custom_config_path: Option<&Path>,
    ) -> Result<(Self, PathBuf), Box<dyn std::error::Error>> {
        if let Some(path) = custom_config_path {
            let config = Self::from_file(path)?;
            return Ok((config, path.to_path_buf()));
        }
        if let Some(existing) = Self::find_existing() {
            let config = Self::from_file(&existing)?;
            Ok((config, existing))
        } else {
            log::warn!("No existing configuration found, creating default config");
            let default_dir = Self::default_path();
            fs::create_dir_all(&default_dir)?;
            let config = Self::default_config();
            let config_file = default_dir.join("config.toml");
            fs::write(&config_file, toml::to_string_pretty(&config)?)?;
            log::warn!(
                "Created default configuration at: {}",
                config_file.display()
            );
            log::warn!("Please review and customize the configuration for your needs");
            Ok((config, default_dir))
        }
    }

    fn default_config() -> Self {
        Self {
            reticulum: ReticulumConfig::default(),
            logging: LoggingConfig::default(),
            interfaces: vec![NamedInterface {
                name: "Default TCP Server Interface".to_string(),
                mode: None,
                bitrate: None,
                ifac_size: None,
                networkname: None,
                passphrase: None,
                discoverable: false,
                discovery_announce_interval_minutes: None,
                discovery_stamp_value: None,
                discovery_name: None,
                reachable_on: None,
                config: InterfaceConfig::TCPServerInterface {
                    enabled: true,
                    bind_host: "127.0.0.1".to_string(),
                    bind_port: 4242,
                },
            }],
        }
    }
}

pub fn python_log_filter(loglevel: u8) -> log::LevelFilter {
    match loglevel {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Info,
        5 => log::LevelFilter::Debug,
        6 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

// ---------------------------------------------------------------------------
// Phase 7.2 config parity: additional interface types + unknown-key warnings.
// ---------------------------------------------------------------------------

/// Keys of the `[reticulum]` section the daemon understands. Keys known from
/// the Python implementation but not (yet) applied by the Rust daemon are
/// listed separately in [`KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS`] so they are
/// reported as "not yet supported" instead of "unknown".
pub const KNOWN_RETICULUM_KEYS: &[&str] = &[
    "enable_transport",
    "share_instance",
    "shared_instance_port",
    "shared_instance_type",
    "instance_control_port",
    "instance_name",
    "panic_on_interface_error",
    "network_identity",
    "static_transport_identity",
    "storagepath",
    "require_if_time_sync",
    "link_mtu_discovery",
    "remote_management",
    "enable_remote_management",
    "probe_destination",
    "enable_remote_probe",
    "enable_stranded_announce_rebroadcast",
];

/// `[reticulum]` keys that are recognized but currently ignored by the Rust
/// daemon.
pub const KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS: &[&str] = &[
    "network_identity",
    "static_transport_identity",
    "storagepath",
    "require_if_time_sync",
    "link_mtu_discovery",
    "enable_stranded_announce_rebroadcast",
];

/// Keys of the `[logging]` section the daemon understands.
pub const KNOWN_LOGGING_KEYS: &[&str] = &["loglevel", "logdest", "logfile"];

/// Keys understood inside `[[interfaces]]` entries, independent of type.
pub const KNOWN_INTERFACE_KEYS: &[&str] = &[
    "name",
    "type",
    "enabled",
    "interface_enabled",
    "mode",
    "configured_bitrate",
    "ifac_size",
    "ifac_key",
    "ifac_netname",
    "announce_rate_target",
    "announce_rate_penalty",
    "announce_rate_grace",
    "announce_rate_min_squeeze",
    "ingress_controlled",
    "discoverable",
    "announce_interval",
    "discovery_stamp_value",
    "discovery_name",
    "reachable_on",
];

/// Warn (never fail) about configuration keys the daemon does not know or
/// does not apply — mirroring Python's `__apply_config` warnings.
pub fn warn_about_unknown_keys(value: &toml::Value) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (section, contents) in table {
        match section.as_str() {
            "reticulum" => warn_section(
                contents,
                KNOWN_RETICULUM_KEYS,
                KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS,
                "reticulum",
            ),
            "logging" => warn_section(contents, KNOWN_LOGGING_KEYS, &[], "logging"),
            "interfaces" => {
                if let Some(entries) = contents.as_array() {
                    for (index, entry) in entries.iter().enumerate() {
                        let Some(entry_table) = entry.as_table() else {
                            continue;
                        };
                        let iface_type = entry_table
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<missing type>");
                        let iface_name = entry_table
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unnamed");
                        if !SUPPORTED_INTERFACE_TYPES.contains(&iface_type) {
                            log::warn!(
                                "Interface '{iface_name}' (#{index}) has type '{iface_type}' which is not supported yet"
                            );
                        }
                        for key in entry_table.keys() {
                            if !KNOWN_INTERFACE_KEYS.contains(&key.as_str()) {
                                log::warn!(
                                    "Unknown key '{key}' in interface '{iface_name}' (type '{iface_type}')"
                                );
                            }
                        }
                    }
                }
            }
            other => log::warn!("Unknown configuration section [{other}]"),
        }
    }
}

fn warn_section(contents: &toml::Value, known: &[&str], unapplied: &[&str], section: &str) {
    let Some(table) = contents.as_table() else {
        return;
    };
    for key in table.keys() {
        if unapplied.contains(&key.as_str()) {
            log::warn!(
                "[{section}] key '{key}' is recognized but not yet applied by the Rust daemon"
            );
        } else if !known.contains(&key.as_str()) {
            log::warn!("Unknown key '{key}' in section [{section}]");
        }
    }
}

/// Interface types the Rust daemon can parse from `[[interfaces]]` entries.
/// (Spawning support depends on the corresponding `reticulum::iface` module
/// being available; see `main.rs`.)
pub const SUPPORTED_INTERFACE_TYPES: &[&str] = &[
    "TCPServerInterface",
    "TCPClientInterface",
    "UDPInterface",
    "SerialInterface",
    "PipeInterface",
    "KISSInterface",
    "AX25KISSInterface",
    "RNodeInterface",
    "RNodeMultiInterface",
    "AutoInterface",
    "I2PInterface",
    "BLEInterface",
    "LocalInterface",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_instance_defaults_match_python() {
        let config: Config = toml::from_str("").unwrap();

        assert!(!config.reticulum.share_instance);
        assert_eq!(config.reticulum.shared_instance_port, 37428);
        assert_eq!(
            config.reticulum.shared_instance_type, "domain",
            "Python uses domain sockets for shared instances where available"
        );
        assert!(config.reticulum.instance_name.is_none());
    }

    #[test]
    fn parse_shared_instance_options() {
        let config: Config = toml::from_str(
            r#"
[reticulum]
share_instance = true
shared_instance_type = "tcp"
shared_instance_port = 42840
instance_name = "node-b"
"#,
        )
        .unwrap();

        assert!(config.reticulum.share_instance);
        assert_eq!(config.reticulum.shared_instance_type, "tcp");
        assert_eq!(config.reticulum.shared_instance_port, 42840);
        assert_eq!(config.reticulum.instance_name.as_deref(), Some("node-b"));
    }

    #[test]
    fn parse_domain_shared_instance() {
        let config: Config = toml::from_str(
            r#"
[reticulum]
share_instance = true
instance_name = "second"

[[interfaces]]
name = "Test Pipe"
type = "PipeInterface"
command = "/bin/cat"
"#,
        )
        .unwrap();

        assert_eq!(config.reticulum.shared_instance_type, "domain");
        assert_eq!(config.reticulum.instance_name.as_deref(), Some("second"));

        let NamedInterface { name, config, .. } = config.interfaces.into_iter().next().unwrap();
        assert_eq!(name, "Test Pipe");
        match config {
            InterfaceConfig::PipeInterface {
                enabled,
                command,
                respawn_delay,
            } => {
                assert!(enabled);
                assert_eq!(command, "/bin/cat");
                assert_eq!(respawn_delay, 5.0, "Python respawn_delay default is 5s");
            }
            other => panic!("unexpected interface config: {other:?}"),
        }
    }

    #[test]
    fn parse_kiss_interface_with_python_defaults() {
        // like a converted Python config: only the port is mandatory
        let config: Config = toml::from_str(
            r#"
[[interfaces]]
name = "Radio"
type = "KISSInterface"
port = "/dev/ttyUSB0"
"#,
        )
        .unwrap();

        let NamedInterface { config, .. } = config.interfaces.into_iter().next().unwrap();
        match config {
            InterfaceConfig::KISSInterface {
                enabled,
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
            } => {
                assert!(enabled);
                assert_eq!(port, "/dev/ttyUSB0");
                // Python constructor defaults (KISSInterface.py)
                assert_eq!(speed, 9600);
                assert_eq!(databits, 8);
                assert_eq!(parity, "N");
                assert_eq!(stopbits, 1);
                assert_eq!(preamble, 350);
                assert_eq!(txtail, 20);
                assert_eq!(persistence, 64);
                assert_eq!(slottime, 20);
                assert!(!flow_control);
            }
            other => panic!("unexpected interface config: {other:?}"),
        }
    }

    #[test]
    fn parse_ax25_and_serial_interfaces() {
        let config: Config = toml::from_str(
            r#"
[[interfaces]]
name = "AX25 Radio"
type = "AX25KISSInterface"
callsign = "n0call"
ssid = 7
port = "/dev/ttyUSB1"
preamble = 300

[[interfaces]]
name = "Raw Serial"
type = "SerialInterface"
port = "/dev/ttyACM0"
"#,
        )
        .unwrap();

        let mut interfaces = config.interfaces.into_iter();
        match interfaces.next().unwrap().config {
            InterfaceConfig::AX25KISSInterface {
                callsign,
                ssid,
                preamble,
                ..
            } => {
                assert_eq!(callsign, "n0call");
                assert_eq!(ssid, 7);
                assert_eq!(preamble, 300);
            }
            other => panic!("unexpected interface config: {other:?}"),
        }
        match interfaces.next().unwrap().config {
            InterfaceConfig::SerialInterface { port, speed, .. } => {
                assert_eq!(port, "/dev/ttyACM0");
                assert_eq!(speed, 9600);
            }
            other => panic!("unexpected interface config: {other:?}"),
        }
    }

    #[test]
    fn parse_auto_interface_options() {
        let config: Config = toml::from_str(
            r#"
[[interfaces]]
name = "Auto"
type = "AutoInterface"
group_id = "mygroup"
discovery_port = 29720
data_port = 42675
devices = "eth0, wlan0"
ignored_devices = "docker0"
discovery_scope = "site"
multicast_address_type = "permanent"
"#,
        )
        .unwrap();

        let NamedInterface { config, .. } = config.interfaces.into_iter().next().unwrap();
        match config {
            InterfaceConfig::AutoInterface {
                enabled,
                group_id,
                discovery_port,
                data_port,
                discovery_scope,
                multicast_address_type,
                devices,
                ignored_devices,
            } => {
                assert!(enabled);
                assert_eq!(group_id, "mygroup");
                assert_eq!(discovery_port, 29720);
                assert_eq!(data_port, 42675);
                assert_eq!(discovery_scope.as_deref(), Some("site"));
                assert_eq!(multicast_address_type.as_deref(), Some("permanent"));
                assert_eq!(devices.as_deref(), Some("eth0, wlan0"));
                assert_eq!(ignored_devices.as_deref(), Some("docker0"));
            }
            other => panic!("unexpected interface config: {other:?}"),
        }
    }

    #[test]
    fn shared_instance_description_matches_python_address_format() {
        let description = SharedInstanceDescription {
            kind: "domain",
            port: 37428,
            instance_name: "default",
        };
        // LocalInterface.py: f"\0rns/{socket_path}"
        assert!(format!("{description:?}").ends_with("rns/default"));

        let description = SharedInstanceDescription {
            kind: "tcp",
            port: 42840,
            instance_name: "default",
        };
        assert_eq!(format!("{description:?}"), "tcp 127.0.0.1:42840");
    }

    #[test]
    fn management_aliases_and_allowlist_forms_parse() {
        let python: Config = toml::from_str(
            r#"
[reticulum]
enable_remote_management = true
respond_to_probes = true
remote_management_allowed = "00112233445566778899aabbccddeeff, fedcba98765432100123456789abcdef"
"#,
        )
        .unwrap();
        assert!(python.reticulum.remote_management);
        assert!(python.reticulum.probe_destination);
        assert_eq!(python.reticulum.remote_management_allowed.len(), 2);

        let native: Config = toml::from_str(
            r#"
[reticulum]
remote_management = true
probe_destination = true
remote_management_allowed = ["00112233445566778899aabbccddeeff"]
"#,
        )
        .unwrap();
        assert!(native.reticulum.remote_management);
        assert!(native.reticulum.probe_destination);
        assert_eq!(native.reticulum.remote_management_allowed.len(), 1);

        let empty: Config = toml::from_str(
            "[reticulum]\nremote_management = true\nremote_management_allowed = []\n",
        )
        .unwrap();
        assert!(empty.reticulum.remote_management_allowed.is_empty());
    }

    #[test]
    fn i2p_peers_accept_strings_and_arrays() {
        for (peers, expected) in [
            ("\"one, two, ,three\"", vec!["one", "two", "three"]),
            ("[\"one\", \" two \"]", vec!["one", "two"]),
        ] {
            let input = format!(
                "[[interfaces]]\nname = \"i2p\"\ntype = \"I2PInterface\"\npeers = {peers}\n"
            );
            let config: Config = toml::from_str(&input).unwrap();
            match &config.interfaces[0].config {
                InterfaceConfig::I2PInterface { peers, .. } => assert_eq!(peers, &expected),
                other => panic!("unexpected interface: {other:?}"),
            }
        }
    }

    #[test]
    fn python_migration_preserves_complete_string_values_and_lists() {
        let migrated = convert_config(
            r#"
[reticulum]
enable_remote_management = Yes
enable_remote_probe = Yes
remote_management_allowed = 00112233445566778899aabbccddeeff, fedcba98765432100123456789abcdef

[[Pipe With Spaces]]
type = PipeInterface
command = socat TCP:example.com:1234 STDIO # keep this
networkname = private mesh
passphrase = correct horse battery staple
reachable_on = gateway.example:4242

[[I2P]]
type = I2PInterface
sam_address = 127.0.0.1:7656
peers = peer one, peer two

[[Auto]]
type = AutoInterface
group_id = mesh group
discovery_scope = site
multicast_address_type = permanent
devices = eth0, wlan0
ignored_devices = docker0, veth0

[[RNode]]
type = RNodeInterface
port = tcp://127.0.0.1:7633
frequency = 867500000
bandwidth = 125000
txpower = 13
spreadingfactor = 9
codingrate = 5
"#,
        );

        assert!(migrated.contains(
            "command = \"socat TCP:example.com:1234 STDIO\" # keep this"
        ));
        let config: Config = toml::from_str(&migrated).expect("migrated Config");
        assert!(config.reticulum.remote_management);
        assert!(config.reticulum.probe_destination);
        assert_eq!(config.reticulum.remote_management_allowed.len(), 2);
        assert_eq!(config.interfaces.len(), 4);

        match &config.interfaces[0].config {
            InterfaceConfig::PipeInterface { command, .. } => {
                assert_eq!(command, "socat TCP:example.com:1234 STDIO")
            }
            other => panic!("unexpected interface: {other:?}"),
        }
        match &config.interfaces[1].config {
            InterfaceConfig::I2PInterface { peers, sam_address, .. } => {
                assert_eq!(peers, &["peer one", "peer two"]);
                assert_eq!(sam_address.as_deref(), Some("127.0.0.1:7656"));
            }
            other => panic!("unexpected interface: {other:?}"),
        }
    }

    #[test]
    fn config_rejects_ifac_sizes_above_ed25519_signature_length() {
        let dir = std::env::temp_dir().join(format!(
            "reticulum-config-ifac-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config.toml"),
            r#"
[[interfaces]]
name = "too-large"
type = "UDPInterface"
listen_ip = "127.0.0.1"
listen_port = 10001
forward_ip = "127.0.0.1"
forward_port = 10002
ifac_size = 513
"#,
        )
        .unwrap();
        assert!(Config::from_file(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
