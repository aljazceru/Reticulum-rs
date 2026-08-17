//! Config parity tests (Phase 7.2): unknown keys warn but never fail, and
//! the additional interface types (serial / KISS / pipe / local) parse.

use std::path::PathBuf;

use reticulum_daemon::config::{Config, InterfaceConfig};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rs-rnsd-cfg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn unknown_keys_and_sections_do_not_fail_parsing() {
    let dir = temp_dir("unknown");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[reticulum]
enable_transport = false
instance_name = "test-instance"
completely_unknown_option = "whatever"
storagepath = "/tmp/somewhere"

[logging]
loglevel = "Info"
logdest = "file"

[some_future_section]
key = 1

[[interfaces]]
name = "UDP"
type = "UDPInterface"
listen_ip = "127.0.0.1"
listen_port = 4242
forward_ip = "127.0.0.1"
forward_port = 4243
mode = "gateway"
configured_bitrate = 12000
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("config must parse despite unknown keys");
    assert!(!config.reticulum.enable_transport);
    assert_eq!(config.reticulum.instance_name.as_deref(), Some("test-instance"));
    assert_eq!(config.interfaces.len(), 1);
}

#[test]
fn serial_kiss_pipe_local_interfaces_parse() {
    let dir = temp_dir("ifaces");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[[interfaces]]
name = "Serial"
type = "SerialInterface"
port = "/dev/ttyUSB0"
speed = 57600

[[interfaces]]
name = "KISS"
type = "KISSInterface"
port = "/dev/ttyUSB1"
speed = 115200

[[interfaces]]
name = "Pipe"
type = "PipeInterface"
command = "socat - TCP:localhost:5000"
respawn_delay = 5.5

[[interfaces]]
name = "Local"
type = "LocalInterface"
listen_ip = "127.0.0.1"
listen_port = 37428

[[interfaces]]
name = "FutureThing"
type = "SomeNewInterfaceType"
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("config must parse");
    let kinds: Vec<&str> = config
        .interfaces
        .iter()
        .map(|iface| match &iface.config {
            InterfaceConfig::SerialInterface { .. } => "serial",
            InterfaceConfig::KISSInterface { .. } => "kiss",
            InterfaceConfig::PipeInterface { .. } => "pipe",
            InterfaceConfig::LocalInterface { .. } => "local",
            InterfaceConfig::Unsupported => "unsupported",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, vec!["serial", "kiss", "pipe", "local", "unsupported"]);

    match &config.interfaces[0].config {
        InterfaceConfig::SerialInterface { port, speed, .. } => {
            assert_eq!(port, "/dev/ttyUSB0");
            assert_eq!(*speed, 57600);
        }
        other => panic!("expected serial interface, got {other:?}"),
    }
    match &config.interfaces[2].config {
        InterfaceConfig::PipeInterface { command, respawn_delay, .. } => {
            assert!(command.starts_with("socat"));
            assert_eq!(*respawn_delay, 5.5);
        }
        other => panic!("expected pipe interface, got {other:?}"),
    }
    match &config.interfaces[3].config {
        InterfaceConfig::LocalInterface { listen_ip, listen_port, .. } => {
            assert_eq!(listen_ip, "127.0.0.1");
            assert_eq!(*listen_port, 37428);
        }
        other => panic!("expected local interface, got {other:?}"),
    }
    // Everything defaults to enabled.
    assert!(matches!(
        &config.interfaces[1].config,
        InterfaceConfig::KISSInterface { enabled: true, .. }
    ));
}

#[test]
fn share_instance_port_defaults_match_python() {
    let dir = temp_dir("defaults");
    std::fs::write(dir.join("config.toml"), "[reticulum]\n").unwrap();
    let config = Config::from_file(&dir).expect("parse");
    assert_eq!(config.reticulum.shared_instance_port, 37428);
    assert_eq!(config.reticulum.instance_control_port, 37429);
}
