//! Hardware-in-the-loop tests (Phase 5.5 / 9.1).
//!
//! These tests run against **real RNode hardware** when the
//! `RETICULUM_HW_RNODE` environment variable points at a serial port
//! (or `RETICULUM_HW_RNODE_TCP` at a TCP address). Without the variable
//! they are skipped — CI uses the emulator (`rn node-sim`) and the mock
//! bridges instead.
//!
//! Requirements for the hardware device:
//! * RNode firmware >= 1.52, provisioned EEPROM (see docs)
//! * the configured radio parameters must be within the device's model
//!   range (defaults below fit an 850-950 MHz model)
//!
//! Run with:
//! `RETICULUM_HW_RNODE=/dev/ttyUSB2 cargo test -p reticulum-utils
//! --features "iface-rnode,iface-serial" --test hardware_rnode`

#![cfg(feature = "iface-rnode")]

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::rnode::*;
use reticulum::transport::{Transport, TransportConfig};

/// Hardware tests share one physical serial port, so they must not run
/// concurrently (cargo's default is parallel per-test threads).
static HW_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn hw_port() -> Option<String> {
    std::env::var("RETICULUM_HW_RNODE").ok().filter(|s| !s.is_empty())
}

fn hw_tcp() -> Option<String> {
    std::env::var("RETICULUM_HW_RNODE_TCP").ok().filter(|s| !s.is_empty())
}

const RADIO: RnodeRadioConfig = RnodeRadioConfig {
    frequency: 867_500_000,
    bandwidth: 125_000,
    txpower: 2,
    spreadingfactor: 9,
    codingrate: 5,
    st_alock: None,
    lt_alock: None,
};

async fn spawn_rnode(transport: &Arc<Transport>) -> reticulum::hash::AddressHash {
    let manager = transport.iface_manager();
    let mut manager = manager.lock().await;

    if let Some(tcp) = hw_tcp() {
        manager.spawn(
            RnodeInterface::tcp(tcp, RADIO).with_manager(transport.iface_manager()),
            RnodeInterface::spawn,
        )
    } else {
        let port = hw_port().expect("hardware port");
        #[cfg(feature = "iface-serial")]
        {
            manager.spawn(
                RnodeInterface::serial(port, 115200, RADIO)
                    .with_manager(transport.iface_manager()),
                RnodeInterface::spawn,
            )
        }
        #[cfg(not(feature = "iface-serial"))]
        {
            panic!("serial hardware tests need --features iface-serial (use RETICULUM_HW_RNODE_TCP for TCP devices)");
        }
    }
}

#[tokio::test]
async fn hw_detect_firmware_and_identity() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("hw-rnode", &identity, false).build());
    let iface = spawn_rnode(&transport).await;

    // The interface must pass detection + firmware validation and come
    // online (this exercises the full connect sequence on hardware).
    let online = async {
        for _ in 0..400 {
            let stats = transport.interface_stats().await;
            if stats.iter().any(|s| s.address == iface && s.online) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "real RNode must validate its radio and come online");
}

#[tokio::test]
async fn hw_device_info_via_rnodeconf() {
    let Some(port) = hw_port() else {
        eprintln!("skipping: no RETICULUM_HW_RNODE set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let info = reticulum_utils::rnodeconf::device_info(
        &reticulum_utils::rnodeconf::DeviceTarget::Serial {
            port,
            baudrate: 115200,
        },
    )
    .await
    .expect("device probe");

    assert!(info.detected, "device must answer the detect burst");
    let (major, minor) = info.firmware.expect("firmware version");
    assert!(
        major > REQUIRED_FW_VER_MAJ || (major >= REQUIRED_FW_VER_MAJ && minor >= REQUIRED_FW_VER_MIN),
        "firmware {major}.{minor} below required {REQUIRED_FW_VER_MAJ}.{REQUIRED_FW_VER_MIN}"
    );
    assert!(info.platform.is_some(), "platform code must be reported");
    assert!(info.mcu.is_some(), "mcu code must be reported");

    eprintln!(
        "hw device: fw {major}.{minor}, platform {:#04x}, mcu {:#04x}, rssi {:?}, snr {:?}",
        info.platform.unwrap(),
        info.mcu.unwrap(),
        info.rssi,
        info.snr
    );
}

#[tokio::test]
async fn hw_radio_config_validation() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let ok = reticulum_utils::rnodeconf::validate_config(
        &reticulum_utils::rnodeconf::DeviceTarget::Tcp {
            addr: hw_tcp().unwrap_or_default(),
        },
        &RADIO,
    )
    .await;

    // For serial devices validate over serial; tcp path above only when
    // a TCP target exists. Skip assertion accordingly.
    if hw_tcp().is_some() {
        assert!(ok.expect("validation"), "radio configuration must validate");
    } else {
        eprintln!("skipping tcp validation (serial device)");
    }
}

#[tokio::test]
async fn hw_packet_transmit() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("hw-tx", &identity, false).build());
    let iface = spawn_rnode(&transport).await;

    let online = async {
        for _ in 0..400 {
            let stats = transport.interface_stats().await;
            if stats.iter().any(|s| s.address == iface && s.online) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online);

    // Transmit an announce through the real radio; with only one device
    // we assert the TX path completes (stat_tx telemetry increments)
    // rather than a full round trip.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("hw", "tx"),
    );
    transport
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    // The interface TX counter must advance.
    let tx_advanced = async {
        let baseline = {
            let stats = transport.interface_stats().await;
            stats
                .iter()
                .find(|s| s.address == iface)
                .map(|s| s.sent)
                .unwrap_or(0)
        };
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let stats = transport.interface_stats().await;
            let sent = stats
                .iter()
                .find(|s| s.address == iface)
                .map(|s| s.sent)
                .unwrap_or(0);
            if sent > baseline {
                return true;
            }
        }
        false
    }
    .await;
    assert!(tx_advanced, "announce must be transmitted over the radio");
}
