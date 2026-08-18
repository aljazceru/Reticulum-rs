//! `rnodeconf` — RNode configuration and diagnostics
//! (Python `RNS/Utilities/rnodeconf.py`).
//!
//! This port covers the non-flashing surface: probing a device,
//! displaying firmware/platform/MCU information and validating the
//! current radio configuration against a target. Firmware flashing and
//! EEPROM provisioning require the upstream flashing toolchain
//! (`rnodeconf` 4.5k lines of device bootstrap); keep using the
//! upstream `rnodeconf` for those.

use std::time::Duration;

use reticulum::error::RnsError;
use reticulum::iface::rnode::{
    detect_request, kiss_frame, RnodeLink, RnodeParser, RnodeRadioConfig, RnodeShared,
    CMD_PLATFORM, CMD_STAT_RSSI, CMD_STAT_SNR, DETECT_REQ,
};

/// Where to find the device.
pub enum DeviceTarget {
    Serial { port: String, baudrate: u32 },
    Tcp { addr: String },
}

/// Information gathered from a device probe.
#[derive(Debug, Default)]
pub struct DeviceInfo {
    pub detected: bool,
    pub firmware: Option<(u8, u8)>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
}

/// Probe a device and report its firmware/platform/MCU identity and
/// live radio status (Python `rnodeconf --device-info`).
pub async fn device_info(target: &DeviceTarget) -> Result<DeviceInfo, RnsError> {
    let mut link = match target {
        DeviceTarget::Tcp { addr } => RnodeLink::tcp(addr).await?,
        DeviceTarget::Serial { port, baudrate } => {
            #[cfg(feature = "iface-serial")]
            {
                RnodeLink::serial(port, *baudrate).await?
            }
            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (port, baudrate);
                return Err(RnsError::Unsupported);
            }
        }
    };

    // Drain any pending input from previous sessions so the parser starts
    // on a frame boundary, not mid-stream.
    let drain = tokio::time::Instant::now() + Duration::from_millis(200);
    let mut scratch = [0u8; 4096];
    while tokio::time::Instant::now() < drain {
        match tokio::time::timeout(Duration::from_millis(50), link.read(&mut scratch)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Ask for identity and current stats.
    let mut request = detect_request();
    request.extend_from_slice(&kiss_frame(CMD_STAT_RSSI, &[0x00]));
    request.extend_from_slice(&kiss_frame(CMD_STAT_SNR, &[0x00]));
    link.write(&request).await?;

    let mut parser = RnodeParser::new(false);
    let mut info = DeviceInfo::default();
    let mut buffer = [0u8; 4096];

    let identity_complete = |info: &DeviceInfo| {
        info.detected && info.firmware.is_some() && info.platform.is_some() && info.mcu.is_some()
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            break;
        }

        let read = tokio::time::timeout(Duration::from_secs(2), link.read(&mut buffer)).await;
        let Ok(Ok(read)) = read else { break };
        if read == 0 {
            break;
        }

        parser.feed(&buffer[..read], |event| {
            use reticulum::iface::rnode::RnodeEvent;
            match event {
                RnodeEvent::Detect => info.detected = true,
                RnodeEvent::FirmwareVersion { major, minor } => {
                    info.firmware = Some((major, minor));
                }
                RnodeEvent::Platform(platform) => info.platform = Some(platform),
                RnodeEvent::Mcu(mcu) => info.mcu = Some(mcu),
                RnodeEvent::Status(status) => {
                    if status.rssi.is_some() {
                        info.rssi = status.rssi;
                    }
                    if status.snr.is_some() {
                        info.snr = status.snr;
                    }
                }
                _ => {}
            }
        });

        // Wait for the complete identity (detect/fw/platform/mcu arrive as
        // separate frames; breaking on firmware alone drops the rest).
        if identity_complete(&info) {
            break;
        }
    }

    // Retry the detect burst once if the first was lost.
    if !identity_complete(&info) {
        link.write(&detect_request()).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            let read = tokio::time::timeout(Duration::from_secs(1), link.read(&mut buffer)).await;
            let Ok(Ok(read)) = read else { break };
            if read == 0 {
                break;
            }
            parser.feed(&buffer[..read], |event| {
                use reticulum::iface::rnode::RnodeEvent;
                match event {
                    RnodeEvent::Detect => info.detected = true,
                    RnodeEvent::FirmwareVersion { major, minor } => {
                        info.firmware = Some((major, minor));
                    }
                    RnodeEvent::Platform(platform) => info.platform = Some(platform),
                    RnodeEvent::Mcu(mcu) => info.mcu = Some(mcu),
                    _ => {}
                }
            });
            if identity_complete(&info) {
                break;
            }
        }
    }

    Ok(info)
}

/// Validate the device's current radio configuration against a target
/// (Python `rnodeconf` configuration validation).
pub async fn validate_config(
    target: &DeviceTarget,
    config: &RnodeRadioConfig,
) -> Result<bool, RnsError> {
    let mut link = match target {
        DeviceTarget::Tcp { addr } => RnodeLink::tcp(addr).await?,
        DeviceTarget::Serial { port, baudrate } => {
            #[cfg(feature = "iface-serial")]
            {
                RnodeLink::serial(port, *baudrate).await?
            }
            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (port, baudrate);
                return Err(RnsError::Unsupported);
            }
        }
    };

    let shared = std::sync::Arc::new(std::sync::RwLock::new(RnodeShared::default()));
    let _ = DETECT_REQ;
    let _ = CMD_PLATFORM;
    reticulum::iface::rnode::detect_and_validate(&mut link, config, &shared).await?;
    Ok(true)
}

/// Render device info like the upstream tool.
pub fn render_info(info: &DeviceInfo) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Detected RNode : {}\n",
        if info.detected { "yes" } else { "no" }
    ));

    if let Some((major, minor)) = info.firmware {
        out.push_str(&format!("Firmware       : {major}.{minor}\n"));
    }
    if let Some(platform) = info.platform {
        out.push_str(&format!("Platform       : {platform:#04x}\n"));
    }
    if let Some(mcu) = info.mcu {
        out.push_str(&format!("MCU            : {mcu:#04x}\n"));
    }
    if let Some(rssi) = info.rssi {
        out.push_str(&format!("RSSI           : {rssi} dBm\n"));
    }
    if let Some(snr) = info.snr {
        out.push_str(&format!("SNR            : {snr} dB\n"));
    }

    out
}
