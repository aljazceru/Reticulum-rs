//! RNode interfaces — Python `RNS.Interfaces.RNodeInterface` and
//! `RNodeMultiInterface` parity (Phase 5.5).
//!
//! * [`RnodeInterface`]: one LoRa radio reachable over serial or TCP,
//!   speaking the RNode KISS command protocol: hardware detection
//!   (firmware/platform/MCU), radio configuration (frequency, bandwidth,
//!   TX power, spreading factor, coding rate, airtime locks), radio
//!   state control, flow control (`CMD_READY`) and radio status
//!   telemetry (RSSI, SNR, link quality, airtime).
//! * [`RnodeMultiInterface`]: one multi-band radio exposing up to twelve
//!   virtual ports; each port is spawned as its own interface and
//!   addressed with `CMD_SEL_INT` prefixes and the per-port data
//!   commands.
//!
//! Firmware >= 1.52 is required, validated on connect
//! (Python `REQUIRED_FW_VER_*`).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

// ---------------------------------------------------------------------------
// KISS framing constants (Python RNodeInterface.KISS).
// ---------------------------------------------------------------------------

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_UNKNOWN: u8 = 0xFE;
pub const CMD_DATA: u8 = 0x00;
pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_STAT_CHTM: u8 = 0x25;
pub const CMD_STAT_PHYPRM: u8 = 0x26;
pub const CMD_STAT_BAT: u8 = 0x27;
pub const CMD_STAT_CSMA: u8 = 0x28;
pub const CMD_STAT_TEMP: u8 = 0x29;
pub const CMD_BLINK: u8 = 0x30;
pub const CMD_RANDOM: u8 = 0x40;
pub const CMD_FB_EXT: u8 = 0x41;
pub const CMD_FB_READ: u8 = 0x42;
pub const CMD_FB_WRITE: u8 = 0x43;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_RESET: u8 = 0x55;
pub const CMD_ERROR: u8 = 0x90;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// RSSI is reported as `byte - RSSI_OFFSET` dBm
/// (Python `RSSI_OFFSET`).
pub const RSSI_OFFSET: i16 = 157;

/// Minimum firmware version (Python `REQUIRED_FW_VER_*`).
pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 52;

/// Link-quality scaling (Python `Q_SNR_*`).
pub const Q_SNR_MIN_BASE: f32 = -9.0;
pub const Q_SNR_MAX: f32 = 6.0;
pub const Q_SNR_STEP: f32 = 2.0;

/// RNodeMulti virtual-port selection (Python `CMD_SEL_INT`).
pub const CMD_SEL_INT: u8 = 0x1F;

/// Per-virtual-port data commands, index == vport
/// (Python `CMD_INT{0..11}_DATA`).
pub const CMD_INT_DATA: [u8; 12] = [
    0x00, 0x10, 0x20, 0x70, 0x75, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
];

// ---------------------------------------------------------------------------
// Framing.
// ---------------------------------------------------------------------------

/// KISS escaping (Python `KISS.escape`).
pub fn kiss_escape(data: &[u8], out: &mut Vec<u8>) {
    for &byte in data {
        match byte {
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            _ => out.push(byte),
        }
    }
}

/// Build a command frame: `FEND cmd escaped-payload FEND`.
pub fn kiss_frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![FEND, command];
    kiss_escape(payload, &mut frame);
    frame.push(FEND);
    frame
}

/// The hardware detection request burst
/// (Python `RNodeInterface.detect`).
pub fn detect_request() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kiss_frame(CMD_DETECT, &[DETECT_REQ]));
    out.extend_from_slice(&kiss_frame(CMD_FW_VERSION, &[0x00]));
    out.extend_from_slice(&kiss_frame(CMD_PLATFORM, &[0x00]));
    out.extend_from_slice(&kiss_frame(CMD_MCU, &[0x00]));
    out
}

/// Tell the device the host is leaving (Python `RNodeInterface.leave`).
pub fn leave_request() -> Vec<u8> {
    kiss_frame(CMD_LEAVE, &[0xFF])
}

/// Hard-reset the device (Python `RNodeInterface.hard_reset`).
pub fn reset_request() -> Vec<u8> {
    kiss_frame(CMD_RESET, &[0xF8])
}

/// Radio configuration of one (virtual) interface
/// (Python `RNodeInterface` configuration options).
#[derive(Debug, Clone)]
pub struct RnodeRadioConfig {
    pub frequency: u64,
    pub bandwidth: u32,
    pub txpower: u8,
    pub spreadingfactor: u8,
    pub codingrate: u8,
    /// Short-term airtime lock in percent.
    pub st_alock: Option<f32>,
    /// Long-term airtime lock in percent.
    pub lt_alock: Option<f32>,
}

impl RnodeRadioConfig {
    /// Build the radio configuration command frames in the Python order
    /// (`setFrequency`, `setBandwidth`, `setTXPower`,
    /// `setSpreadingFactor`, `setCodingRate`, airtime locks, radio
    /// state).
    pub fn configuration_frames(&self, radio_state: u8) -> Vec<Vec<u8>> {
        // Python `setFrequency`: four big-endian bytes.
        let mut frames = vec![
            kiss_frame(CMD_FREQUENCY, &(self.frequency as u32).to_be_bytes()),
            kiss_frame(CMD_BANDWIDTH, &self.bandwidth.to_be_bytes()),
            kiss_frame(CMD_TXPOWER, &[self.txpower]),
            kiss_frame(CMD_SF, &[self.spreadingfactor]),
            kiss_frame(CMD_CR, &[self.codingrate]),
        ];

        if let Some(st_alock) = self.st_alock {
            let at = (st_alock * 100.0) as u16;
            frames.push(kiss_frame(CMD_ST_ALOCK, &at.to_be_bytes()));
        }

        if let Some(lt_alock) = self.lt_alock {
            let at = (lt_alock * 100.0) as u16;
            frames.push(kiss_frame(CMD_LT_ALOCK, &at.to_be_bytes()));
        }

        frames.push(kiss_frame(CMD_RADIO_STATE, &[radio_state]));
        frames
    }

    /// Whether the radio state echoed by the device matches this
    /// configuration (Python `validateRadioState`).
    pub fn validate(&self, echoed: &RnodeEchoState) -> Result<(), &'static str> {
        let Some(r_frequency) = echoed.frequency else {
            return Err("device did not report frequency");
        };
        if self.frequency.abs_diff(r_frequency) > 100 {
            return Err("frequency mismatch");
        }
        if Some(self.bandwidth) != echoed.bandwidth {
            return Err("bandwidth mismatch");
        }
        if Some(self.txpower) != echoed.txpower {
            return Err("TX power mismatch");
        }
        if Some(self.spreadingfactor) != echoed.spreadingfactor {
            return Err("spreading factor mismatch");
        }
        if Some(self.codingrate) != echoed.codingrate {
            return Err("coding rate mismatch");
        }
        if Some(RADIO_STATE_ON) != echoed.radio_state {
            return Err("radio state mismatch");
        }
        Ok(())
    }
}

/// Radio state reported back by the device
/// (Python `r_frequency` and friends).
#[derive(Debug, Default, Clone)]
pub struct RnodeEchoState {
    pub frequency: Option<u64>,
    pub bandwidth: Option<u32>,
    pub txpower: Option<u8>,
    pub spreadingfactor: Option<u8>,
    pub codingrate: Option<u8>,
    pub radio_state: Option<u8>,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
}

impl RnodeEchoState {
    fn merge(&mut self, other: RnodeEchoState) {
        if other.frequency.is_some() {
            self.frequency = other.frequency;
        }
        if other.bandwidth.is_some() {
            self.bandwidth = other.bandwidth;
        }
        if other.txpower.is_some() {
            self.txpower = other.txpower;
        }
        if other.spreadingfactor.is_some() {
            self.spreadingfactor = other.spreadingfactor;
        }
        if other.codingrate.is_some() {
            self.codingrate = other.codingrate;
        }
        if other.radio_state.is_some() {
            self.radio_state = other.radio_state;
        }
        if other.st_alock.is_some() {
            self.st_alock = other.st_alock;
        }
        if other.lt_alock.is_some() {
            self.lt_alock = other.lt_alock;
        }
    }
}

/// Live status telemetry of a radio (Python `r_stat_*` fields).
#[derive(Debug, Default, Clone)]
pub struct RnodeStatus {
    pub stat_rx: Option<u32>,
    pub stat_tx: Option<u32>,
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
    /// Derived link quality percentage (Python `r_stat_q`).
    pub quality: Option<f32>,
    pub battery: Option<u16>,
    pub temperature: Option<i16>,
}

impl RnodeStatus {
    /// Link quality from an SNR report
    /// (Python `r_stat_snr` quality computation).
    pub fn quality_for(snr: f32, spreadingfactor: Option<u8>) -> Option<f32> {
        let sf = spreadingfactor?;
        let sfs = sf.saturating_sub(7) as f32;
        let q_min = Q_SNR_MIN_BASE - sfs * Q_SNR_STEP;
        let span = Q_SNR_MAX - q_min;
        Some((((snr - q_min) / span) * 100.0).clamp(0.0, 100.0))
    }
}

/// Events produced by parsing the device byte stream.
#[derive(Debug, Clone)]
pub enum RnodeEvent {
    /// Payload data (CMD_DATA or a per-vport data command).
    Data { vport: Option<u8>, data: Vec<u8> },
    /// A virtual port was selected (RNodeMulti).
    SelectedVport(u8),
    Detect,
    FirmwareVersion { major: u8, minor: u8 },
    Platform(u8),
    Mcu(u8),
    Ready(bool),
    Echo(RnodeEchoState),
    Status(RnodeStatus),
    Error(u8),
    /// Raw random bytes from CMD_RANDOM.
    Random(Vec<u8>),
}

/// Streaming parser for the device byte stream
/// (Python `RNodeInterface.read_loop` / `RNodeMultiInterface.readLoop`
/// state machines).
#[derive(Debug, Default)]
pub struct RnodeParser {
    in_frame: bool,
    escaped: bool,
    command: u8,
    data_buffer: Vec<u8>,
    /// RNodeMulti mode: per-vport data commands are recognised.
    multi: bool,
    /// Last vport reported selected by the device.
    selected_vport: Option<u8>,
}

impl RnodeParser {
    pub fn new(multi: bool) -> Self {
        Self {
            multi,
            ..Default::default()
        }
    }

    fn unescape(&mut self, byte: u8) -> Option<u8> {
        if self.escaped {
            self.escaped = false;
            Some(match byte {
                TFEND => FEND,
                TFESC => FESC,
                _ => byte,
            })
        } else if byte == FESC {
            self.escaped = true;
            None
        } else {
            Some(byte)
        }
    }

    fn vport_of(&self, command: u8) -> Option<u8> {
        if self.multi {
            CMD_INT_DATA.iter().position(|&cmd| cmd == command).map(|v| v as u8)
        } else if command == CMD_DATA {
            Some(0)
        } else {
            None
        }
    }

    /// Feed received bytes, invoking `on_event` for every parsed event.
    pub fn feed(&mut self, bytes: &[u8], mut on_event: impl FnMut(RnodeEvent)) {
        for &byte in bytes {
            if byte == FEND {
                if self.in_frame {
                    self.emit(&mut on_event);
                    self.in_frame = false;
                    self.command = CMD_UNKNOWN;
                } else {
                    self.in_frame = true;
                    self.command = CMD_UNKNOWN;
                    self.data_buffer.clear();
                }
                continue;
            }

            if !self.in_frame {
                continue;
            }

            if self.command == CMD_UNKNOWN && self.data_buffer.is_empty() {
                self.command = byte;
                continue;
            }

            let Some(byte) = self.unescape(byte) else { continue };

            // Bound the accumulating frame: a malicious TCP endpoint can
            // stream unterminated bytes indefinitely (Python caps
            // data_buffer at HW_MTU).
            if self.data_buffer.len() < 2048 {
                self.data_buffer.push(byte);
            }
        }
    }

    fn emit(&mut self, on_event: &mut impl FnMut(RnodeEvent)) {
        let command = self.command;
        let data = std::mem::take(&mut self.data_buffer);

        // vport data commands
        if let Some(vport) = self.vport_of(command) {
            if !data.is_empty() {
                on_event(RnodeEvent::Data {
                    vport: if self.multi { Some(vport) } else { None },
                    data,
                });
            }
            return;
        }

        // RNodeMulti: vport selection acknowledgement
        if self.multi && command == CMD_SEL_INT && data.len() == 1 {
            self.selected_vport = Some(data[0]);
            on_event(RnodeEvent::SelectedVport(data[0]));
            return;
        }

        match command {
            CMD_DETECT if data.first() == Some(&DETECT_RESP) => {
                on_event(RnodeEvent::Detect)
            }
            CMD_FW_VERSION if data.len() >= 2 => on_event(RnodeEvent::FirmwareVersion {
                major: data[0],
                minor: data[1],
            }),
            CMD_PLATFORM if !data.is_empty() => on_event(RnodeEvent::Platform(data[0])),
            CMD_MCU if !data.is_empty() => on_event(RnodeEvent::Mcu(data[0])),
            CMD_READY if !data.is_empty() => on_event(RnodeEvent::Ready(data[0] == 0x01)),
            CMD_FREQUENCY if data.len() >= 4 => on_event(RnodeEvent::Echo(RnodeEchoState {
                frequency: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64),
                ..Default::default()
            })),
            CMD_BANDWIDTH if data.len() >= 4 => on_event(RnodeEvent::Echo(RnodeEchoState {
                bandwidth: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                ..Default::default()
            })),
            CMD_TXPOWER if !data.is_empty() => on_event(RnodeEvent::Echo(RnodeEchoState {
                txpower: Some(data[0]),
                ..Default::default()
            })),
            CMD_SF if !data.is_empty() => on_event(RnodeEvent::Echo(RnodeEchoState {
                spreadingfactor: Some(data[0]),
                ..Default::default()
            })),
            CMD_CR if !data.is_empty() => on_event(RnodeEvent::Echo(RnodeEchoState {
                codingrate: Some(data[0]),
                ..Default::default()
            })),
            CMD_RADIO_STATE if !data.is_empty() => on_event(RnodeEvent::Echo(RnodeEchoState {
                radio_state: Some(data[0]),
                ..Default::default()
            })),
            CMD_ST_ALOCK if data.len() >= 2 => on_event(RnodeEvent::Echo(RnodeEchoState {
                st_alock: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 100.0),
                ..Default::default()
            })),
            CMD_LT_ALOCK if data.len() >= 2 => on_event(RnodeEvent::Echo(RnodeEchoState {
                lt_alock: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 100.0),
                ..Default::default()
            })),
            CMD_STAT_RSSI if !data.is_empty() => on_event(RnodeEvent::Status(RnodeStatus {
                rssi: Some(data[0] as i16 - RSSI_OFFSET),
                ..Default::default()
            })),
            CMD_STAT_SNR if !data.is_empty() => {
                let snr = data[0] as i8 as f32 * 0.25;
                on_event(RnodeEvent::Status(RnodeStatus {
                    snr: Some(snr),
                    ..Default::default()
                }))
            }
            CMD_STAT_RX if data.len() >= 4 => on_event(RnodeEvent::Status(RnodeStatus {
                stat_rx: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                ..Default::default()
            })),
            CMD_STAT_TX if data.len() >= 4 => on_event(RnodeEvent::Status(RnodeStatus {
                stat_tx: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                ..Default::default()
            })),
            CMD_ERROR if !data.is_empty() => on_event(RnodeEvent::Error(data[0])),
            CMD_RANDOM => on_event(RnodeEvent::Random(data)),
            _ => {}
        }
    }
}

/// Shared radio state: validated echo state, telemetry and flow-control
/// readiness.
pub type SharedRnodeState = Arc<std::sync::RwLock<RnodeShared>>;

#[derive(Default)]
pub struct RnodeShared {
    pub echo: RnodeEchoState,
    pub status: RnodeStatus,
    pub firmware: Option<(u8, u8)>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub detected: bool,
    /// Flow control: tx paused until CMD_READY.
    pub interface_ready: bool,
}

async fn wait_for_interface_ready(
    state: &SharedRnodeState,
    cancel: &tokio_util::sync::CancellationToken,
    link_cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    loop {
        if state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .interface_ready
        {
            return true;
        }
        tokio::select! {
            _ = cancel.cancelled() => return false,
            _ = link_cancel.cancelled() => return false,
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
    }
}

fn vport_transmit_frames(index: u8, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (kiss_frame(CMD_SEL_INT, &[index]), kiss_frame(CMD_DATA, data))
}

/// One open link to an RNode device: serial or TCP
/// (Python serial / `use_tcp` modes).
pub struct RnodeLink {
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
}

impl RnodeLink {
    /// Open a serial link.
    ///
    /// USB-serial devices need a moment to release the tty after a
    /// previous close; an immediate reopen can fail with EIO, so the
    /// open is retried briefly.
    #[cfg(feature = "iface-serial")]
    pub async fn serial(port: &str, baudrate: u32) -> Result<Self, RnsError> {
        let builder = tokio_serial::new(port, baudrate);

        let mut last_err = None;
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200 * attempt as u64)).await;
            }
            match tokio_serial::SerialStream::open(&builder) {
                Ok(port) => {
                    let (reader, writer) = tokio::io::split(port);
                    return Ok(Self {
                        reader: Box::new(reader),
                        writer: Box::new(writer),
                    });
                }
                Err(error) => {
                    log::debug!(
                        "rnode: serial open attempt {attempt} on {port} failed: {error}; retrying"
                    );
                    last_err = Some(error);
                }
            }
        }

        let _ = last_err;
        Err(RnsError::ConnectionError)
    }

    /// Open a TCP link (Python `use_tcp`).
    pub async fn tcp(addr: &str) -> Result<Self, RnsError> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        stream.set_nodelay(true).ok();
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), RnsError> {
        self.writer
            .write_all(data)
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        self.writer.flush().await.map_err(|_| RnsError::ConnectionError)
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, RnsError> {
        self.reader.read(buffer).await.map_err(|_| RnsError::ConnectionError)
    }
}

/// Handle detection, firmware validation and radio validation on a link
/// (Python `detect` / `validate_firmware` / `validateRadioState`).
pub async fn detect_and_validate(
    link: &mut RnodeLink,
    config: &RnodeRadioConfig,
    shared: &SharedRnodeState,
) -> Result<(), RnsError> {
    link.write(&detect_request()).await?;

    let mut parser = RnodeParser::new(false);
    let mut buffer = [0u8; 4096];

    // Detection phase: collect detect/fw/platform/mcu responses.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(RnsError::ConnectionError);
        }

        let read = tokio::time::timeout(std::time::Duration::from_secs(2), link.read(&mut buffer))
            .await
            .map_err(|_| RnsError::ConnectionError)?
            .map_err(|_| RnsError::ConnectionError)?;

        if read == 0 {
            return Err(RnsError::ConnectionError);
        }

        let mut firmware_seen = false;
        {
            let shared = shared.clone();
            parser.feed(&buffer[..read], |event| {
                let mut shared = shared.write().unwrap_or_else(|e| e.into_inner());
                match event {
                    RnodeEvent::Detect => shared.detected = true,
                    RnodeEvent::FirmwareVersion { major, minor } => {
                        shared.firmware = Some((major, minor));
                        firmware_seen = true;
                    }
                    RnodeEvent::Platform(platform) => shared.platform = Some(platform),
                    RnodeEvent::Mcu(mcu) => shared.mcu = Some(mcu),
                    _ => {}
                }
            });
        }

        if firmware_seen {
            break;
        }
    }

    // Firmware validation (Python `validate_firmware`).
    let (major, minor) = shared
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .firmware
        .ok_or(RnsError::ConnectionError)?;

    let ok = major > REQUIRED_FW_VER_MAJ
        || (major >= REQUIRED_FW_VER_MAJ && minor >= REQUIRED_FW_VER_MIN);
    if !ok {
        log::error!(
            "rnode: firmware {major}.{minor} too old, at least              {REQUIRED_FW_VER_MAJ}.{REQUIRED_FW_VER_MIN} required"
        );
        return Err(RnsError::Unsupported);
    }

    // Configure the radio, then collect configuration echoes.
    for frame in config.configuration_frames(RADIO_STATE_ON) {
        link.write(&frame).await?;
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let mut collected = RnodeEchoState::default();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            break;
        }

        let read = tokio::time::timeout(std::time::Duration::from_secs(1), link.read(&mut buffer))
            .await;

        let Ok(Ok(read)) = read else { break };
        if read == 0 {
            break;
        }

        parser.feed(&buffer[..read], |event| {
            if let RnodeEvent::Echo(echo) = event {
                collected.merge(echo);
            }
        });

        if config.validate(&collected).is_ok() {
            break;
        }
    }

    config.validate(&collected).map_err(|reason| {
        log::error!("rnode: radio state validation failed: {reason}");
        RnsError::ConnectionError
    })?;

    {
        let mut shared = shared.write().unwrap_or_else(|e| e.into_inner());
        shared.echo = collected;
        shared.interface_ready = true;
    }

    Ok(())
}


// ---------------------------------------------------------------------------
// RNodeInterface: one radio per interface.
// ---------------------------------------------------------------------------

/// The single-radio RNode interface
/// (Python `RNodeInterface`).
pub struct RnodeInterface {
    /// TCP address when `tcp` mode is used.
    pub tcp_addr: Option<String>,
    /// Serial port when serial mode is used (requires `iface-serial`).
    pub serial_port: Option<String>,
    pub baudrate: u32,
    pub config: RnodeRadioConfig,
    /// Require a CMD_READY notification before each transmission.
    pub flow_control: bool,
    /// Interface manager of the owning transport (tunnel synthesis).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
    /// Shared radio state, exposed to embedders for diagnostics.
    pub state: SharedRnodeState,
}

impl RnodeInterface {
    pub fn tcp(addr: impl Into<String>, config: RnodeRadioConfig) -> Self {
        Self {
            tcp_addr: Some(addr.into()),
            serial_port: None,
            baudrate: 115200,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
        }
    }

    #[cfg(feature = "iface-serial")]
    pub fn serial(port: impl Into<String>, baudrate: u32, config: RnodeRadioConfig) -> Self {
        Self {
            tcp_addr: None,
            serial_port: Some(port.into()),
            baudrate,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
        }
    }

    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    pub fn with_flow_control(mut self, flow_control: bool) -> Self {
        self.flow_control = flow_control;
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let inner = context.inner.clone();
        let state = { context.inner.lock().unwrap().state.clone() };
        let (rx_channel, tx_channel) = context.channel.split();
        let rx_channel = Arc::new(tokio::sync::Mutex::new(rx_channel));
        let mut tx_channel_slot = Some(tx_channel);

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let link = {
                let (tcp_addr, serial_port, baudrate) = {
                    let inner = inner.lock().unwrap();
                    (inner.tcp_addr.clone(), inner.serial_port.clone(), inner.baudrate)
                };

                let result = if let Some(addr) = tcp_addr {
                    RnodeLink::tcp(&addr).await
                } else {
                    let _ = (&serial_port, baudrate);
                    #[cfg(feature = "iface-serial")]
                    {
                        match serial_port.as_deref() {
                            Some(port) => RnodeLink::serial(port, baudrate).await,
                            None => Err(RnsError::InvalidArgument),
                        }
                    }
                    #[cfg(not(feature = "iface-serial"))]
                    {
                        Err(RnsError::Unsupported)
                    }
                };

                match result {
                    Ok(link) => link,
                    Err(_) => {
                        log::warn!("rnode: could not open device link, retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            };
            let mut link = link;

            let (config, flow_control) = {
                let inner = context.inner.lock().unwrap();
                (inner.config.clone(), inner.flow_control)
            };

            // Detection + firmware + radio validation
            // (Python connect sequence).
            if let Err(error) = detect_and_validate(&mut link, &config, &state).await {
                log::error!("rnode: device validation failed: {error:?}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            log::info!("rnode: device online and radio configuration validated");
            stats.set_online(true);

            // Tunnel synthesis hook (RNodes participate in tunnel
            // endpoints via wants_tunnel, like Python).
            let manager_of = { inner.lock().unwrap().iface_manager.clone() };
            if let Some(manager) = manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
            }

            let mut writer = link.writer;
            let mut reader = link.reader;
            let link_cancel = tokio_util::sync::CancellationToken::new();

            let rx_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let state = state.clone();

                tokio::spawn(async move {
                    let mut parser = RnodeParser::new(false);
                    let mut buffer = [0u8; 4096];

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
                            result = reader.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    let mut packets: Vec<Vec<u8>> = Vec::new();
                                    parser.feed(&buffer[..n], |event| {
                                        match event {
                                            RnodeEvent::Data { data, .. } => packets.push(data),
                                            RnodeEvent::Ready(ready) => {
                                                state.write().unwrap_or_else(|e| e.into_inner()).interface_ready = ready;
                                            }
                                            RnodeEvent::Status(status) => {
                                                let mut shared = state.write().unwrap_or_else(|e| e.into_inner());
                                                if let Some(rssi) = status.rssi { shared.status.rssi = Some(rssi); }
                                                if let Some(snr) = status.snr {
                                                    shared.status.snr = Some(snr);
                                                    shared.status.quality = RnodeStatus::quality_for(snr, None);
                                                }
                                                if let Some(stat_rx) = status.stat_rx { shared.status.stat_rx = Some(stat_rx); }
                                                if let Some(stat_tx) = status.stat_tx { shared.status.stat_tx = Some(stat_tx); }
                                            }
                                            RnodeEvent::Error(code) => {
                                                log::debug!("rnode: device error code {code:#x}");
                                            }
                                            _ => {}
                                        }
                                    });

                                    let rx_channel = rx_channel.lock().await;
                                    for data in packets {
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&data)) {
                                            stats.count_rx(data.len());
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let state = state.clone();
                let tx_channel = tx_channel_slot.take();

                tokio::spawn(async move {
                    let mut tx_channel = tx_channel?;
                    loop {
                        let mut buffer = [0u8; 2048];

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            message = tx_channel.recv() => match message {
                                Some(message) => message,
                                None => break,
                            },
                        };

                        if flow_control {
                            // Flow control: wait for interface readiness
                            // (Python CMD_READY handling).
                            if !wait_for_interface_ready(&state, &cancel, &link_cancel).await {
                                return Some(tx_channel);
                            }
                        }

                        let packet = message.packet;
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let frame = kiss_frame(CMD_DATA, output.as_slice());
                            if writer.write_all(&frame).await.is_ok()
                                && writer.flush().await.is_ok()
                            {
                                stats.count_tx(output.offset());
                                if flow_control {
                                    state
                                        .write()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .interface_ready = false;
                                }
                            } else {
                                link_cancel.cancel();
                                break;
                            }
                        }
                    }

                    Some(tx_channel)
                })
            };

            let mut rx_task = rx_task;
            let mut tx_task = tx_task;
            let tx_result = tokio::select! {
                _ = &mut rx_task => {
                    link_cancel.cancel();
                    tx_task.await
                }
                result = &mut tx_task => {
                    link_cancel.cancel();
                    let _ = rx_task.await;
                    result
                }
                _ = context.cancel.cancelled() => {
                    link_cancel.cancel();
                    let _ = rx_task.await;
                    tx_task.await
                }
            };
            if let Ok(Some(tx_channel)) = tx_result {
                tx_channel_slot = Some(tx_channel);
            }
            stats.set_online(false);
            if context.cancel.is_cancelled() {
                break;
            }
            log::warn!("rnode: device link lost, reconnecting");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

impl Interface for RnodeInterface {
    fn mtu() -> usize {
        500
    }
}

// ---------------------------------------------------------------------------
// RNodeMultiInterface: virtual ports over one device.
// ---------------------------------------------------------------------------

/// One virtual port of a multi-interface
/// (Python `RNodeMultiInterfacePeer`).
#[derive(Debug, Clone)]
pub struct RnodeVport {
    /// Virtual port index (0..11).
    pub index: u8,
    pub config: RnodeRadioConfig,
}

impl RnodeVport {
    /// The prefixed configuration frames for this port
    /// (Python `FEND SEL_INT idx FEND FEND CMD ... FEND`).
    pub fn configuration_frames(&self, radio_state: u8) -> Vec<Vec<u8>> {
        let prefix = kiss_frame(CMD_SEL_INT, &[self.index]);

        self.config
            .configuration_frames(radio_state)
            .into_iter()
            .map(|frame| {
                let mut out = prefix.clone();
                out.extend_from_slice(&frame);
                out
            })
            .collect()
    }
}

/// The multi-band RNode interface: owns the device and one spawned peer
/// interface per configured virtual port
/// (Python `RNodeMultiInterface`).
pub struct RnodeMultiInterface {
    pub tcp_addr: Option<String>,
    pub serial_port: Option<String>,
    pub baudrate: u32,
    /// Virtual ports to spawn (Python `[[subinterfaces]]`).
    pub vports: Vec<RnodeVport>,
    /// Interface manager: peers are spawned into it.
    pub iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    pub state: SharedRnodeState,
}

impl RnodeMultiInterface {
    pub fn tcp(addr: impl Into<String>, vports: Vec<RnodeVport>, iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        Self {
            tcp_addr: Some(addr.into()),
            serial_port: None,
            baudrate: 115200,
            vports,
            iface_manager,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
        }
    }

    #[cfg(feature = "iface-serial")]
    pub fn serial(port: impl Into<String>, baudrate: u32, vports: Vec<RnodeVport>, iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        Self {
            tcp_addr: None,
            serial_port: Some(port.into()),
            baudrate,
            vports,
            iface_manager,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let inner = context.inner.clone();
        let state = { context.inner.lock().unwrap().state.clone() };
        let (_parent_rx, _parent_tx) = context.channel.split();
        let _ = (_parent_rx, _parent_tx);

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let mut link = {
                let (tcp_addr, serial_port, baudrate) = {
                    let inner = inner.lock().unwrap();
                    (inner.tcp_addr.clone(), inner.serial_port.clone(), inner.baudrate)
                };

                let result = if let Some(addr) = tcp_addr {
                    RnodeLink::tcp(&addr).await
                } else {
                    let _ = (&serial_port, baudrate);
                    #[cfg(feature = "iface-serial")]
                    {
                        match serial_port.as_deref() {
                            Some(port) => RnodeLink::serial(port, baudrate).await,
                            None => Err(RnsError::InvalidArgument),
                        }
                    }
                    #[cfg(not(feature = "iface-serial"))]
                    {
                        Err(RnsError::Unsupported)
                    }
                };

                match result {
                    Ok(link) => link,
                    Err(_) => {
                        log::warn!("rnode_multi: could not open device link, retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            };

            // Detection + firmware validation using the first vport's
            // configuration; radio state per vport is configured below.
            let first_config = {
                let inner = inner.lock().unwrap();
                inner
                    .vports
                    .first()
                    .map(|vport| vport.config.clone())
                    .unwrap_or(RnodeRadioConfig {
                        frequency: 867_500_000,
                        bandwidth: 125_000,
                        txpower: 0,
                        spreadingfactor: 9,
                        codingrate: 5,
                        st_alock: None,
                        lt_alock: None,
                    })
            };

            if let Err(error) = detect_and_validate(&mut link, &first_config, &state).await {
                log::error!("rnode_multi: device validation failed: {error:?}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            // Configure and spawn each virtual port.
            let (vports, iface_manager) = {
                let inner = inner.lock().unwrap();
                (inner.vports.clone(), inner.iface_manager.clone())
            };

            let (vport_tx, vport_rx) = tokio::sync::mpsc::unbounded_channel::<(u8, Vec<u8>)>();
            let inbound: VportInbound =
                Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

            {
                let mut manager = iface_manager.lock().await;
                for vport in &vports {
                    // Per-vport configuration with the SEL_INT prefix.
                    for frame in vport.configuration_frames(RADIO_STATE_ON) {
                        let _ = link.write(&frame).await;
                    }

                    let (peer_in_tx, peer_in_rx) =
                        tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    inbound
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(vport.index, peer_in_tx);

                    let address = manager.spawn(
                        RnodeVportPeer {
                            index: vport.index,
                            outbound: vport_tx.clone(),
                            inbound: Some(peer_in_rx),
                        },
                        RnodeVportPeer::spawn,
                    );

                    // RNodeMulti peers use tunnel endpoints
                    // (Python wants_tunnel on the spawned peers).
                    manager.set_iface_wants_tunnel(&address, true);
                }
            }

            stats.set_online(true);
            log::info!(
                "rnode_multi: device online with {} virtual ports",
                vports.len()
            );
            let link_cancel = tokio_util::sync::CancellationToken::new();

            // Writer pump: vport peers submit packets through the
            // channel; each is framed with its port's data command.
            let writer_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let mut writer = link.writer;
                let mut vport_rx = vport_rx;

                tokio::spawn(async move {
                    loop {
                        let outgoing = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            outgoing = vport_rx.recv() => match outgoing {
                                Some(outgoing) => outgoing,
                                None => break,
                            },
                        };

                        let (index, data) = outgoing;
                        // RNodeMulti selects a virtual interface first; data
                        // itself is always transmitted with the normal data
                        // command. Per-port data commands are receive-only.
                        let (select, frame) = vport_transmit_frames(index, &data);
                        if writer.write_all(&select).await.is_ok()
                            && writer.write_all(&frame).await.is_ok()
                            && writer.flush().await.is_ok()
                        {
                            stats.count_tx(data.len());
                        } else {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            // Reader pump: parse device frames, dispatch data to the
            // spawned vport peers by their data command.
            let reader_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let mut reader = link.reader;
                let state = state.clone();
                let inbound = inbound.clone();

                tokio::spawn(async move {
                    let mut parser = RnodeParser::new(true);
                    let mut buffer = [0u8; 4096];

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
                            result = reader.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    let mut routed: Vec<(Option<u8>, Vec<u8>)> = Vec::new();
                                    parser.feed(&buffer[..n], |event| {
                                        match event {
                                            RnodeEvent::Data { vport, data } => routed.push((vport, data)),
                                            RnodeEvent::SelectedVport(_) => {}
                                            RnodeEvent::Status(status) => {
                                                let mut shared = state.write().unwrap_or_else(|e| e.into_inner());
                                                if let Some(rssi) = status.rssi { shared.status.rssi = Some(rssi); }
                                                if let Some(snr) = status.snr { shared.status.snr = Some(snr); }
                                            }
                                            _ => {}
                                        }
                                    });

                                    for (vport, data) in routed {
                                        if let Some(vport) = vport {
                                            if let Some(sender) = inbound
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .get(&vport)
                                            {
                                                let _ = sender.send(data);
                                            }
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            let mut writer_task = writer_task;
            let mut reader_task = reader_task;
            tokio::select! {
                _ = &mut writer_task => {
                    link_cancel.cancel();
                    let _ = reader_task.await;
                }
                _ = &mut reader_task => {
                    link_cancel.cancel();
                    let _ = writer_task.await;
                }
                _ = context.cancel.cancelled() => {
                    link_cancel.cancel();
                    let _ = writer_task.await;
                    let _ = reader_task.await;
                }
            }
            stats.set_online(false);
            if context.cancel.is_cancelled() {
                break;
            }
            log::warn!("rnode_multi: device link lost, reconnecting");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

impl Interface for RnodeMultiInterface {
    fn mtu() -> usize {
        500
    }
}

/// Inbound data senders by virtual port (parent -> peer).
pub type VportInbound =
    Arc<std::sync::Mutex<std::collections::HashMap<u8, mpsc::UnboundedSender<Vec<u8>>>>>;

/// A spawned virtual-port peer: packets from the parent's device reader
/// arrive on `inbound`, outgoing packets are forwarded to the parent's
/// writer pump (Python `RNodeMultiInterfacePeer`).
pub struct RnodeVportPeer {
    pub index: u8,
    /// Outbound pump to the parent device writer.
    pub outbound: mpsc::UnboundedSender<(u8, Vec<u8>)>,
    /// Inbound data from the parent device reader (taken by the worker).
    pub inbound: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl RnodeVportPeer {
    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();

        let mut inbound = context
            .inner
            .lock()
            .unwrap()
            .inbound
            .take()
            .expect("vport inbound taken once");

        loop {
            // Route both directions without select! to keep the arm
            // types independent.
            tokio::select! {
                biased;

                message = tx_channel.recv() => match message {
                    Some(message) => {
                        let packet = message.packet;
                        let mut buffer = [0u8; 2048];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let (index, outbound) = {
                                let inner = context.inner.lock().unwrap();
                                (inner.index, inner.outbound.clone())
                            };
                            let _ = outbound.send((index, output.as_slice().to_vec()));
                            stats.count_tx(output.offset());
                        }
                        continue;
                    }
                    None => break,
                },

                data = inbound.recv() => match data {
                    Some(data) => {
                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&data)) {
                            stats.count_rx(data.len());
                            let _ = rx_channel
                                .try_send(RxMessage { address: iface_address, packet });
                        }
                        continue;
                    }
                    None => continue,
                },

                _ = context.cancel.cancelled() => break,
            }
        }
    }
}

impl Interface for RnodeVportPeer {
    fn mtu() -> usize {
        500
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_state_and_multi_transmit_frames_match_protocol() {
        assert_eq!(RADIO_STATE_ON, 0x01);
        assert_eq!(RADIO_STATE_OFF, 0x00);

        let (select, data) = vport_transmit_frames(3, b"payload");
        assert_eq!(select, kiss_frame(CMD_SEL_INT, &[3]));
        assert_eq!(data, kiss_frame(CMD_DATA, b"payload"));
        assert_ne!(data, kiss_frame(CMD_INT_DATA[3], b"payload"));
    }

    #[tokio::test]
    async fn flow_control_waits_for_each_ready_event_and_observes_cancellation() {
        let state = Arc::new(std::sync::RwLock::new(RnodeShared::default()));
        let cancel = tokio_util::sync::CancellationToken::new();
        let link_cancel = tokio_util::sync::CancellationToken::new();

        let waiter = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let link_cancel = link_cancel.clone();
            async move { wait_for_interface_ready(&state, &cancel, &link_cancel).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());
        state.write().unwrap().interface_ready = true;
        assert!(waiter.await.unwrap());

        // A successful transmission consumes readiness, so the next one
        // blocks until another CMD_READY. Cancellation must still wake it.
        state.write().unwrap().interface_ready = false;
        let waiter = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let link_cancel = link_cancel.clone();
            async move { wait_for_interface_ready(&state, &cancel, &link_cancel).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());
        link_cancel.cancel();
        assert!(!waiter.await.unwrap());
    }
}
