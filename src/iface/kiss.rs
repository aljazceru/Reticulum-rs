//! KISS serial interfaces, a port of `RNS/Interfaces/KISSInterface.py`
//! (v1.4.2), with AX.25 KISS support from `AX25KISSInterface.py` via
//! [`KissMode::Ax25`] (address encoding lives in [`crate::iface::ax25`]).
//!
//! Wire format (byte-for-byte Python):
//!
//! * data frames: `FEND + 0x00 + escaped(data) + FEND` where `FEND = 0xC0`,
//!   `FESC = 0xDB`, `TFEND = 0xDC`, `TFESC = 0xDD`:
//!   `data.replace(0xDB -> DB DD).replace(0xC0 -> DB DC)` (in this order),
//! * the first byte after `FEND` is the port/TNC command nibble
//!   (`0x00` for data; the port nibble is stripped on receive),
//! * TNC configuration commands (CSMA parameters) are written as
//!   `FEND + CMD + value + FEND` at startup - see [`CsmaParams`].
//!
//! Flow control uses the KISS `CMD_READY` (0x0F) command: after transmitting
//! with flow control enabled the interface waits for a READY frame before
//! sending the next packet, queueing in between (`interface_ready` /
//! `process_queue` in Python).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio_serial::SerialStream;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::iface::ax25;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;

// KISS constants (KISSInterface.py class KISS)
pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_UNKNOWN: u8 = 0xFE;
pub const CMD_DATA: u8 = 0x00;
pub const CMD_TXDELAY: u8 = 0x01;
pub const CMD_P: u8 = 0x02;
pub const CMD_SLOTTIME: u8 = 0x03;
pub const CMD_TXTAIL: u8 = 0x04;
pub const CMD_FULLDUPLEX: u8 = 0x05;
pub const CMD_SETHARDWARE: u8 = 0x06;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_RETURN: u8 = 0xFF;

/// `KISSInterface.HW_MTU`
pub const HW_MTU: usize = 564;

/// CSMA parameters configured on the TNC at startup. These match the
/// `setPreamble`/`setTxTail`/`setPersistence`/`setSlotTime` commands of
/// `KISSInterface.py`: millisecond values are divided by 10 and clamped to
/// one byte before transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsmaParams {
    /// TX preamble length in milliseconds (`preamble`, default 350)
    pub preamble: u32,
    /// TX tail length in milliseconds (`txtail`, default 20)
    pub txtail: u32,
    /// CSMA persistence (`persistence`, default 64)
    pub persistence: u32,
    /// CSMA slot time in milliseconds (`slottime`, default 20)
    pub slottime: u32,
}

impl Default for CsmaParams {
    fn default() -> Self {
        Self {
            preamble: 350,
            txtail: 20,
            persistence: 64,
            slottime: 20,
        }
    }
}

impl CsmaParams {
    pub fn new(preamble: u32, txtail: u32, persistence: u32, slottime: u32) -> Self {
        Self {
            preamble,
            txtail,
            persistence,
            slottime,
        }
    }

    /// All KISS configuration commands for these parameters, in the order
    /// Python sends them (`configure_device`).
    pub fn commands(&self) -> Vec<Vec<u8>> {
        vec![
            set_preamble(self.preamble),
            set_txtail(self.txtail),
            set_persistence(self.persistence),
            set_slottime(self.slottime),
            set_flow_control(true),
        ]
    }
}

/// `FEND + CMD + value + FEND`
fn kiss_command(command: u8, value: u8) -> Vec<u8> {
    vec![FEND, command, value, FEND]
}

/// `setPreamble`: preamble in ms is converted to 10ms units and clamped.
pub fn set_preamble(preamble_ms: u32) -> Vec<u8> {
    kiss_command(CMD_TXDELAY, (preamble_ms / 10).min(255) as u8)
}

/// `setTxTail`: tail in ms is converted to 10ms units and clamped.
pub fn set_txtail(txtail_ms: u32) -> Vec<u8> {
    kiss_command(CMD_TXTAIL, (txtail_ms / 10).min(255) as u8)
}

/// `setPersistence`: persistence is clamped to 0..=255 directly.
pub fn set_persistence(persistence: u32) -> Vec<u8> {
    kiss_command(CMD_P, persistence.min(255) as u8)
}

/// `setSlotTime`: slot time in ms is converted to 10ms units and clamped.
pub fn set_slottime(slottime_ms: u32) -> Vec<u8> {
    kiss_command(CMD_SLOTTIME, (slottime_ms / 10).min(255) as u8)
}

/// `setFlowControl` enables the READY command flow control handshake.
pub fn set_flow_control(enabled: bool) -> Vec<u8> {
    kiss_command(CMD_READY, u8::from(enabled))
}

/// KISS escaping, byte-for-byte `KISS.escape` / `process_outgoing`:
/// `0xDB -> DB DD` first, then `0xC0 -> DB DC`.
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(data.len());
    for &byte in data {
        match byte {
            FESC => escaped.extend_from_slice(&[FESC, TFESC]),
            FEND => escaped.extend_from_slice(&[FESC, TFEND]),
            _ => escaped.push(byte),
        }
    }
    escaped
}

/// Frame `data` as a KISS data frame on port 0:
/// `FEND + 0x00 + escape(data) + FEND` (`process_outgoing`).
pub fn encode_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(data.len() + 4);
    frame.push(FEND);
    frame.push(CMD_DATA);
    frame.extend_from_slice(&escape(data));
    frame.push(FEND);
    frame
}

/// Event emitted by [`KissDecoder`] while feeding raw port bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KissEvent {
    /// A complete data frame (unescaped, port nibble stripped)
    Data(Vec<u8>),
    /// A `CMD_READY` frame was received (flow control release)
    Ready,
}

/// Incremental KISS frame decoder, a byte-for-byte port of the
/// `readLoop` state machine of `KISSInterface.py`:
///
/// * `FEND` starts a frame, the next `FEND` completes it,
/// * the first byte inside a frame is the port/command nibble
///   (`byte & 0x0F`), only `CMD_DATA` frames carry payload,
/// * `FESC TFEND` decodes to `FEND`, `FESC TFESC` decodes to `FESC`,
/// * `CMD_READY` frames release flow control (`process_queue`),
/// * other commands are ignored like in Python.
#[derive(Debug)]
pub struct KissDecoder {
    frame: Vec<u8>,
    in_frame: bool,
    escape: bool,
    command: u8,
    mtu: usize,
}

impl KissDecoder {
    pub fn new(mtu: usize) -> Self {
        Self {
            frame: Vec::new(),
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
            mtu,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<KissEvent> {
        let mut events = Vec::new();

        for &byte in data {
            if self.in_frame && byte == FEND && self.command == CMD_DATA {
                self.in_frame = false;
                self.command = CMD_UNKNOWN;
                self.escape = false;
                events.push(KissEvent::Data(std::mem::take(&mut self.frame)));
            } else if byte == FEND {
                self.in_frame = true;
                self.command = CMD_UNKNOWN;
                self.escape = false;
                self.frame.clear();
            } else if self.in_frame && self.frame.len() < self.mtu {
                if self.frame.is_empty() && self.command == CMD_UNKNOWN {
                    // We only support one HDLC port for now, so
                    // strip off the port nibble
                    self.command = byte & 0x0F;
                } else if self.command == CMD_DATA {
                    if byte == FESC {
                        self.escape = true;
                    } else {
                        let mut byte = byte;
                        if self.escape {
                            if byte == TFEND {
                                byte = FEND;
                            }
                            if byte == TFESC {
                                byte = FESC;
                            }
                            self.escape = false;
                        }
                        self.frame.push(byte);
                    }
                } else if self.command == CMD_READY {
                    events.push(KissEvent::Ready);
                    // ignore the rest of this command frame
                    self.command = CMD_UNKNOWN;
                }
            }
        }

        events
    }
}

/// Serial port configuration (Python constructor defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialPortConfig {
    pub port: String,
    pub speed: u32,
    pub databits: u8,
    pub parity: String,
    pub stopbits: u8,
}

impl SerialPortConfig {
    pub fn new(port: impl Into<String>, speed: u32) -> Self {
        Self {
            port: port.into(),
            speed,
            databits: 8,
            parity: "N".to_string(),
            stopbits: 1,
        }
    }

    pub fn with_format(mut self, databits: u8, parity: impl Into<String>, stopbits: u8) -> Self {
        self.databits = databits;
        self.parity = parity.into();
        self.stopbits = stopbits;
        self
    }

    pub(crate) fn open(&self) -> Result<SerialStream, crate::error::RnsError> {
        super::serial::open_serial_stream(self)
    }
}

/// KISS framing mode: plain KISS or AX.25 KISS with the configured
/// source callsign/SSID (`AX25KISSInterface.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KissMode {
    Kiss,
    Ax25 { callsign: String, ssid: u8 },
}

/// KISS beacon configuration (`id_interval` / `id_callsign`): transmit the
/// callsign padded to 15 bytes `id_interval` seconds after the last start of
/// regular traffic (see the `first_tx` logic in `KISSInterface.readLoop`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissBeacon {
    pub interval: u64,
    pub data: Vec<u8>,
}

/// Shared transmit state: flow-control readiness and the packet queue
/// (Python `interface_ready` / `packet_queue` / `process_queue`).
#[derive(Debug, Default)]
struct TxState {
    ready: bool,
    queue: VecDeque<Vec<u8>>,
}

/// KISS interface over a serial port (plain or AX.25).
pub struct KissInterface {
    mode: KissMode,
    serial: SerialPortConfig,
    csma: CsmaParams,
    flow_control: bool,
    beacon: Option<KissBeacon>,
    stream: Option<SerialStream>,
}

impl KissInterface {
    pub fn new(serial: SerialPortConfig, csma: CsmaParams, flow_control: bool) -> Self {
        Self {
            mode: KissMode::Kiss,
            serial,
            csma,
            flow_control,
            beacon: None,
            stream: None,
        }
    }

    /// AX.25 KISS interface (`AX25KISSInterface.py`): frames are wrapped in
    /// an AX.25 UI header with source `callsign`/`ssid` (upper-cased like
    /// Python) and destination `APZRNS`/0 before KISS escaping.
    pub fn new_ax25(
        callsign: impl Into<String>,
        ssid: u8,
        serial: SerialPortConfig,
        csma: CsmaParams,
        flow_control: bool,
    ) -> Result<Self, crate::error::RnsError> {
        let callsign = callsign.into().to_uppercase();
        ax25::validate_callsign(&callsign, ssid)?;

        Ok(Self {
            mode: KissMode::Ax25 { callsign, ssid },
            serial,
            csma,
            flow_control,
            beacon: None,
            stream: None,
        })
    }

    /// Enable the identification beacon (`id_interval` / `id_callsign`).
    pub fn with_beacon(mut self, interval_secs: u64, data: impl Into<Vec<u8>>) -> Self {
        self.beacon = Some(KissBeacon {
            interval: interval_secs,
            data: data.into(),
        });
        self
    }

    /// Wrap an already opened serial stream (used for tests over a pty pair;
    /// skips the device initialisation delay and never reconnects).
    pub fn from_stream(
        mode: KissMode,
        csma: CsmaParams,
        flow_control: bool,
        stream: SerialStream,
    ) -> Self {
        Self {
            mode,
            serial: SerialPortConfig::new("", 9600),
            csma,
            flow_control,
            beacon: None,
            stream: Some(stream),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();

        let mode = context.inner.lock().unwrap().mode.clone();
        let serial = context.inner.lock().unwrap().serial.clone();
        let csma = context.inner.lock().unwrap().csma;
        let flow_control = context.inner.lock().unwrap().flow_control;
        let beacon = context.inner.lock().unwrap().beacon.clone();
        let mut injected = context.inner.lock().unwrap().stream.take();
        // injected streams are consumed exactly once (test pty pairs)
        let is_injected = injected.is_some();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let tx_state = Arc::new(std::sync::Mutex::new(TxState {
            ready: true,
            queue: VecDeque::new(),
        }));
        let ready_notify = Arc::new(Notify::new());

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let stream = match injected.take() {
                Some(stream) => stream,
                None => match serial.open() {
                    Ok(stream) => {
                        // Allow time for interface to initialise before config
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        stream
                    }
                    Err(_) => {
                        log::warn!(
                            "kiss: couldn't open serial port <{}>, retrying",
                            serial.port
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                },
            };

            log::info!("kiss: serial port <{}> is now open", serial.port);
            stats.set_online(true);

            let (mut read_half, mut write_half) = tokio::io::split(stream);

            // Configure KISS interface parameters
            for command in csma.commands() {
                let _ = write_half.write_all(&command).await;
            }
            let _ = write_half.flush().await;
            log::debug!("kiss: configured csma parameters {:?}", csma);

            let cancel = context.cancel.clone();
            let stop = tokio_util::sync::CancellationToken::new();

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let tx_state = tx_state.clone();
                let ready_notify = ready_notify.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mode = mode.clone();
                let decoder_mtu = match &mode {
                    KissMode::Kiss => HW_MTU,
                    KissMode::Ax25 { .. } => HW_MTU + ax25::HEADER_SIZE,
                };

                tokio::spawn(async move {
                    let mut decoder = KissDecoder::new(decoder_mtu);
                    let mut buffer = [0u8; 4096];

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            result = read_half.read(&mut buffer[..]) => match result {
                                Ok(0) => {
                                    log::warn!("kiss: serial port closed");
                                    stop.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    for event in decoder.feed(&buffer[..n]) {
                                        match event {
                                            KissEvent::Data(frame) => {
                                                let payload = match &mode {
                                                    KissMode::Kiss => Some(frame.clone()),
                                                    KissMode::Ax25 { .. } => {
                                                        ax25::strip_ax25_header(&frame)
                                                            .map(|data| data.to_vec())
                                                    }
                                                };

                                                if let Some(payload) = payload {
                                                    stats.count_rx(frame.len());
                                                    let plain = {
                                                        let ifac = channel_ifac_rx
                                                            .read()
                                                            .expect("ifac lock")
                                                            .clone();
                                                        match crate::iface::ifac::decode(
                                                            &payload,
                                                            ifac.as_deref(),
                                                        ) {
                                                            Some(plain) => plain,
                                                            None => {
                                                                log::debug!("kiss: dropping packet with invalid access code");
                                                                continue;
                                                            }
                                                        }
                                                    };
                                                    match Packet::deserialize(
                                                        &mut InputBuffer::new(&plain[..]),
                                                    ) {
                                                        Ok(packet) => {
                                                            let _ = rx_channel
                                                                .send(RxMessage {
                                                                    address: iface_address,
                                                                    packet,
                                                                })
                                                                .await;
                                                        }
                                                        Err(_) => log::debug!(
                                                            "kiss: couldn't decode packet"
                                                        ),
                                                    }
                                                }
                                            }
                                            KissEvent::Ready => {
                                                // process_queue: release flow control
                                                tx_state.lock().unwrap().ready = true;
                                                ready_notify.notify_one();
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("kiss: serial port error {}", e);
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let tx_state = tx_state.clone();
                let ready_notify = ready_notify.clone();
                let channel_ifac = channel_ifac.clone();
                let beacon = beacon.clone();
                let mode = mode.clone();
                let mut write_half = write_half;

                tokio::spawn(async move {
                    // `first_tx` opens the beacon window (Python readLoop)
                    let mut first_tx: Option<tokio::time::Instant> = None;

                    let encode = |data: &[u8]| match &mode {
                        KissMode::Kiss => encode_frame(data),
                        KissMode::Ax25 { callsign, ssid } => {
                            encode_frame(&ax25::pack_ax25_frame(data, callsign, *ssid))
                        }
                    };

                    /// transmit `data` honouring flow control; returns whether
                    /// the frame was written now (queued otherwise)
                    async fn transmit<W>(
                        write: &mut W,
                        frame: Vec<u8>,
                        payload_len: usize,
                        flow_control: bool,
                        tx_state: &Arc<std::sync::Mutex<TxState>>,
                        stats: &Arc<super::InterfaceCounters>,
                    ) -> bool
                    where
                        W: tokio::io::AsyncWrite + Unpin,
                    {
                        {
                            let mut state = tx_state.lock().unwrap();
                            if !state.ready && flow_control {
                                state.queue.push_back(frame);
                                return false;
                            }
                        }

                        if write.write_all(&frame).await.is_err() {
                            return false;
                        }
                        let _ = write.flush().await;
                        stats.count_tx(payload_len);

                        if flow_control {
                            tx_state.lock().unwrap().ready = false;
                        }

                        true
                    }

                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            // flow control released: send one queued packet
                            _ = ready_notify.notified() => None,
                            message = tx_channel.recv() => Some(message),
                        };

                        let data = match message {
                            Some(Some(message)) => {
                                let packet = message.packet;
                                let mut buffer = [0u8; 2048];
                                let mut output = OutputBuffer::new(&mut buffer[..]);
                                if packet.serialize(&mut output).is_err() {
                                    continue;
                                }
                                let ifac = channel_ifac.read().expect("ifac lock").clone();
                                Some(crate::iface::ifac::encode(
                                    output.as_slice(),
                                    ifac.as_deref(),
                                ))
                            }
                            None | Some(None) => {
                                // process_queue: exactly one queued packet
                                let queued = tx_state.lock().unwrap().queue.pop_front();
                                if let Some(frame) = queued {
                                    let _ = transmit(
                                        &mut write_half,
                                        frame,
                                        0,
                                        flow_control,
                                        &tx_state,
                                        &stats,
                                    )
                                    .await;
                                }
                                None
                            }
                        };

                        // identification beacon window
                        if let Some(beacon) = &beacon {
                            if let Some(started) = first_tx {
                                if tokio::time::Instant::now()
                                    > started + Duration::from_secs(beacon.interval)
                                {
                                    // Pad to minimum length
                                    let mut frame = beacon.data.clone();
                                    while frame.len() < 15 {
                                        frame.push(0x00);
                                    }

                                    let transmitted = transmit(
                                        &mut write_half,
                                        encode(&frame),
                                        frame.len(),
                                        flow_control,
                                        &tx_state,
                                        &stats,
                                    )
                                    .await;

                                    if transmitted {
                                        log::debug!("kiss: transmitted beacon data");
                                        first_tx = None;
                                    }
                                }
                            }
                        }

                        let Some(data) = data else { continue };

                        let transmitted = transmit(
                            &mut write_half,
                            encode(&data),
                            data.len(),
                            flow_control,
                            &tx_state,
                            &stats,
                        )
                        .await;

                        if transmitted {
                            if let Some(beacon) = &beacon {
                                if data != beacon.data && first_tx.is_none() {
                                    first_tx = Some(tokio::time::Instant::now());
                                }
                            }
                        }
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            stats.set_online(false);
            log::warn!("kiss: serial port <{}> closed", serial.port);

            if is_injected {
                break;
            }

            // Reticulum will attempt to reconnect the interface periodically.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for KissInterface {
    fn mtu() -> usize {
        HW_MTU
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_reference() {
        // Python: KISS.escape(bytes([0x7e, 0x7d, 0x01, 0xc0, 0xdb, 0xdc, 0xdd]))
        //       = 7e 7d 01 db dc db dd dc dd
        assert_eq!(
            escape(&[0x7e, 0x7d, 0x01, 0xc0, 0xdb, 0xdc, 0xdd]),
            vec![0x7e, 0x7d, 0x01, 0xdb, 0xdc, 0xdb, 0xdd, 0xdc, 0xdd]
        );
    }

    #[test]
    fn encode_frame_matches_python_reference() {
        // Python: bytes([KISS.FEND])+bytes([0x00])+KISS.escape(data)+bytes([KISS.FEND])
        assert_eq!(
            encode_frame(&[0x7e, 0x7d, 0x01, 0xc0, 0xdb, 0xdc, 0xdd]),
            vec![0xc0, 0x00, 0x7e, 0x7d, 0x01, 0xdb, 0xdc, 0xdb, 0xdd, 0xdc, 0xdd, 0xc0]
        );

        // empty data frame
        assert_eq!(encode_frame(&[]), vec![0xc0, 0x00, 0xc0]);
    }

    #[test]
    fn csma_commands_match_python_reference() {
        // setPreamble(350) -> FEND CMD_TXDELAY 0x23 FEND  (350/10 = 0x23)
        assert_eq!(set_preamble(350), vec![0xc0, 0x01, 0x23, 0xc0]);
        // setPreamble(3000) clamps to 255
        assert_eq!(set_preamble(3000), vec![0xc0, 0x01, 0xff, 0xc0]);
        // setTxTail(20) -> FEND CMD_TXTAIL 0x02 FEND
        assert_eq!(set_txtail(20), vec![0xc0, 0x04, 0x02, 0xc0]);
        // setPersistence(64) -> FEND CMD_P 0x40 FEND
        assert_eq!(set_persistence(64), vec![0xc0, 0x02, 0x40, 0xc0]);
        // setSlotTime(20) -> FEND CMD_SLOTTIME 0x02 FEND
        assert_eq!(set_slottime(20), vec![0xc0, 0x03, 0x02, 0xc0]);
        // setFlowControl -> FEND CMD_READY 0x01 FEND
        assert_eq!(set_flow_control(true), vec![0xc0, 0x0f, 0x01, 0xc0]);
    }

    #[test]
    fn csma_defaults_match_python_reference() {
        assert_eq!(
            CsmaParams::default().commands(),
            vec![
                vec![0xc0, 0x01, 0x23, 0xc0],
                vec![0xc0, 0x04, 0x02, 0xc0],
                vec![0xc0, 0x02, 0x40, 0xc0],
                vec![0xc0, 0x03, 0x02, 0xc0],
                vec![0xc0, 0x0f, 0x01, 0xc0],
            ]
        );
    }

    #[test]
    fn decoder_round_trip() {
        let payload = vec![0x7e, 0x7d, 0xc0, 0xdb, 0x00, 0xff];
        let frame = encode_frame(&payload);

        let mut decoder = KissDecoder::new(HW_MTU);
        // feed in chunks to exercise partial-frame handling
        let mut events = Vec::new();
        for chunk in frame.chunks(3) {
            events.extend(decoder.feed(chunk));
        }

        assert_eq!(events, vec![KissEvent::Data(payload)]);
    }

    #[test]
    fn decoder_strips_port_nibble_and_ignores_other_commands() {
        let mut decoder = KissDecoder::new(HW_MTU);

        // data frame with port nibble 0x05 in the command byte would be
        // command 5 (CMD_FULLDUPLEX) and is ignored
        let not_data = vec![FEND, 0x05, 0x01, 0x02, FEND];
        assert!(decoder.feed(&not_data).is_empty());

        // CMD_READY releases flow control
        let ready = vec![FEND, CMD_READY, 0x01, FEND];
        assert_eq!(decoder.feed(&ready), vec![KissEvent::Ready]);

        // regular data frame on port 0
        let data = encode_frame(&[0xaa, 0xbb]);
        assert_eq!(decoder.feed(&data), vec![KissEvent::Data(vec![0xaa, 0xbb])]);
    }
}
