//! c6l-modem-idf v2: RNode-compatible KISS modem for the M5Stack Unit C6L.
//!
//! One std thread owns everything (single-radio, half-duplex):
//!   USB-Serial-JTAG <-> rnode-modem-core (KISS protocol) <-> SX1262
//!
//! Radio driver conventions verified on hardware (see TECHNICAL_NOTES.md):
//! - byte-by-byte SPI with CS (GPIO23) held LOW for the whole command
//! - RNode init sequence: calibrate, image-cal, TCXO 3.0V, sync [0x14,0x24],
//!   preamble 18, CRC on, IQ-errata RMW after EVERY SetPacketParams
//! - SetTx(0x000000) single-shot; TX length via SetPacketParams
//! - RNode wire format: [header(seq<<4|flags), payload...]
//! - ReadBuffer data at buf[3]; GetRxBufferStatus len@3 off@4

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver, SpiSingleDeviceDriver};
use esp_println::println;

use rnode_modem_core::frame::FEND;
use rnode_modem_core::modem::Modem;
use rnode_modem_core::protocol::{Protocol, RadioOp};
use rnode_modem_core::radio::RadioParams;
use rnode_modem_core::MCU_ESP32_C6;

use std::sync::atomic::{AtomicBool, Ordering};

static SAW_KISS: AtomicBool = AtomicBool::new(false);

fn main() {
    println!("c6l-modem v2.0 (KISS/RNode)");
    let handle = std::thread::Builder::new()
        .stack_size(65536)
        .spawn(|| {
            if let Err(e) = modem_run() {
                println!("modem error: {:?}", e);
            }
        })
        .unwrap();
    handle.join().unwrap();
}

// ---- Radio driver ----
fn bandwidth_code(bw: u32) -> u8 {
    match bw {
        0..=7_800 => 0x00,
        7_801..=10_400 => 0x08,
        10_401..=15_600 => 0x01,
        15_601..=20_800 => 0x09,
        20_801..=31_250 => 0x02,
        31_251..=41_700 => 0x0A,
        41_701..=62_500 => 0x03,
        62_501..=125_000 => 0x04,
        125_001..=250_000 => 0x05,
        _ => 0x06,
    }
}

fn esp_random() -> u32 {
    unsafe { esp_idf_sys::esp_random() }
}

/// USB-Serial-JTAG direct TX (esp-println's backend for the C6).
/// FIFO 0x6000_F000 (u32 per byte), CONF 0x6000_F004:
/// bit0 write = flush, bit1 clear = FIFO full.
fn usb_write_direct(bytes: &[u8]) {
    const FIFO: *mut u32 = 0x6000_F000 as *mut u32;
    const CONF: *mut u32 = 0x6000_F004 as *mut u32;
    unsafe {
        for &b in bytes {
            let mut timeout = 50_000usize;
            while (CONF.read_volatile() & 0b010) == 0 {
                if timeout == 0 {
                    return; // no host draining — drop the rest
                }
                timeout -= 1;
            }
            FIFO.write_volatile(b as u32);
        }
        CONF.write_volatile(0b001); // flush
    }
}

struct Radio {
    cs: PinDriver<'static, esp_idf_hal::gpio::InputOutput>,
    spi: SpiSingleDeviceDriver<'static>,
    last_params: RadioParams,
}

impl Radio {
    fn cmd(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.cs.set_low()?;
        let r = self.spi.transfer_in_place(buf);
        self.cs.set_high()?;
        r?;
        Ok(())
    }
    fn xfer(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.cs.set_low()?;
        for i in 0..buf.len() {
            let mut b = [buf[i]];
            self.spi.transfer_in_place(&mut b)?;
            buf[i] = b[0];
        }
        self.cs.set_high()?;
        Ok(())
    }
    fn delay_ms(&self, ms: u32) {
        // vTaskDelay takes TICKS (100Hz => 1 tick = 10ms)
        let ticks = (ms / 10).max(1);
        unsafe { esp_idf_sys::vTaskDelay(ticks) }
    }

    /// Full RNode-matching init at the given parameters.
    fn init(&mut self, p: &RadioParams) -> anyhow::Result<()> {
        self.last_params = p.clone();
        let freq = p.frequency.max(1);
        let rf = ((freq as u64) << 25) / 32_000_000;
        let f3 = (rf >> 24) as u8;
        let f2 = ((rf >> 16) & 0xFF) as u8;
        let f1 = ((rf >> 8) & 0xFF) as u8;
        let f0 = (rf & 0xFF) as u8;
        let bw_code = bandwidth_code(p.bandwidth);
        let sf = p.sf.clamp(5, 12);
        let cr = p.cr.clamp(5, 8) - 4;

        self.xfer(&mut [0x00])?; // NOP
        self.delay_ms(2);
        self.xfer(&mut [0x80, 0x00])?; // SetStandby(STBY_RC)
        self.delay_ms(2);
        self.xfer(&mut [0x89, 0x7F])?; // Calibrate all
        self.delay_ms(5);
        // Image calibration 863-870 MHz
        self.xfer(&mut [0x98, 0xD7, 0xDB])?;
        self.delay_ms(5);
        // TCXO 3.0V (C6L variant), timeout 65535*15.625us
        self.cmd(&mut [0x97, 0x06, 0x00, 0x00, 0xFF])?;
        self.delay_ms(50);
        self.xfer(&mut [0x8A, 0x01])?; // SetPacketType(LoRa)
        self.delay_ms(2);
        self.xfer(&mut [0x86, f3, f2, f1, f0])?; // SetRfFrequency
        self.delay_ms(2);
        // RNode sync word [0x14, 0x24]
        self.xfer(&mut [0x0D, 0x07, 0x40, 0x14])?;
        self.xfer(&mut [0x0D, 0x07, 0x41, 0x24])?;
        self.xfer(&mut [0x9D, 0x01])?; // DIO2 as RF switch
        self.xfer(&mut [0x8B, sf, bw_code, cr, 0x00])?; // ModParams (LDRO off)
        self.delay_ms(2);
        // optimizeModemSensitivity: reg 0x0889 bit 2 SET (read-modify-write!)
        let mut ms = [0x1D, 0x08, 0x89, 0x00, 0x00];
        self.xfer(&mut ms)?;
        self.xfer(&mut [0x0D, 0x08, 0x89, ms[4] | 0x04])?;
        // PacketParams: preamble 18, explicit, len 0xFF, CRC on, std IQ (+3 unused)
        self.xfer(&mut [0x8C, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00])?;
        self.delay_ms(2);
        // IQ errata 15.4 (RMW) — SetPacketParams resets this register
        let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
        self.xfer(&mut iq)?;
        self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
        // Buffer base TX=0 RX=0
        self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?;
        // Regulator DC-DC
        self.xfer(&mut [0x96, 0x01])?;
        // PA config: SX1262 high power
        self.xfer(&mut [0x95, 0x04, 0x07, 0x00, 0x01])?;
        // TX power + ramp 40us
        let txp = p.txpower.min(22);
        self.xfer(&mut [0x8E, txp, 0x02])?;
        // OCP 140mA
        self.xfer(&mut [0x0D, 0x08, 0xE7, 0x38])?;
        // TX clamp errata (RMW)
        let mut clamp = [0x1D, 0x08, 0xD8, 0x00, 0x00];
        self.xfer(&mut clamp)?;
        self.xfer(&mut [0x0D, 0x08, 0xD8, clamp[4] | 0x1E])?;
        // IRQ: enable all, route none to DIO1 (we poll)
        self.xfer(&mut [0x08, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00])?;
        self.xfer(&mut [0x02, 0x03, 0xFF])?; // ClearIrq
        if p.radio_on {
            self.start_rx()?;
            // HARDWARE QUIRK (empirical): after a full re-init the RX
            // front end stays dead (RSSI -127, nothing received) until
            // one SetTx->TxDone cycle runs — the trailing start_rx of a
            // transmission is what reliably re-arms reception. Real RNodes
            // mask this because RNS sends its id_callsign packet right
            // after radio-on. Mirror that: one header-only packet per
            // reconfigure.
            self.transmit(&[])?;
        }
        Ok(())
    }

    fn start_rx(&mut self) -> anyhow::Result<()> {
        // RX packet params (payload len 0xFF) + IQ fix, then SetRx continuous
        self.xfer(&mut [0x8C, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00])?;
        let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
        self.xfer(&mut iq)?;
        self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
        self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?; // FIFO pointers 0,0
        self.xfer(&mut [0x02, 0x03, 0xFF])?; // clear latched IRQs
        self.delay_ms(10); // let the chip settle (post-TX shutdown)
        self.cmd(&mut [0x82, 0xFF, 0xFF, 0xFF])?; // SetRx continuous
        Ok(())
    }

    /// Poll IRQ flags; on RxDone read the packet and return it
    /// (RNode header byte stripped).
    fn poll_rx(&mut self, out: &mut Vec<u8>) -> anyhow::Result<bool> {
        let mut irq = [0x12u8, 0x00, 0x00, 0x00];
        self.xfer(&mut irq)?;
        let flags = ((irq[2] as u16) << 8) | irq[3] as u16;
        if flags & 0x0002 == 0 {
            // Do NOT clear latched preamble/header flags here: clearing
            // during an active reception ABORTS the packet (hardware-
            // verified). Latched flags are harmless.
            return Ok(false);
        }
        // GetRxBufferStatus: len@3 (byte-by-byte framing shifts Semtech's
        // nominal len@2 by one — hardware-verified; the @4 slot does NOT
        // hold a usable offset in this framing)
        let mut rbs = [0x13u8, 0x00, 0x00, 0x00, 0x00];
        self.xfer(&mut rbs)?;
        let len = rbs[3] as usize;
        let mut got = false;
        if len > 0 && len < 256 {
            let read_len = len.min(240);
            let mut pkt = [0u8; 4 + 240];
            pkt[0] = 0x1E; // ReadBuffer from FIFO address 0
            self.xfer(&mut pkt[..4 + read_len])?;
            let data = &pkt[3..3 + read_len];
            // RNode wire format: first byte is the header (seq<<4|flags)
            let payload = if data.len() > 1 { &data[1..] } else { &[][..] };
            out.extend_from_slice(payload);
            got = !payload.is_empty();
        }
        // RX-continuous mode AUTO-REARMS after each packet: do NOT issue
        // SetRx/packet-params here — the reconfigure race was dropping
        // ~half of all packets (codex-reviewed). Reset the FIFO pointers
        // so the next packet lands at 0, and clear only the RxDone bit.
        self.cmd(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?; // SetBufferBaseAddress(0,0)
        self.cmd(&mut [0x02, 0x00, 0x02])?; // ClearIrqStatus(RxDone only)
        Ok(got)
    }

    /// Transmit with RNode wire format (header + payload), honoring
    /// split packets for payloads > 254 bytes.
    fn transmit(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        const FLAG_SPLIT: u8 = 0x01;
        const CHUNK: usize = 254; // max payload per LoRa packet

        let mut seq: u8 = 0;
        let chunks: Vec<&[u8]> = if payload.len() <= CHUNK {
            vec![payload]
        } else {
            seq = (esp_random() & 0x0F) as u8;
            vec![&payload[..CHUNK], &payload[CHUNK..]]
        };
        let split = payload.len() > CHUNK;

        for chunk in chunks {
            let header = (seq << 4) | if split { FLAG_SPLIT } else { 0 };
            let total = 1 + chunk.len();
            // standby
            self.xfer(&mut [0x80, 0x00])?;
            self.delay_ms(2);
            // TX packet params with the ACTUAL length
            self.xfer(&mut [
                0x8C, 0x00, 0x12, 0x00, total as u8, 0x01, 0x00, 0x00, 0x00, 0x00,
            ])?;
            let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
            self.xfer(&mut iq)?;
            self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
            // WriteBuffer: opcode + offset + [header, data...]
            let mut wr = [0u8; 2 + 1 + CHUNK];
            wr[0] = 0x0E;
            wr[1] = 0x00;
            wr[2] = header;
            wr[3..3 + chunk.len()].copy_from_slice(chunk);
            self.xfer(&mut wr[..3 + chunk.len()])?;
            self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?;
            // SetTx(0x000000) single-shot (RNode endPacket)
            self.xfer(&mut [0x83, 0x00, 0x00, 0x00, 0x00])?;
            // wait for TxDone (airtime up to ~1.3s at SF12)
            let mut done = false;
            for _ in 0..150 {
                let mut ti = [0x12u8, 0x00, 0x00, 0x00];
                self.xfer(&mut ti)?;
                let tflags = ((ti[2] as u16) << 8) | ti[3] as u16;
                if tflags & 0x0001 != 0 {
                    done = true;
                    break;
                }
                // NOTE: 0x0004 is PreambleDetected (latches under
                // interference) — do NOT treat it as a TX timeout.
                self.delay_ms(10);
            }
            let _ = done;
            self.xfer(&mut [0x02, 0x03, 0xFF])?; // clear IRQs
        }
        // Post-TX restore (codex-reviewed): explicit standby, settle, then
        // a VERIFIED RX entry — SetRx can be silently rejected while the
        // chip is busy, leaving it in standby (the "deaf until TX" bug).
        self.xfer(&mut [0x80, 0x00])?; // SetStandby(STBY_RC)
        self.delay_ms(20);
        for attempt in 0..3 {
            self.start_rx()?;
            self.delay_ms(10);
            let mut st = [0xC0u8, 0x00];
            self.xfer(&mut st)?;
            let mode = (st[0] >> 4) & 0x7;
            if mode == 5 {
                let _ = attempt;
                return Ok(());
            }
            // not in RX — re-issue standby then SetRx again
            self.xfer(&mut [0x80, 0x00])?;
            self.delay_ms(10);
        }
        Ok(())
    }

    /// Read the last packet's RSSI/SNR (GetPacketStatus).
    fn packet_status(&mut self) -> anyhow::Result<(i16, i8)> {
        let mut ps = [0x14u8, 0x00, 0x00, 0x00, 0x00];
        self.xfer(&mut ps)?;
        Ok((-(ps[2] as i16) / 2, ps[3] as i8))
    }
}


fn modem_run() -> anyhow::Result<()> {
    let peripherals = Peripherals::take()?;
    let pins = peripherals.pins;
    let mut cs = PinDriver::input_output(pins.gpio23, esp_idf_hal::gpio::Pull::Floating)?;
    cs.set_high()?;
    let _dio1 = PinDriver::input(pins.gpio7, esp_idf_hal::gpio::Pull::Down)?;
    // NOTE: GPIO19 (SX1262 BUSY) is a flash-shared pin on ESP32-C6. Taking
    // it via the HAL *and* rewriting its IO_MUX register broke the radio
    // RX entirely (hardware-verified) — so we deliberately do NOT touch it.
    // The driver relies on command settle delays instead of BUSY polling.

    let mut spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        pins.gpio20,
        pins.gpio21,
        Some(pins.gpio22),
        Option::<esp_idf_hal::gpio::Gpio23>::None,
        &DriverConfig::new(),
        &Config::new().baudrate(2_000_000.into()),
    )?;



    // ---- Modem core + USB session ----
    let mut params = RadioParams::default();
    params.frequency = 867_500_000;
    params.bandwidth = 125_000;
    params.sf = 9;
    params.cr = 5;
    params.txpower = 14;
    params.radio_on = true;

    let mut radio = Radio { cs, spi, last_params: params.clone() };
    radio.init(&params)?;
    println!("radio up");

    // Install the USB-Serial-JTAG driver (the console output path does NOT
    // install it; read_bytes/write_bytes need the driver's buffers/ISR).
    let mut usb_cfg = esp_idf_sys::usb_serial_jtag_driver_config_t {
        rx_buffer_size: 2048,
        tx_buffer_size: 2048,
    };
    let usb_r = unsafe { esp_idf_sys::usb_serial_jtag_driver_install(&mut usb_cfg) };
    if usb_r != 0 {
        println!("usb driver install failed: {}", usb_r);
        return Err(anyhow::anyhow!("usb_serial_jtag_driver_install: {}", usb_r));
    }
    println!("usb driver ok");

    let mut modem = Modem::new(Protocol::new(MCU_ESP32_C6));
    let usb = modem.add_session();
    let mut tx_buf: Vec<u8> = Vec::new();
    let mut rx_payload: Vec<u8> = Vec::new();

    let mut usb_in = [0u8; 64];
    loop {
        // ---- read host bytes (10 ms timeout tick) ----
        let n = unsafe {
            esp_idf_sys::usb_serial_jtag_read_bytes(
                usb_in.as_mut_ptr() as *mut _,
                usb_in.len() as u32,
                0, // non-blocking: the driver's timeout does not fire
                   // reliably (blocks until data!); poll instead, then
                   // vTaskDelay(1) at the loop tail for cadence.
            )
        };
        if n > 0 {
            let data: &[u8] = &usb_in[..n as usize];
            if !SAW_KISS.load(Ordering::Relaxed) && data.contains(&FEND) {
                SAW_KISS.store(true, Ordering::Relaxed);
            }
            let fed = modem.feed(usb, data);
            for frame in fed.to_sender.iter() {
                tx_buf.extend_from_slice(frame);
            }
            // to_others = fan-out to OTHER host links (WiFi-TCP sessions).
            // With a single USB session there are no others — sending it
            // back would echo the host's own data (not half-duplex!).
            if modem.session_ids().len() > 1 {
                for frame in fed.to_others.iter() {
                    tx_buf.extend_from_slice(frame);
                }
            }
            // Flush replies NOW: RNS validates config echoes within 250ms
            // of sending them; radio re-inits take longer than that.
            if !tx_buf.is_empty() {
                usb_write_direct(&tx_buf);
                tx_buf.clear();
            }
            for op in fed.ops {
                apply_op(&mut radio, &mut modem, &mut params, op)?;
            }
        }

        // ---- poll radio ----
        rx_payload.clear();
        if radio.poll_rx(&mut rx_payload)? {
            let (rssi, snr) = radio.packet_status().unwrap_or((0, 0));
            modem.protocol.stats.rssi = rssi;
            modem.protocol.stats.snr = snr as f32;
            for frame in modem.radio_rx(&rx_payload) {
                tx_buf.extend_from_slice(&frame);
            }
        }

        // ---- write host bytes (direct EP1 FIFO, like esp-println) ----
        if !tx_buf.is_empty() {
            usb_write_direct(&tx_buf);
            tx_buf.clear();
        }

        unsafe { esp_idf_sys::vTaskDelay(1); } // 10ms cadence, feeds the watchdog
    }
}

fn apply_op(
    radio: &mut impl RadioOps,
    _modem: &mut Modem,
    params: &mut RadioParams,
    op: RadioOp,
) -> anyhow::Result<()> {
    match op {
        RadioOp::Configure(p) => {
            *params = p;
            radio.reconfigure(params)?;
        }
        RadioOp::RadioOn => {
            params.radio_on = true;
            radio.reconfigure(params)?;
        }
        RadioOp::RadioOff => {
            params.radio_on = false;
            radio.reconfigure(params)?;
        }
        RadioOp::Transmit(data) => {
            radio.transmit_pub(&data)?;
            _modem.protocol.tx_complete(data.len());
        }
    }
    Ok(())
}

// Small trait indirection so apply_op can live outside modem_run
trait RadioOps {
    fn reconfigure(&mut self, p: &RadioParams) -> anyhow::Result<()>;
    fn transmit_pub(&mut self, data: &[u8]) -> anyhow::Result<()>;
}

impl RadioOps for Radio {
    fn reconfigure(&mut self, p: &RadioParams) -> anyhow::Result<()> {
        self.init(p)
    }
    fn transmit_pub(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.transmit(data)
    }
}

