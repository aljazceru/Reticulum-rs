use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver};
use esp_println::println;

fn main() -> anyhow::Result<()> {
    println!("c6l-modem-idf: LoRa RX v7 (IRQ polling)");
    let handle = std::thread::Builder::new()
        .stack_size(65536)
        .spawn(|| { if let Err(e) = lora_rx() { println!("Error: {:?}", e); } })
        .unwrap();
    handle.join().unwrap();
    Ok(())
}

fn lora_rx() -> anyhow::Result<()> {
    let peripherals = esp_idf_hal::peripherals::Peripherals::take()?;
    let pins = peripherals.pins;
    let mut cs = esp_idf_hal::gpio::PinDriver::input_output(pins.gpio23, esp_idf_hal::gpio::Pull::Floating)?;
    cs.set_high()?;
    let mut dio1 = esp_idf_hal::gpio::PinDriver::input(pins.gpio7, esp_idf_hal::gpio::Pull::Down)?;

    let mut spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        pins.gpio20,
        pins.gpio21,
        Some(pins.gpio22),
        Option::<esp_idf_hal::gpio::Gpio23>::None,
        &DriverConfig::new(),
        &Config::new().baudrate(2_000_000.into()),
    )?;

    // WRITE: multi-byte single transaction
    macro_rules! cmd {
        ($buf:expr) => {{
            cs.set_low()?;
            let r = spi.transfer_in_place($buf);
            cs.set_high()?;
            r?
        }};
    }

    // READ: byte-by-byte separate transactions
    macro_rules! read {
        ($buf:expr) => {{
            cs.set_low()?;
            let result: Result<(), esp_idf_hal::spi::SpiError> = (|| {
                for i in 0..$buf.len() {
                    let mut byte = [$buf[i]];
                    spi.transfer_in_place(&mut byte)?;
                    $buf[i] = byte[0];
                }
                Ok(())
            })();
            cs.set_high()?;
            result?
        }};
    }

    macro_rules! wait {
        ($c:expr) => { for _ in 0..$c { std::thread::yield_now(); } };
    }

    // Error-safe read (inline, no macro, can't crash the loop)
    macro_rules! read_safe {
        ($buf:expr) => {{
            let _ = cs.set_low();
            for i in 0..$buf.len() {
                let mut b = [$buf[i]];
                if spi.transfer_in_place(&mut b).is_ok() {
                    $buf[i] = b[0];
                }
            }
            let _ = cs.set_high();
        }};
    }

    println!("SPI ready");

    // === INIT — exact RNode firmware sequence (markqvist/RNode_Firmware sx126x.cpp) ===
    read!(&mut [0x00u8]); wait!(5000);  // NOP
    read!(&mut [0x80u8, 0x00]); wait!(5000);  // SetStandby(STBY_RC)

    // Calibrate all (RNode: MASK_CALIBRATE_ALL = 0x7F)
    read!(&mut [0x89u8, 0x7F]); wait!(5000);

    // Image calibration for 863-870 MHz (RNode: 0xD7, 0xDB)
    read!(&mut [0x98u8, 0xD7, 0xDB]); wait!(5000);

    // Enable TCXO 3.0V (M5Stack C6L variant: SX126X_DIO3_TCXO_VOLTAGE 3.0), timeout 0x0000FF
    cmd!(&mut [0x97u8, 0x06, 0x00, 0x00, 0xFF]);
    wait!(50000); // Wait for TCXO to stabilize

    read!(&mut [0x8Au8, 0x01]); wait!(5000);  // SetPacketType(LoRa)
    read!(&mut [0x86u8, 0x36, 0x38, 0x00, 0x00]); wait!(5000);  // SetRfFreq(867.5MHz)

    // RNode sync word: hardcoded [0x14, 0x24] (sx126x.cpp setSyncWord())
    read!(&mut [0x0Du8, 0x07, 0x40, 0x14]); wait!(5000);
    read!(&mut [0x0Du8, 0x07, 0x41, 0x24]); wait!(5000);

    // DIO2 as RF switch (RNode Heltec V3: DIO2_AS_RF_SWITCH = true)
    read!(&mut [0x9Du8, 0x01]); wait!(5000);

    // LNA boost DISABLED — caused constant -73dBm noise floor on C6L
    // (RNode uses it on Heltec but C6L has ESP32-C6 RF leakage too close)

    read!(&mut [0x8Bu8, 0x09, 0x04, 0x01, 0x00]); wait!(5000);  // SetModParams(SF9, BW125, CR4/5, LDRO off)

    // optimizeModemSensitivity (RNode: reg 0x0889 bit 2 SET for BW < 500 kHz)
    // READ-MODIFY-WRITE: preserve other bits!
    let mut ms = [0x1Du8, 0x08, 0x89, 0x00, 0x00];
    read!(&mut ms);
    let ms_val = ms[4];
    read!(&mut [0x0Du8, 0x08, 0x89, ms_val | 0x04]); wait!(5000);
    println!("0x0889: read=0x{:02x} -> write=0x{:02x}", ms_val, ms_val | 0x04);

    // SetPacketParams — RNode sends 9 bytes: preamble=18, explicit, len=255, CRC ON, std IQ
    read!(&mut [0x8Cu8, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00]); wait!(5000);

    // SX1262 errata 15.4: IQ fix must run AFTER EVERY SetPacketParams call!
    // Standard IQ (0x00) -> reg 0x0736 bit 2 SET — READ-MODIFY-WRITE!
    let mut iq2 = [0x1Du8, 0x07, 0x36, 0x00, 0x00];
    read!(&mut iq2);
    let iq2_val = iq2[4];
    read!(&mut [0x0Du8, 0x07, 0x36, iq2_val | 0x04]); wait!(5000);
    println!("0x0736: read=0x{:02x} -> write=0x{:02x}", iq2_val, iq2_val | 0x04);

    // SetPaConfig: PADutyCycle=0x04, HPMax=0x07, DeviceSel=0x00 (SX1262), PALut=0x01
    read!(&mut [0x95u8, 0x04, 0x07, 0x00, 0x01]); wait!(5000);
    // SetTxParams: 14 dBm, ramp 40us
    read!(&mut [0x8Eu8, 0x0E, 0x02]); wait!(5000);
    // OCP 140mA (RNode OCP_TUNED default 0x38 = 140mA)
    read!(&mut [0x0Du8, 0x08, 0xE7, 0x38]); wait!(5000);
    // Tx clamp config errata 15.2: set bits 4-1
    let mut clamp = [0x1Du8, 0x08, 0xD8, 0x00, 0x00];
    read!(&mut clamp);
    read!(&mut [0x0Du8, 0x08, 0xD8, clamp[4] | 0x1E]); wait!(5000);

    // Buffer base addresses TX=0 RX=0
    read!(&mut [0x8Fu8, 0x00, 0x00, 0x00, 0x00]); wait!(5000);

    // SetRegulatorMode DC-DC (opcode 0x96, value 0x01) — power efficiency
    read!(&mut [0x96u8, 0x01]); wait!(5000);

    read!(&mut [0x08u8, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00]); wait!(5000);  // SetDioIrq
    read!(&mut [0x02u8, 0x03, 0xFF]); wait!(5000);  // ClearIrq

    // Verify sync word after full init
    let mut sw = [0x1Du8, 0x07, 0x40, 0x00, 0x00, 0x00];
    read!(&mut sw);
    println!("SyncWord: [{:02x}, {:02x}] (want 14,24)", sw[4], sw[5]);
    
    // SetRx
    cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
    wait!(50000);

    let mut st = [0xC0u8, 0x00];
    read!(&mut st);
    let mode = (st[0] >> 4) & 0x7;
    println!("Mode: {} ({})", mode, if mode == 5 { "RX" } else { "?" });
    println!("=== LISTENING ===");

    // === RX LOOP: poll IRQ status via safe reads ===
    let mut pkt_count = 0u32;
    let mut loop_n: u32 = 0;
    let mut telem_n: u32 = 0;
    let mut rssi_val: i16 = 0;

    loop {
        loop_n += 1;

        // Poll IRQ status every 50000 iterations (~7ms at 7M/sec)
        if loop_n % 50000 == 0 {
            let mut irq = [0x12u8, 0x00, 0x00, 0x00];
            read_safe!(&mut irq);
            let flags = ((irq[2] as u16) << 8) | irq[3] as u16;

            if flags & 0x0002 != 0 { // RxDone!
                // GetRxBufferStatus: [opcode, dummy, dummy, len, rxOffset]
                let mut rbs = [0x13u8, 0x00, 0x00, 0x00, 0x00];
                read_safe!(&mut rbs);
                let len = rbs[3] as usize;
                let rx_off = rbs[4] as usize;

                if len > 0 && len < 256 {
                    let read_len = len.min(64);
                    // ReadBuffer: opcode + 2 dummies + payload
                    let mut pkt = [0u8; 4 + 64];
                    pkt[0] = 0x1E; // ReadBuffer
                    read_safe!(&mut pkt[..4 + read_len]);

                    pkt_count += 1;

                    // GetPacketStatus: [opcode, dummy, rssi, snr]
                    let mut ps = [0x14u8, 0x00, 0x00, 0x00, 0x00];
                    read_safe!(&mut ps);
                    let rssi = -(ps[2] as i16) / 2;
                    let snr = ps[3] as i8;

                    println!("*** RX #{}: len={} off={} rssi={} snr={} ***",
                        pkt_count, len, rx_off, rssi, snr);
                    // Full FIFO dump with positions (read 24 bytes from addr 0)
                    let mut dump = [0x1Eu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    read_safe!(&mut dump);
                    let mut line = String::new();
                    for (i, b) in dump.iter().enumerate().skip(1) {
                        line.push_str(&format!("{:02x} ", b));
                    }
                    println!("FIFO[0..24] from buf[1]: {}", line);
                }

                // Clear IRQ, reset FIFO pointers, restart RX
                cmd!(&mut [0x02u8, 0x03, 0xFF]);
                cmd!(&mut [0x8Fu8, 0x00, 0x00, 0x00, 0x00]);  // SetBufferBaseAddress(0,0)
                cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            } else if flags & 0x0040 != 0 { // CrcError
                println!("CRC ERROR flags={:04x}", flags);
                cmd!(&mut [0x02u8, 0x03, 0xFF]);
                cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            } else if flags != 0 {
                // Log interesting IRQs (PreambleDetected=0x04, SyncWordValid=0x08, HeaderValid=0x10)
                if flags & 0x000C != 0 || flags & 0x0010 != 0 {
                    println!("IRQ {:04x} (pre={:?} sync={:?} hdr={:?})", flags,
                        flags & 0x0004 != 0, flags & 0x0008 != 0, flags & 0x0010 != 0);
                }
                cmd!(&mut [0x02u8, 0x03, 0xFF]);  // clear all latched IRQs
            }

            // DIO1 debug (rate-limited)
            if dio1.is_high() && loop_n % 5000000 == 0 {
                println!("DIO1=HIGH flags={:04x}", flags);
            }
        }

        // Telemetry every ~500000 iterations (~0.7 seconds)
        if loop_n % 500000 == 0 {
            telem_n += 1;
            // Safe RSSI read
            let mut rssi_buf = [0x15u8, 0x00, 0x00, 0x00];
            read_safe!(&mut rssi_buf);
            rssi_val = -(rssi_buf[2] as i16) / 2;
            if telem_n <= 3 {
                println!("RSSI raw bytes: {:02x} {:02x} {:02x} {:02x}",
                    rssi_buf[0], rssi_buf[1], rssi_buf[2], rssi_buf[3]);
            }

            println!("TELEM#{}: pkts={} dio1={} rssi={}", 
                telem_n, pkt_count, if dio1.is_high() { "H" } else { "L" }, rssi_val);
        }

        // Periodic TX every ~10 seconds (100_000_000 iterations at ~10M/sec)
        if loop_n % 100000000 == 0 && loop_n > 0 {
            println!("TX cycle...");
            
            // Go to standby first (byte-by-byte like RNode)
            read!(&mut [0x80u8, 0x00]);
            wait!(10000);

            // SetPacketParams with ACTUAL payload length (1 header + 5 data = 6)
            // RNode wire format: [header(seq<<4), payload...]
            read!(&mut [0x8Cu8, 0x00, 0x12, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00]);
            wait!(5000);
            // re-apply IQ errata fix (SetPacketParams resets reg 0x0736)
            let mut iqt = [0x1Du8, 0x07, 0x36, 0x00, 0x00];
            read!(&mut iqt);
            cmd!(&mut [0x0Du8, 0x07, 0x36, iqt[4] | 0x04]);
            wait!(5000);
            
            // Write RNode-format packet: header byte (seq=1, no split) + HELLO
            read!(&mut [0x0Eu8, 0x00, 0x10, b'H', b'E', b'L', b'L', b'O']);
            wait!(5000);

            // DIAGNOSTIC: read FIFO back to verify the write landed
            {
                let mut chk = [0x1Eu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                read!(&mut chk);
                println!("FIFO check: {:02x?} (want 10 48 45 4c 4c 4f)",
                    &chk[3..9]);
            }
            
            // Set buffer base addresses (TX=0, RX=0)
            read!(&mut [0x8Fu8, 0x00, 0x00, 0x00, 0x00]);
            wait!(5000);
            
            // SetTx(0x000000) = single TX mode, no timeout (exactly like RNode endPacket)
            read!(&mut [0x83u8, 0x00, 0x00, 0x00, 0x00]);
            // Poll for TxDone IRQ with mode diagnostics
            let mut tx_ok = false;
            let mut printed = 0;
            for i in 0..300 {
                let mut ti = [0x12u8, 0x00, 0x00, 0x00];
                read_safe!(&mut ti);
                let tflags = ((ti[2] as u16) << 8) | ti[3] as u16;
                let mut gs = [0xC0u8, 0x00];
                read_safe!(&mut gs);
                let mode = (gs[0] >> 4) & 0x7;
                if i % 50 == 0 && printed < 6 {
                    println!("TX poll: mode={} flags={:04x}", mode, tflags);
                    printed += 1;
                }
                if tflags & 0x0001 != 0 { tx_ok = true; println!("TX poll: TxDone! mode={}", mode); break; }
                if tflags & 0x0004 != 0 { println!("TX poll: TIMEOUT flag mode={}", mode); break; }
                unsafe { esp_idf_sys::vTaskDelay(1); }
            }
            println!("TX done! irq_ok={}", tx_ok);
            
            // Clear IRQ and go back to RX
            cmd!(&mut [0x02u8, 0x03, 0xFF]);
            wait!(5000);
            // restore RX packet params (payload len 255) for RX explicit mode
            cmd!(&mut [0x8Cu8, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00]);
            wait!(5000);
            let mut iqr = [0x1Du8, 0x07, 0x36, 0x00, 0x00];
            read!(&mut iqr);
            cmd!(&mut [0x0Du8, 0x07, 0x36, iqr[4] | 0x04]);
            cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            wait!(10000);
        }
        
        // Yield to IDLE (prevent watchdog)
        if loop_n % 100000 == 0 {
            unsafe { esp_idf_sys::vTaskDelay(1); }
        }
    }
}
