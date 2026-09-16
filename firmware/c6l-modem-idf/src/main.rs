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

    // === INIT ===
    read!(&mut [0x00u8]); wait!(5000);  // NOP
    read!(&mut [0x80u8, 0x00]); wait!(5000);  // SetStandby(STBY_RC)
    
    // Enable TCXO (3.0V, 5ms timeout) — CRITICAL for correct frequency!
    // Without TCXO, internal RC oscillator has ±5% error = ±43 MHz at 867.5 MHz!
    // Using multi-byte write (cmd!) which works for all writes.
    cmd!(&mut [0x97u8, 0x06, 0x00, 0x01, 0x40]); // TCXO 3.0V, delay=320*15.625us=5ms
    wait!(50000); // Wait for TCXO to stabilize
    
    // Verify reads still work after TCXO
    let mut sw_tcxo = [0x1Du8, 0x07, 0x40, 0x00, 0x00, 0x00];
    read!(&mut sw_tcxo);
    println!("After TCXO: [3]={:02x} [4]={:02x} [5]={:02x}", sw_tcxo[3], sw_tcxo[4], sw_tcxo[5]);
    
    read!(&mut [0x8Au8, 0x01]); wait!(5000);  // SetPacketType
    read!(&mut [0x86u8, 0x36, 0x38, 0x00, 0x00]); wait!(5000);  // SetRfFreq(867.5MHz)
    read!(&mut [0x8Bu8, 0x09, 0x04, 0x01, 0x00]); wait!(5000);  // SetModParams
    // IQ COMPENSATION FIX (datasheet section 15.4 — REQUIRED!)
    // Read register 0x0736, set/clear bit 2 based on IQ polarity
    // For STANDARD IQ (0x00): OR with 0x04
    // For INVERTED IQ (0x01): AND with 0xFB
    let mut iq_reg = [0x1Du8, 0x07, 0x36, 0x00, 0x00];
    read!(&mut iq_reg);
    let iq_val = iq_reg[4];
    let fixed_iq = (iq_val | 0x04) as u8;  // Standard IQ fix
    println!("IQ reg 0x0736: read=0x{:02x} -> write=0x{:02x}", iq_val, fixed_iq);
    
    // Write back the fixed IQ register
    read!(&mut [0x0Du8, 0x07, 0x36, fixed_iq]); wait!(5000);
    
    // SetPacketParams with STANDARD IQ (0x00)
    read!(&mut [0x8Cu8, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x00]); wait!(5000);  // PktParams(std IQ)
    // Write RadioLib/RNode private sync word [0x10, 0x20]
    read!(&mut [0x0Du8, 0x07, 0x40, 0x10, 0x20]); wait!(5000);
    read!(&mut [0x9Du8, 0x01]); wait!(5000);  // SetDio2AsRfSwitch
    read!(&mut [0x08u8, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00]); wait!(5000);  // SetDioIrq
    read!(&mut [0x02u8, 0x03, 0xFF]); wait!(5000);  // ClearIrq

    // Full readback diagnostic — print ALL buffer positions
    let mut sw = [0x1Du8, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00];
    read!(&mut sw);
    println!("SyncWord full dump: [0]={:02x} [1]={:02x} [2]={:02x} [3]={:02x} [4]={:02x} [5]={:02x} [6]={:02x} [7]={:02x}",
        sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]);
    // The actual data likely starts at buf[3] (after opcode + 2 addr bytes)

    // Set buffer base addresses (TX=0, RX=0) — CRITICAL for packet reception!
    read!(&mut [0x8Fu8, 0x00, 0x00, 0x00, 0x00]); wait!(5000);
    
    // Set RX gain to boosted mode (improves sensitivity)
    read!(&mut [0x96u8, 0x01]); wait!(5000);  // SetRxGain boosted
    
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
                // Read packet length
                let mut rbs = [0x13u8, 0x00, 0x00, 0x00];
                read_safe!(&mut rbs);
                let len = rbs[2] as usize;

                if len > 0 && len < 256 {
                    let read_len = len.min(64);
                    let mut pkt = [0u8; 3 + 64];
                    pkt[0] = 0x1E; // ReadBuffer
                    pkt[1] = 0x00;
                    pkt[2] = 0x00;
                    read_safe!(&mut pkt[..3 + read_len]);

                    pkt_count += 1;

                    // Read RSSI/SNR
                    let mut ps = [0x14u8, 0x00, 0x00, 0x00];
                    read_safe!(&mut ps);
                    let rssi = -(ps[2] as i16) / 2;
                    let snr = ps[3] as i8;

                    println!("*** RX #{}: {}B {:02x?} RSSI={}dBm SNR={}dB IRQ={:04x} ***",
                        pkt_count, len, &pkt[3..3 + read_len], rssi, snr, flags);
                }

                // Clear IRQ and restart RX (multi-byte writes)
                cmd!(&mut [0x02u8, 0x03, 0xFF]);
                cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            } else if flags & 0x0040 != 0 { // CrcError
                println!("CRC ERROR flags={:04x}", flags);
                cmd!(&mut [0x02u8, 0x03, 0xFF]);
                cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            }

            // Check DIO1 for comparison
            let dio1_state = dio1.is_high();
            if dio1_state {
                println!("DIO1=HIGH flags={:04x}", flags);
            }
        }

        // Telemetry every ~500000 iterations (~0.7 seconds)
        if loop_n % 500000 == 0 {
            telem_n += 1;
            // Safe RSSI read
            let mut rssi_buf = [0x15u8, 0x00, 0x00];
            read_safe!(&mut rssi_buf);
            rssi_val = -(rssi_buf[2] as i16) / 2;

            println!("TELEM#{}: pkts={} dio1={} rssi={}", 
                telem_n, pkt_count, if dio1.is_high() { "H" } else { "L" }, rssi_val);
        }

        // Periodic TX every ~10 seconds (100_000_000 iterations at ~10M/sec)
        if loop_n % 100000000 == 0 && loop_n > 0 {
            println!("TX cycle...");
            
            // Go to standby first
            cmd!(&mut [0x80u8, 0x00]);
            wait!(10000);
            
            // Write HELLO to TX buffer
            let mut wr_buf = [0u8; 7];
            wr_buf[0] = 0x0E; // WriteBuffer
            wr_buf[1] = 0x00; // offset 0
            wr_buf[2] = b'H';
            wr_buf[3] = b'E';
            wr_buf[4] = b'L';
            wr_buf[5] = b'L';
            wr_buf[6] = b'O';
            read!(&mut wr_buf);
            wait!(5000);
            
            // Set TX buffer address
            read!(&mut [0x8Fu8, 0x00, 0x00, 0x00, 0x00]);
            wait!(5000);
            
            // SetTx with 5s timeout
            read!(&mut [0x83u8, 0x00, 0x00, 0x13, 0x88]);
            wait!(50000); // Wait for TX
            
            println!("TX done!");
            
            // Clear IRQ and go back to RX
            read!(&mut [0x02u8, 0x03, 0xFF]);
            wait!(5000);
            cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
            wait!(10000);
        }
        
        // Yield to IDLE (prevent watchdog)
        if loop_n % 100000 == 0 {
            unsafe { esp_idf_sys::vTaskDelay(1); }
        }
    }
}
