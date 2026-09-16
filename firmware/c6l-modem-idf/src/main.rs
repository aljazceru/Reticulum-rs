use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver};
use esp_println::println;

fn main() -> anyhow::Result<()> {
    println!("c6l-modem-idf: LoRa RX v3");
    // Run in thread with 64KB stack (main task stack is too small for closures)
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

    // Byte-by-byte SPI (CRITICAL for SX1262!)
    macro_rules! xfer {
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

    println!("SPI ready");

    // === INIT: ALL CONFIG IN STBY_RC, THEN TCXO, THEN RX ===
    // (Writes only work in STBY_RC! TCXO forces STBY_XOSC where writes fail.)
    
    // Phase 1: Configure in STBY_RC (RC oscillator, writes work)
    xfer!(&mut [0x00u8]); // NOP reset
    xfer!(&mut [0x80u8, 0x00]); // SetStandby(STBY_RC)
    
    xfer!(&mut [0x8Au8, 0x01]); // SetPacketType(LoRa)
    // NOTE: SetRfFrequency moved AFTER TCXO (PLL needs TCXO reference!)
    xfer!(&mut [0x8Bu8, 0x09, 0x04, 0x01, 0x00]); // SF9, BW125, CR4/5
    xfer!(&mut [0x8Cu8, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x00]); // PktParams
    xfer!(&mut [0x0Du8, 0x07, 0x40, 0x14, 0x24]); // SyncWord 0x1424
    xfer!(&mut [0x9Du8, 0x01]); // SetDio2AsRfSwitch
    xfer!(&mut [0x08u8, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00]); // IRQ: Preamble|Sync|Header|RxDone|TxDone on DIO1
    xfer!(&mut [0x02u8, 0x03, 0xFF]); // ClearIrqStatus
    
    // Phase 2: Enable TCXO (enters STBY_XOSC)
    xfer!(&mut [0x97u8, 0x01, 0x2C, 0x01, 0x40]); // TCXO 3.0V, 5ms
    std::thread::sleep(std::time::Duration::from_millis(10)); // TCXO settle
    
    // Phase 3: Set frequency NOW (with TCXO as PLL reference!)
    xfer!(&mut [0x86u8, 0x36, 0x38, 0x00, 0x00]); // SetRfFreq(867.5MHz)
    
    // Phase 4: Enter RX mode
    xfer!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]); // SetRx(continuous)
    
    // Verify mode
    let mut st = [0xC0u8, 0x00];
    xfer!(&mut st);
    println!("Mode: {} (5=RX)", (st[0] >> 4) & 0x7);

    println!("=== LISTENING 867.5 MHz BW125 SF9 ===");

    // === RX LOOP (using yield_now, NOT sleep!) ===
    let mut pkt_count = 0u32;
    let mut n: u32 = 0;
    let mut last_telem: u32 = 0;

    loop {
        n += 1;

        // Check DIO1 for RxDone
        if dio1.is_high() {
            let mut irq = [0x12u8, 0x00, 0x00, 0x00];
            xfer!(&mut irq);
            let flags = ((irq[2] as u16) << 8) | irq[3] as u16;

            if flags & 0x0002 != 0 { // RxDone
                let mut rbs = [0x13u8, 0x00, 0x00, 0x00];
                xfer!(&mut rbs);
                let len = rbs[2] as usize;

                if len > 0 && len < 256 {
                    let read_len = len.min(32);
                    let mut pkt = [0u8; 3 + 32];
                    pkt[0] = 0x1E; // ReadBuffer
                    pkt[1] = 0x00; // offset
                    pkt[2] = 0x00; // NOP
                    xfer!(&mut pkt[..3 + read_len]);

                    pkt_count += 1;
                    
                    // Packet status for RSSI/SNR
                    let mut ps = [0x14u8, 0x00, 0x00, 0x00];
                    xfer!(&mut ps);
                    let rssi = -(ps[2] as i16) / 2;
                    let snr = ps[3] as i8;

                    println!("RX #{}: {}B {:02x?} RSSI={}dBm SNR={}dB",
                        pkt_count, len, &pkt[3..3 + read_len], rssi, snr);
                }
            }

            if flags & 0x0040 != 0 {
                println!("CRC ERROR");
            }

            // Clear IRQ and restart RX
            xfer!(&mut [0x02u8, 0x03, 0xFF]);
            xfer!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
        }

        // Telemetry every ~500K iterations (~1 second)
        if n - last_telem > 500_000 {
            last_telem = n;
            println!("TELEM: n={} pkts={} dio1={}", n, pkt_count, if dio1.is_high() { "H" } else { "L" });
        }

        // CRITICAL: yield, don't sleep! (sleep blocks forever in ESP-IDF std)
        if n % 100 == 0 {
            std::thread::yield_now();
        }
    }
}
