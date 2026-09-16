use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver};
use esp_println::println;

fn main() -> anyhow::Result<()> {
    println!("c6l-modem-idf: LoRa RX v6 (hybrid SPI)");
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

    // WRITE macro: multi-byte single transaction (works for writes!)
    macro_rules! cmd {
        ($buf:expr) => {{
            cs.set_low()?;
            let r = spi.transfer_in_place($buf);
            cs.set_high()?;
            r?
        }};
    }

    // READ macro: byte-by-byte (works for reads!)
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

    // Busy-wait delay
    macro_rules! wait {
        ($c:expr) => { for _ in 0..$c { std::thread::yield_now(); } };
    }

    println!("SPI ready");

    // === INIT: multi-byte writes ===
    cmd!(&mut [0x00u8]); // NOP
    wait!(5000);
    cmd!(&mut [0x80u8, 0x00]); // SetStandby(STBY_RC)
    wait!(5000);
    cmd!(&mut [0x8Au8, 0x01]); // SetPacketType(LoRa)
    wait!(5000);
    cmd!(&mut [0x86u8, 0x36, 0x38, 0x00, 0x00]); // SetRfFreq(867.5MHz)
    wait!(5000);
    cmd!(&mut [0x8Bu8, 0x09, 0x04, 0x01, 0x00]); // SF9, BW125, CR4/5
    wait!(5000);
    cmd!(&mut [0x8Cu8, 0x00, 0x08, 0x00, 0xFF, 0x01, 0x00]); // PktParams
    wait!(5000);
    cmd!(&mut [0x0Du8, 0x07, 0x40, 0x14, 0x24]); // SyncWord
    wait!(5000);
    cmd!(&mut [0x9Du8, 0x01]); // SetDio2AsRfSwitch
    wait!(5000);
    cmd!(&mut [0x08u8, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00]); // IRQ on DIO1
    wait!(5000);
    cmd!(&mut [0x02u8, 0x03, 0xFF]); // ClearIrqStatus
    wait!(5000);

    // === VERIFY: byte-by-byte reads ===
    let mut sw = [0x1Du8, 0x07, 0x40, 0x00, 0x00];
    read!(&mut sw);
    println!("Sync word: 0x{:02x} (expect 0x14)", sw[4]);

    // === SetRx: multi-byte write ===
    cmd!(&mut [0x82u8, 0xFF, 0xFF, 0xFF]);
    wait!(50000);

    // Verify mode with byte-by-byte read
    let mut st = [0xC0u8, 0x00];
    read!(&mut st);
    let mode = (st[0] >> 4) & 0x7;
    println!("Mode: {} ({})", mode, if mode == 5 { "RX - WORKING!" } else if mode == 2 { "STANDBY" } else { "?" });

    println!("=== LISTENING 867.5 MHz BW125 SF9 ===");

    // === RX LOOP ===
    // SIMPLE LOOP TEST: just counter + vTaskDelay + print
    let mut tick: u32 = 0;
    loop {
        tick += 1;
        if tick % 100000 == 0 {
            println!("TICK {}", tick);
        }
        if tick % 50000 == 0 {
            unsafe { esp_idf_sys::vTaskDelay(1); }
        }
    }
}
