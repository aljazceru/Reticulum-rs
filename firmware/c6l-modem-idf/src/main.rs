use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver};
use esp_println::println;

fn main() -> anyhow::Result<()> {
    println!("c6l-modem-idf boot");

    let handle = std::thread::Builder::new()
        .stack_size(32768)
        .spawn(|| {
            if let Err(e) = lora_test() {
                println!("Error: {:?}", e);
            }
        })
        .unwrap();

    handle.join().unwrap();
    Ok(())
}

fn lora_test() -> anyhow::Result<()> {
    let peripherals = esp_idf_hal::peripherals::Peripherals::take()?;
    let pins = peripherals.pins;

    // Deselect SSD1306 OLED (shares SPI bus)
    let mut oled_cs = esp_idf_hal::gpio::PinDriver::input_output(pins.gpio6, esp_idf_hal::gpio::Pull::Floating)?;
    oled_cs.set_high()?;
    let mut oled_dc = esp_idf_hal::gpio::PinDriver::input_output(pins.gpio18, esp_idf_hal::gpio::Pull::Floating)?;
    oled_dc.set_high()?;
    let mut oled_rst = esp_idf_hal::gpio::PinDriver::input_output(pins.gpio15, esp_idf_hal::gpio::Pull::Floating)?;
    oled_rst.set_low()?;

    // Configure DIO1 (IRQ) as input for packet detection
    let mut dio1 = esp_idf_hal::gpio::PinDriver::input(pins.gpio7, esp_idf_hal::gpio::Pull::Down)?;

    // Create SPI
    let mut spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        pins.gpio20,
        pins.gpio21,
        Some(pins.gpio22),
        Some(pins.gpio23),
        &DriverConfig::new(),
        &Config::new().baudrate(2_000_000.into()),
    )?;
    println!("SPI ready");

    // === SX1262 Init Sequence ===
    
    // 1. SetDio3AsTcxoClock(3.0V, 20ms timeout)
    // voltage=300 (10mV units), timeout=0x0500 (15.625us units)
    let tcxo = [0x97u8, 0x01, 0x2C, 0x05, 0x00];
    spi.transfer_in_place(&mut tcxo.clone())?;
    std::thread::sleep(std::time::Duration::from_millis(20));
    println!("TCXO set");

    // 2. SetStandby(STBY_XOSC)
    spi.transfer_in_place(&mut [0x80u8, 0x01])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 3. SetRegulatorMode(DC-DC)
    spi.transfer_in_place(&mut [0x96u8, 0x01])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 4. Calibrate(all)
    spi.transfer_in_place(&mut [0x89u8, 0x7F])?;
    std::thread::sleep(std::time::Duration::from_millis(10));

    // 5. CalibrateImage(863-870 MHz)
    spi.transfer_in_place(&mut [0x98u8, 0xD7, 0xDB])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 6. SetDio2AsRfSwitch(true)
    spi.transfer_in_place(&mut [0x9Du8, 0x01])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 7. SetPacketType(LoRa)
    spi.transfer_in_place(&mut [0x88u8, 0x01])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 8. SetRfFrequency(867.5 MHz)
    let rf: u32 = 909_639_680; // 867.5 MHz
    spi.transfer_in_place(&mut [0x86u8, (rf >> 24) as u8, (rf >> 16) as u8, (rf >> 8) as u8, rf as u8])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 9. SetModulationParams(SF9, BW125k, CR4/5, LDRO=0)
    spi.transfer_in_place(&mut [0x8Bu8, 0x09, 0x04, 0x01, 0x00])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 10. SetPacketParams(preamble=8, explicit header, dynamic len, CRC off, standard IQ)
    spi.transfer_in_place(&mut [0x8Cu8, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x00])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 11. Write sync word 0x1424 (RNode)
    spi.transfer_in_place(&mut [0x0Du8, 0x07, 0x40, 0x14, 0x24])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 12. SetDioIrqParams: enable RxDone|TxDone on DIO1
    spi.transfer_in_place(&mut [0x98u8, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 13. Clear IRQ status
    spi.transfer_in_place(&mut [0x02u8, 0x03, 0xFF])?;
    std::thread::sleep(std::time::Duration::from_millis(5));

    // 14. SetRx(continuous)
    spi.transfer_in_place(&mut [0x82u8, 0xFF, 0xFF, 0xFF])?;
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Verify mode
    let mut status_buf = [0xC0u8, 0x00];
    spi.transfer_in_place(&mut status_buf)?;
    let mode = (status_buf[0] >> 4) & 0x7;
    println!("Radio initialized! mode={} (should be 5=RX)", mode);

    // === Packet Reception Loop ===
    println!("Listening for LoRa packets at 867.5 MHz...");
    
    let mut pkt_count = 0;
    loop {
        // Check DIO1 for RxDone
        if dio1.is_high() {
            // Read IRQ status
            let mut irq_buf = [0x12u8, 0x00, 0x00];
            spi.transfer_in_place(&mut irq_buf)?;
            let irq = ((irq_buf[1] as u16) << 8) | irq_buf[2] as u16;
            
            if irq & 0x0002 != 0 { // RxDone
                // Read packet status for length
                let mut len_buf = [0x13u8, 0x00, 0x00, 0x00];
                spi.transfer_in_place(&mut len_buf)?;
                let len = len_buf[1] as usize;
                
                // Read the packet from the buffer
                if len > 0 && len <= 255 {
                    let mut pkt_buf = vec![0u8; 4 + len];
                    pkt_buf[0] = 0x1E; // ReadBuffer
                    pkt_buf[1] = 0x00; // offset
                    // Rest are NOPs for reading
                    spi.transfer_in_place(&mut pkt_buf)?;
                    
                    // Data starts at pkt_buf[3] (skip status + offset echo)
                    let data = &pkt_buf[3..3 + len.min(pkt_buf.len() - 3)];
                    pkt_count += 1;
                    println!("RX packet #{}: {} bytes: {:02x?}", pkt_count, len, &data[..len.min(16)]);
                }
            }
            
            if irq & 0x0040 != 0 { // CrcError
                println!("CRC error on packet");
            }
            
            // Clear IRQ and restart RX
            spi.transfer_in_place(&mut [0x02u8, 0x03, 0xFF])?;
            spi.transfer_in_place(&mut [0x82u8, 0xFF, 0xFF, 0xFF])?;
        }
        
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
