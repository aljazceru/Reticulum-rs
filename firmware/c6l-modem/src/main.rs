//! c6l-modem — RNode-class LoRa modem firmware for the M5Stack Unit C6L
//! (ESP32-C6 + SX1262), with USB-CDC and WiFi-TCP host links.
//!
//! Architecture: dual executor.
//! - Modem (USB + LoRa + sessions) on the INTERRUPT executor (always responsive)
//! - WiFi (association + TCP) on a dedicated THREAD executor

#![no_std]
#![no_main]

extern crate alloc;

use esp_backtrace as _;
use esp_hal::{clock::CpuClock, Config};

mod board;
mod modem_tasks;
mod sessions;
mod sx1262;
mod wifi;

esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn interrupt_ticker() {
    esp_println::println!("INT-TICK: started");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
        esp_println::println!("INT-TICK");
    }
}

#[esp_hal::main]
fn main() -> ! {
    esp_alloc::heap_allocator!(size: 160_000);
    esp_println::println!("c6l-modem boot");

    let config = Config::default().with_cpu_clock(CpuClock::max());
    let peris = esp_hal::init(config);

    let (mut modem_hal, wifi_hal, rtos_hal) = modem_tasks::split(peris);

    // Radio bring-up before the scheduler starts
    {
        let gpio_in: u32 = unsafe { core::ptr::read_volatile(0x6009_103C as *const u32) };
        let bit19 = (gpio_in >> 19) & 1;
        let bit7 = (gpio_in >> 7) & 1;
        let bit22 = (gpio_in >> 22) & 1;
        let bit23 = (gpio_in >> 23) & 1;
        esp_println::println!("GPIO raw: 19(busy)={} 7(irq)={} 22(miso)={} 23(cs)={}", bit19, bit7, bit22, bit23);
    }
    // The SX1262 raises BUSY during its power-on sequence (~ms). Wait for
        // the chip to settle before touching SPI (no RST pin on this board).
        // Scan all GPIO inputs to find which pins are HIGH at boot
        // (BUSY should be LOW when radio is idle; IRQ/DIO1 LOW; CS HIGH)
        let gin: u32 = unsafe { core::ptr::read_volatile(0x6009_103C as *const u32) };
        let mut highs = alloc::string::String::new();
        for bit in 0..=30u32 {
            if (gin >> bit) & 1 == 1 {
                if !highs.is_empty() { highs.push(' '); }
                highs.push_str(&alloc::format!("{}", bit));
            }
        }
        esp_println::println!("GPIO high at boot: [{}]", highs);

        let gpio_out_cs: u32 = unsafe { core::ptr::read_volatile(0x6009_1004 as *const u32) };
        let gpio_en_cs: u32 = unsafe { core::ptr::read_volatile(0x6009_1020 as *const u32) };
        // Also check IO_MUX for GPIO23 (correct base 0x60090000, offset 0x04 + 23*4)
        let iomux_cs: u32 = unsafe { core::ptr::read_volatile(0x60090060 as *const u32) };
        esp_println::println!(
            "CS-hal: out={} en={} iomux={:x} mcu_sel={}",
            (gpio_out_cs >> 23) & 1, (gpio_en_cs >> 23) & 1, iomux_cs, iomux_cs & 0x1F
        );
    {
        let cmd: u32 = unsafe { core::ptr::read_volatile(0x6008_1000 as *const u32) };
        let ctrl: u32 = unsafe { core::ptr::read_volatile(0x6008_1008 as *const u32) };
        let clock: u32 = unsafe { core::ptr::read_volatile(0x6008_100C as *const u32) };
        let user: u32 = unsafe { core::ptr::read_volatile(0x6008_1010 as *const u32) };
        let user1: u32 = unsafe { core::ptr::read_volatile(0x6008_1014 as *const u32) };
        let user2: u32 = unsafe { core::ptr::read_volatile(0x6008_1018 as *const u32) };
        let ms_dlen: u32 = unsafe { core::ptr::read_volatile(0x6008_101C as *const u32) };
        esp_println::println!(
            "SPI-REGS: cmd={:x} ctrl={:x} clk={:x} user={:x} u1={:x} u2={:x} dlen={:x}",
            cmd, ctrl, clock, user, user1, user2, ms_dlen
        );
        // Mode bits in CTRL: C_POL(bit 3?), C_PHASE(bit 2?), wait for actual C6 layout
        // USER: doutdin(bit 6?), usr_miso(bit 28), usr_mosi(bit 27)
    }
        let iomux19: u32 = unsafe { core::ptr::read_volatile(0x60090050 as *const u32) };
        let gpio_in19: u32 = unsafe { core::ptr::read_volatile(0x6009_103C as *const u32) };
        let bit19 = (gpio_in19 >> 19) & 1;
        esp_println::println!(
            "BUSY-19: in={} iomux={:x} wpu={} wpd={}",
            bit19, iomux19, (iomux19 >> 6) & 1, (iomux19 >> 7) & 1
        );
        let gpio_out3: u32 = unsafe { core::ptr::read_volatile(0x6009_1004 as *const u32) };
        let gpio_in3: u32 = unsafe { core::ptr::read_volatile(0x6009_103C as *const u32) };
        let gpio_en3: u32 = unsafe { core::ptr::read_volatile(0x6009_1020 as *const u32) };
        let func23: u32 = unsafe { core::ptr::read_volatile(0x6009_15B0 as *const u32) };
        // GPIO_PIN[n] register: offset 0x74 + n*4 for C6 (pad driver config)
        let pin23: u32 = unsafe { core::ptr::read_volatile((0x6009_1000 + 0x74 + 23 * 4) as *const u32) };
        esp_println::println!(
            "CS-all: out={} in={} en={} func={:x} pin={:x}",
            (gpio_out3 >> 23) & 1, (gpio_in3 >> 23) & 1, (gpio_en3 >> 23) & 1, func23, pin23
        );
        // ESP32-C6 IO_MUX registers: 0x60009000 + gpio_num * 4
        let iomux20: u32 = unsafe { core::ptr::read_volatile((0x60090004 + 20 * 4) as *const u32) };
        let iomux23: u32 = unsafe { core::ptr::read_volatile((0x60090004 + 23 * 4) as *const u32) };
        esp_println::println!("IO_MUX: gpio20={:08x} gpio23={:08x}", iomux20, iomux23);
        {
            let st = modem_hal.radio.get_status_noinit();
            esp_println::println!("pre-init GetStatus: {:x}", st);
        }
        esp_hal::delay::Delay::new().delay_millis(100); // BOOT-DELAY
        match modem_hal.radio.init(&esp_hal::delay::Delay::new()) {
        Ok(()) => {
            esp_println::println!("radio: SX1262 init ok");
            // Post-init SPI register dump
            let user2: u32 = unsafe { core::ptr::read_volatile(0x6008_1010 as *const u32) };
            let dlen2: u32 = unsafe { core::ptr::read_volatile(0x6008_101C as *const u32) };
            let ctrl2: u32 = unsafe { core::ptr::read_volatile(0x6008_1008 as *const u32) };
            let misc: u32 = unsafe { core::ptr::read_volatile(0x6008_1020 as *const u32) };
            let din_mode: u32 = unsafe { core::ptr::read_volatile(0x6008_1024 as *const u32) };
            let din_num: u32 = unsafe { core::ptr::read_volatile(0x6008_1028 as *const u32) };
            let dout_mode: u32 = unsafe { core::ptr::read_volatile(0x6008_102C as *const u32) };
            let w0: u32 = unsafe { core::ptr::read_volatile(0x6008_1058 as *const u32) };
            esp_println::println!("POST-INIT SPI: user={:x} doutdin={} ctrl={:x} misc={:x} din={:x}/{:x} dout={:x} w0={:x}",
                user2, user2 & 1, ctrl2, misc, din_mode, din_num, dout_mode, w0);
        }
        Err(_e) => esp_println::println!("radio: init failed at step, continuing"),
    }

    // Scheduler + embassy time driver
    esp_rtos::start(rtos_hal.timg0_timer, rtos_hal.sw_interrupt0);

    // WiFi bring-up on main thread (blocking calls need thread context)
    let wifi_stack = wifi::bringup(wifi_hal.wifi);

    // INTERRUPT executor: modem (always responsive)
    static IEXEC: static_cell::StaticCell<esp_rtos::embassy::InterruptExecutor<1>> =
        static_cell::StaticCell::new();
    let iexec = IEXEC.init(esp_rtos::embassy::InterruptExecutor::new(
        rtos_hal.sw_interrupt1,
    ));
    let modem_spawner = iexec.start(esp_hal::interrupt::Priority::Priority2);
    modem_spawner.spawn(modem_tasks::modem_task(modem_tasks::SendHal(modem_hal), modem_spawner).unwrap());
    modem_spawner.spawn(interrupt_ticker().unwrap());
    esp_println::println!("stage: modem on interrupt executor");

    // THREAD executor: WiFi (association + TCP)
    if let Some((controller, station)) = wifi_stack {
        static WEXEC: static_cell::StaticCell<esp_rtos::embassy::Executor> =
            static_cell::StaticCell::new();
        let wexec = WEXEC.init(esp_rtos::embassy::Executor::new());
        wexec.spawn("wifi-net", 24 * 1024, 1, move |spawner| {
            spawner.spawn(wifi::wifi_task(controller, station, spawner).unwrap());
        });
    }

    loop {
        esp_rtos::CurrentThreadHandle::get().delay(esp_hal::time::Duration::from_secs(60));
    }
}
