//! Console output gating: the USB-Serial-JTAG console shares its wire
//! with KISS data. Once the host sends its first FEND byte, any println!
//! corrupts the KISS stream — all diagnostics must go through `clog!`,
//! which silences output after that point.

use std::sync::atomic::{AtomicBool, Ordering};

static SAW_KISS: AtomicBool = AtomicBool::new(false);

/// Mark that KISS traffic has started (first FEND seen on any session).
pub fn mark_kiss() {
    SAW_KISS.store(true, Ordering::Relaxed);
}

/// True while printing to the console is still safe.
pub fn may_log() -> bool {
    !SAW_KISS.load(Ordering::Relaxed)
}

/// `println!` that silences itself once KISS traffic starts.
#[macro_export]
macro_rules! clog {
    ($($arg:tt)*) => {
        if $crate::console::may_log() {
            ::esp_println::println!($($arg)*);
        }
    };
}
