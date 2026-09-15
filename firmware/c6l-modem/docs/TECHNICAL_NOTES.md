# c6l-modem: Technical Documentation

## Overview

The c6l-modem firmware turns the M5Stack Unit C6L (ESP32-C6 + SX1262)
into an RNode-class LoRa modem with USB and WiFi-TCP host links,
driven by the Reticulum-rs Rust SDK.

## Architecture (v0.5 — Single-Thread)

All tasks run on the main RTOS thread's executor. No cross-thread
communication needed.

```
┌─ Main RTOS Thread Executor ────────────────────┐
│                                                │
│  modem_task ─── KISS protocol, LoRa, USB TX   │
│    usb_rx_task ─── dedicated USB reader       │
│    yield_helper ─── forces round-robin        │
│                                                │
│  wifi_task ─── WiFi association + DHCP        │
│    connection_task ─── WiFi event monitor     │
│    net_task ─── smoltcp (10ms re-poll)        │
│    tcp_session ─── per-host KISS over TCP     │
│                                                │
│  Communication: embassy_sync Channel          │
│  (works perfectly within single executor)     │
└────────────────────────────────────────────────┘

Host runs: `nc -l 4990` (or equivalent listener)
Modem reverse-connects to C6L_TCP_HOST:4990
```

## What Works (All Hardware-Verified)

| Feature | Status |
|---------|--------|
| USB KISS modem | ✅ 16/16 protocol acceptance |
| Multi-session stability | ✅ 5/5 reset cycles |
| 115s soak | ✅ 0 failures |
| reticulum-actor end-to-end | ✅ announce over the air |
| WiFi association + DHCP | ✅ IP 192.168.1.233/24 |
| TCP KISS over WiFi | ✅ 7-frame detect burst |
| USB + TCP simultaneously | ✅ both active |

## The Actual Root Cause of the TCP Bug

After extensive debugging (hours of cross-thread investigation), the
TCP data path failure was caused by a **one-line omission** in
`rnode-modem-core/src/modem.rs`:

```rust
// BEFORE: TCP data silently dropped
pub fn feed(&mut self, id: u64, bytes: &[u8]) -> Fed {
    let Some((_, session)) = self.sessions.iter_mut().find(...) else {
        return Fed::empty();  // ← session 2 (TCP) never found!
    };
}

// AFTER: auto-create unknown sessions
pub fn feed(&mut self, id: u64, bytes: &[u8]) -> Fed {
    if !self.sessions.iter().any(|(sid, _)| *sid == id) {
        self.sessions.push((id, Session::new()));
    }
    ...
}
```

TCP sessions registered with the outbound routing registry (for reply
delivery) but were never added to the modem's internal frame parser.
`feed()` returned zero replies, making it appear as if cross-thread
communication was broken. It wasn't — the channel worked fine within
the single-thread executor. The select3 handler received TCP data and
called `feed()`, which returned `Fed{replies: 0}` because session 2
wasn't in the parser list.

## Build System

### Environment Variables (Compile-Time)
```bash
rm -f target/riscv32imac-unknown-none-elf/release/c6l-modem
find src ../patches ../../rnode-modem-core/src -name "*.rs" -exec touch {} \;
C6L_WIFI_SSID="YourNetwork" \
C6L_WIFI_PASS="YourPassword" \
C6L_TCP_HOST="192.168.1.161" \
    cargo build --release
# Verify (cargo doesn't rebuild on env-var changes!)
strings target/.../c6l-modem | grep "YourNetwork"
```

### Dependency Stack
- esp-hal 1.1.2 (unstable)
- esp-rtos 0.3.0 (patched)
- esp-radio 0.18.0
- embassy-executor 0.10 / embassy-net 0.9 (patched)
- opt-level 2 for esp-radio, "s" for app

### Patches Applied

**esp-rtos** (`firmware/patches/esp-rtos/`):
1. Executor poll loop: yields when tasks self-wake during poll
2. ThreadFlag::set(): forced yield on flag-set-without-waiter (race fix)
3. Diagnostic counters (RTOS_DIAG)

**embassy-net** (`firmware/patches/embassy-net/`):
1. `Runner::run()`: timer-based re-poll (10ms) — the esp-radio driver
   never calls the runner's waker on packet arrival
2. Accept instrumentation: logs socket state transitions
3. Driver receive tracking

**rnode-modem-core** (`rnode-modem-core/`):
1. `Modem::feed()`: auto-create sessions for unknown IDs (THE fix)

## Hardware Findings

| # | Finding | Resolution |
|---|---------|-----------|
| 1 | esp-radio driver never calls runner's waker | Timer re-poll (10ms) |
| 2 | esp-radio driver drops incoming TCP SYNs | Reverse-connect mode |
| 3 | esp_println deadlocks at interrupt priority | Avoid prints in ISR |
| 4 | logq static must be `static mut` | Fixed |
| 5 | Session IDs from add_session() start at 1 | Runtime USB_SID |
| 6 | Cargo doesn't rebuild on env-var changes | Documented workaround |
| 7 | StaticCell::init() panics on double-init | Direct static registry |
| 8 | select3 cancels in-flight async reads | Dedicated usb_rx_task |
| 9 | embassy-net Runner always self-wakes | Timer re-poll |
| 10 | Modem.feed() drops unregistered sessions | Auto-create (THE fix) |

## Test Suite

```bash
make c6-acceptance   # 16 protocol checks over USB
make c6-stability    # 5 open/close reset cycles
make c6-soak        # 115s continuous connection
make c6-test        # all three
```

## TCP Host Setup

The modem connects OUT to a configured host (reverse-connect). Run a
listener on your laptop:

```bash
nc -l 4990
# Or a proper KISS host using reticulum-rs:
RUST_LOG=info cargo run --example rnode_listen \
    --features "iface-rnode,iface-serial" -- --port /dev/ttyACM1
```

Build with `C6L_TCP_HOST=<laptop-ip>` to set the target.

## Files Modified

- `firmware/c6l-modem/src/` — firmware (5 source files)
- `firmware/c6l-modem/tests/` — acceptance, stability, soak tests
- `firmware/patches/esp-rtos/` — esp-rtos fork
- `firmware/patches/embassy-net/` — embassy-net fork
- `rnode-modem-core/` — protocol core (the critical fix)
- `src/iface/rnode.rs` — host-side (detect validation, reset-on-open)
- `src/iface.rs` — announces_sent counter fix
