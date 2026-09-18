//! WiFi STA bring-up for the TCP bridge (BRIDGE_PLAN Phase 1 + Phase 4).
//!
//! Contract (pinned — do not change signatures):
//!   - `start()` spawns the 16 KB WiFi thread and returns immediately.
//!   - `ip_addr()` returns the DHCPv4 address once GOT_IP arrives.
//!   - Credentials come from `C6L_WIFI_SSID` / `C6L_WIFI_PASSWORD` env
//!     vars at BUILD time (`option_env!`); unset => WiFi stays off.
//!   - ALL logging goes through `crate::clog!` (KISS-safe) — never
//!     `println!` directly.
//!   - Reconnect on disconnect with bounded backoff (Phase 4).
//!
//! Implementation target: raw `esp_idf_sys` calls only (no esp-idf-svc —
//! version conflict with esp-idf-hal 0.47). `wifi_init_config_t` has a
//! `Default` impl in the generated bindings; `g_wifi_osi_funcs` is
//! exported. Init sequence per BRIDGE_PLAN:
//!   nvs_flash_init -> esp_netif_init -> esp_event_loop_create_default
//!   -> esp_netif_create_default_wifi_sta -> esp_wifi_init
//!   -> register WIFI_EVENT + IP_EVENT handlers -> set_mode(STA)
//!   -> set_config -> start -> esp_wifi_connect on STA_START.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU32;

static GOT_IP: AtomicU32 = AtomicU32::new(0);

/// Spawn the WiFi bring-up/reconnect thread. Returns immediately.
/// No-op (with a `clog!` note) when credentials are not compiled in.
pub fn start() {
    todo!("agent W: implement per BRIDGE_PLAN Phase 1 + Phase 4 reconnect")
}

/// The DHCPv4 address once associated, `None` before GOT_IP / after loss.
pub fn ip_addr() -> Option<Ipv4Addr> {
    let raw = GOT_IP.load(std::sync::atomic::Ordering::Relaxed);
    (raw != 0).then(|| Ipv4Addr::from(raw.to_be_bytes()))
}
