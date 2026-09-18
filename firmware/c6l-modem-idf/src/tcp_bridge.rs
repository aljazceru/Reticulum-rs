//! TCP listener + session threads for the KISS bridge
//! (BRIDGE_PLAN Phase 2 + Phase 4).
//!
//! Contract (pinned — do not change signatures):
//!   - `start(bus)` spawns the 16 KB accept thread and returns
//!     immediately. The listener binds 0.0.0.0:4990 (std::net over
//!     lwIP — binds fine before DHCP; clients just can't reach it yet).
//!   - Max 2 concurrent sessions (one laptop + one debug client);
//!     further connections are accepted, drained-and-closed politely.
//!   - Each session: one 8 KB reader thread per socket; TCP_NODELAY on
//!     every accepted stream (KISS is tiny frames).
//!   - Reader: blocking-ish `read` loop -> `bus.send_in(id, bytes)`.
//!     Writer: `guard.rx.recv()` -> `stream.write_all`. Split the
//!     TcpStream via `try_clone` for the two directions.
//!   - `SessionGuard` drop (on disconnect/error) unregisters the
//!     session and notifies the modem thread automatically.
//!   - ALL logging via `crate::clog!` — never `println!`.
//!
//! The KISS parser does NOT live here: raw bytes go to the modem thread
//! which owns `Modem::feed`; outbound frames arrive pre-framed.

use std::sync::Arc;

use crate::bus::Bus;

/// TCP port for the RNode KISS bridge (rnsd: tcp://C6L_IP:4990).
pub const LISTEN_PORT: u16 = 4990;
/// Max concurrent TCP sessions (plan: laptop + debug client).
pub const MAX_SESSIONS: usize = 2;

/// Spawn the accept thread. Returns immediately.
pub fn start(bus: Arc<Bus>) {
    let _ = bus;
    todo!("agent T: implement per BRIDGE_PLAN Phase 2 + Phase 4")
}
