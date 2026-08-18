//! `reticulum-utils` — the `rn*` utility tools for Reticulum-rs.
//!
//! Ports of the Python `RNS/Utilities` tools (Phase 8 of the implementation
//! plan):
//!
//! * [`rnid`] — identity generation/inspection (`Utilities/rnid.py`)
//! * [`rnpath`] — path lookup / path table (`Utilities/rnpath.py`)
//! * [`rnstatus`] — instance status (`Utilities/rnstatus.py`)
//! * [`rnprobe`] — round-trip probes (`Utilities/rnprobe.py`)
//! * [`rnx`] — remote command execution (`Utilities/rnx.py`)
//! * [`rnsh`] — remote shell sessions (`Utilities/rnsh/`)
//! * [`rnodeconf`] — RNode diagnostics/config validation
//! * [`rnir`] / [`rnpkg`] — reference stub utilities
//! * [`rncp`] — file transfer over resources (`Utilities/rncp.py`)
//!
//! The tools are exposed both as a library (used by the integration tests
//! and embeddable elsewhere) and as one multi-call binary, `rn`
//! (`rn id`, `rn path`, `rn status`, `rn cp`).
//!
//! All tools take `--config <dir>` like the Python versions (default
//! `~/.reticulum`) and run their own transport instance with the interfaces
//! configured there. Attaching to a shared instance (Python
//! `require_shared_instance`) is not implemented yet — see the
//! `remote`-mode TODOs in `rnstatus`.

pub mod common;
pub mod rncp;
pub mod rnid;
pub mod rnpath;
pub mod rnir;
#[cfg(feature = "iface-rnode")]
pub mod rnodeconf;
pub mod rnprobe;
pub mod rnpkg;
pub mod rnsh;
#[cfg(feature = "iface-rnode")]
pub mod rnode_sim;
pub mod rnx;
pub mod rnstatus;
