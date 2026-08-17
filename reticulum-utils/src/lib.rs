//! `reticulum-utils` — the `rn*` utility tools for Reticulum-rs.
//!
//! Ports of the Python `RNS/Utilities` tools (Phase 8 of the implementation
//! plan):
//!
//! * [`rnid`] — identity generation/inspection (`Utilities/rnid.py`)
//! * [`rnpath`] — path lookup / path table (`Utilities/rnpath.py`)
//! * [`rnstatus`] — instance status (`Utilities/rnstatus.py`)
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
pub mod rnstatus;
