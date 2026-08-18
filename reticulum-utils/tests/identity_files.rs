//! Identity file persistence tests (Phase 1.1 / 7.4):
//! hex round-trip, Python raw-key round-trip, rnid generate → daemon load
//! (restart stability).

use std::path::PathBuf;

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum_utils::common::{
    identity_from_raw_keys, load_or_create_private_identity, load_private_identity,
    save_private_identity,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-identity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn hex_round_trip() {
    let dir = temp_dir("hex");
    let path = dir.join("identity");
    let identity = PrivateIdentity::new_from_rand(OsRng);

    save_private_identity(&path, &identity).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content.len(), 128);

    let loaded = load_private_identity(&path).unwrap();
    assert_eq!(
        loaded.address_hash().to_hex_string(),
        identity.address_hash().to_hex_string()
    );
    assert_eq!(loaded.to_hex_string(), identity.to_hex_string());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_raw_key_format_round_trip() {
    // Python Identity.to_file writes 64 raw key bytes (X25519 private key ‖
    // Ed25519 signing key) in the same order as our hex format.
    let dir = temp_dir("raw");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let hex_string = identity.to_hex_string();
    let mut raw = Vec::with_capacity(64);
    for pair in hex_string.as_bytes().chunks(2) {
        raw.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    let path = dir.join("identity.rid");
    std::fs::write(&path, &raw).unwrap();

    let loaded = load_private_identity(&path).unwrap();
    assert_eq!(loaded.to_hex_string(), hex_string);
    assert_eq!(
        identity_from_raw_keys(&raw).unwrap().to_hex_string(),
        hex_string
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_identity_file_is_rejected() {
    let dir = temp_dir("corrupt");
    let path = dir.join("identity");
    std::fs::write(&path, "not-an-identity").unwrap();
    assert!(load_private_identity(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rnid_generate_then_daemon_restart_keeps_identity_stable() {
    // `rn id -g <path>` generates and saves; the daemon loads the same file
    // on every start, so the instance identity (and all destinations derived
    // from it) must stay stable across restarts.
    let config_dir = temp_dir("restart");
    let identity_path = config_dir.join("identity");

    // First "rn id -g" run.
    let exit = reticulum_utils::rnid::run(reticulum_utils::rnid::IdOptions {
        generate: Some(identity_path.clone()),
        identity: None,
        public: false,
        no_save: false,
    })
    .expect("rnid generate");
    assert_eq!(exit, 0);

    // First daemon start: load-or-create must load, not create.
    let (first, created) = load_or_create_private_identity(&identity_path).unwrap();
    assert!(!created);

    // Simulated restarts.
    for _ in 0..3 {
        let (again, created) = load_or_create_private_identity(&identity_path).unwrap();
        assert!(!created);
        assert_eq!(
            again.address_hash().to_hex_string(),
            first.address_hash().to_hex_string()
        );
    }

    // `rn id -i` can inspect the same file.
    let exit = reticulum_utils::rnid::run(reticulum_utils::rnid::IdOptions {
        generate: None,
        identity: Some(identity_path.display().to_string()),
        public: false,
        no_save: false,
    })
    .expect("rnid inspect");
    assert_eq!(exit, 0);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[test]
fn rncp_identity_persists_per_config_dir() {
    let config_dir = temp_dir("rncp-id");
    let path = config_dir.join("storage/identities/rncp");
    let (first, created) = load_or_create_private_identity(&path).unwrap();
    assert!(created);
    assert!(path.exists());
    let (second, created) = load_or_create_private_identity(&path).unwrap();
    assert!(!created);
    assert_eq!(
        first.address_hash().to_hex_string(),
        second.address_hash().to_hex_string()
    );
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[cfg(unix)]
#[test]
fn private_identity_writes_are_owner_only_even_for_existing_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("permissions");
    let paths = [
        dir.join("identity"),
        dir.join("storage/identities/rnsh"),
        dir.join("storage/identities/rnx"),
        dir.join("storage/identities/rncp"),
        dir.join("utility.rid"),
    ];
    let identity = PrivateIdentity::new_from_rand(OsRng);

    for path in paths {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"replace me").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        save_private_identity(&path, &identity).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{} must remain private",
            path.display()
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}
