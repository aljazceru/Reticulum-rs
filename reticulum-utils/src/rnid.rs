//! `rnid` — Reticulum identity utility (subset of `RNS/Utilities/rnid.py`):
//! generate identities, persist them to files, load existing ones and print
//! their hash and keys.
//!
//! Not ported (yet): encrypt/decrypt, signing, announce, destination hashes
//! for arbitrary aspects.

use std::path::Path;

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;

use crate::common::{
    identity_from_raw_keys, load_private_identity, save_private_identity,
};

/// Exit code for an invalid identity (Python `rnid.py` `R_INVALID_IDENTITY`).
pub const R_INVALID_IDENTITY: i32 = 8;

/// What `rn id` should do.
#[derive(Debug, Default)]
pub struct IdOptions {
    /// `-g/--generate <path>`: generate a new identity and save it to path.
    pub generate: Option<std::path::PathBuf>,
    /// `-i/--identity <path|hex>`: inspect an existing identity.
    pub identity: Option<String>,
    /// `--public`: only print public key material.
    pub public: bool,
    /// `--no-save`: generate without saving even when a path is implied.
    pub no_save: bool,
}

/// A rendered identity report.
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub hash: String,
    pub public_key: String,
    pub verifying_key: String,
    pub private_key: Option<String>,
    pub saved_to: Option<String>,
    pub loaded_from: Option<String>,
}

impl IdentityInfo {
    /// Render like Python `rnid` output:
    /// ```text
    /// Identity     : <hash>
    /// Public Key   : <hex>
    /// Verifying Key: <hex>
    /// Private Key  : <hex>
    /// ```
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Identity     : {}\n", self.hash));
        if let Some(source) = &self.loaded_from {
            out.push_str(&format!("Loaded From  : {source}\n"));
        }
        out.push_str(&format!("Public Key   : {}\n", self.public_key));
        out.push_str(&format!("Verifying Key: {}\n", self.verifying_key));
        if let Some(private) = &self.private_key {
            out.push_str(&format!("Private Key  : {private}\n"));
        }
        if let Some(path) = &self.saved_to {
            out.push_str(&format!("Saved To     : {path}\n"));
        }
        out
    }
}

/// Run `rn id`. Returns the process exit code.
pub fn run(options: IdOptions) -> Result<i32, String> {
    if options.generate.is_some() && options.identity.is_some() {
        return Err("The --generate and --identity options are mutually exclusive".to_string());
    }

    if let Some(path) = options.generate.clone() {
        if path.exists() {
            return Err(format!(
                "Identity file {} already exists. Not overwriting.",
                path.display()
            ));
        }
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let info = info_for_private(&identity, &options);
        let mut info = info;
        if !options.no_save {
            save_private_identity(&path, &identity)
                .map_err(|err| format!("An error occurred while saving the generated identity: {err}"))?;
            info.saved_to = Some(path.display().to_string());
        }
        print!("{}", info.render());
        return Ok(0);
    }

    if let Some(identity_arg) = &options.identity {
        // Either a path to an identity file or a hex string.
        let path = Path::new(identity_arg);
        let info = if path.is_file() {
            let identity = load_private_identity(path)
                .map_err(|err| format!("Could not load Identity from specified file: {err}"))?;
            let mut info = info_for_private(&identity, &options);
            info.loaded_from = Some(path.display().to_string());
            info
        } else {
            // Hex string (128 characters). A private and a public identity
            // hex string have the same length, so the interpretation is
            // chosen explicitly: `--public` reads a public identity
            // (Python `-m/--import-pub`), otherwise a private one
            // (Python `-M/--import-prv`).
            let cleaned = identity_arg.trim();
            if options.public {
                let identity = reticulum::identity::Identity::new_from_hex_string(cleaned)
                    .map_err(|_| "Could not parse the specified public identity".to_string())?;
                IdentityInfo {
                    hash: crate::common::prettyhexrep(identity.address_hash.as_slice()),
                    public_key: hex(identity.public_key_bytes()),
                    verifying_key: hex(identity.verifying_key_bytes()),
                    private_key: None,
                    saved_to: None,
                    loaded_from: None,
                }
            } else {
                let identity = PrivateIdentity::new_from_hex_string(cleaned)
                    .map_err(|_| "Could not parse the specified identity".to_string())?;
                info_for_private(&identity, &options)
            }
        };
        print!("{}", info.render());
        return Ok(0);
    }

    // Default: generate a new ephemeral identity and print it.
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let info = info_for_private(&identity, &options);
    print!("{}", info.render());
    Ok(0)
}

fn info_for_private(identity: &PrivateIdentity, options: &IdOptions) -> IdentityInfo {
    IdentityInfo {
        hash: crate::common::prettyhexrep(identity.address_hash().as_slice()),
        public_key: hex(identity.as_identity().public_key_bytes()),
        verifying_key: hex(identity.as_identity().verifying_key_bytes()),
        private_key: if options.public {
            None
        } else {
            Some(identity.to_hex_string())
        },
        saved_to: None,
        loaded_from: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:0>2x}")).collect()
}

/// Re-exported for other tools/tests: build an identity from raw Python-format
/// key bytes.
pub fn from_raw_keys(bytes: &[u8]) -> Option<PrivateIdentity> {
    identity_from_raw_keys(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_render() {
        let info = run(IdOptions::default()).expect("run");
        assert_eq!(info, 0);
    }

    #[test]
    fn private_key_hidden_in_public_mode() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let info = info_for_private(&identity, &IdOptions { public: true, ..Default::default() });
        assert!(info.private_key.is_none());
        let full = info_for_private(&identity, &IdOptions::default());
        assert!(full.private_key.is_some());
        assert_eq!(full.private_key.unwrap().len(), 128);
    }
}
