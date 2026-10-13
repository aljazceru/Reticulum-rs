# Remaining gaps vs Python Reticulum 1.5.5

Comparison target: `/home/user/g/reticulum/Reticulum` (`RNS/_version.py` =
1.5.5). The items below are the differences that remain after the parity
series landed. LXMF, LXST, `reticulum-actor`, `reticulum-ffi`, and
`firmware/` are Rust-side extras, not Python parity items, and are not
listed here.

## Interfaces and platform support

- **Android USB host interfaces.** Python swaps in
  `RNS/Interfaces/Android/{RNode,Serial,KISS}Interface.py` on Android.
  Rust implements none of them: `AndroidRNodeInterface`,
  `AndroidSerialInterface`, `AndroidKISSInterface`, and `usb://` /
  `android-usb://` ports return `RnsError::Unsupported`
  (`src/iface/rnode.rs::android_usb_error`), and an Android daemon build
  refuses Weave USB serial outright (`reticulum-daemon/src/main.rs`).
- **RNode over `ble://` needs a cargo feature.** The btleplug backend
  lives behind `iface-rnode-ble` (`Cargo.toml`); default builds reject
  `ble://` targets (`src/iface/rnode.rs`). Python reaches a BLE radio
  whenever the platform Bluetooth stack exists.
- **No interface plugins.** Python `Reticulum` executes
  `interfaces/<type>.py` for an interface type it does not know
  (`RNS/Reticulum.py`). Rust loads no external modules; an unknown
  `type =` is reported as `type 'X' is not supported yet`
  (`reticulum-daemon/src/config.rs`) and the interface is not started.
- **AutoInterface enumeration is per-OS.** `platform_addresses()` in
  `src/iface/auto.rs` covers Linux, Android, macOS, the BSDs, and
  Windows; any other target (for example Solaris, which Python's
  vendored `netinfo` handles via `getifaddrs`) gets an empty list, so
  AutoInterface finds no subinterfaces there.

## Utilities

- **`rnodeconf` is framing-only.** `reticulum-utils/src/rnodeconf.rs`
  covers probing, EEPROM read/write, firmware info, TNC mode, display,
  WiFi, and BLE control frames. Not ported from
  `RNS/Utilities/rnodeconf.py`: the firmware database and autoinstall
  flow, MD5 image hashing and RSA signing/key handling, the bundled
  recovery esptool, most inter-command timing sleeps, and the
  interactive "Press enter to exit" Bluetooth-pairing wait. `--flash`
  only builds an argv for an external `rnodeconf` or `esptool` found on
  `PATH` (`flash_command`); the Rust tool never flashes itself.
- **`rngit` has no web output.** `reticulum-utils/src/rngit.rs`
  implements the node, client, and `git-remote-rns` wire operations.
  The Python tool's HTML repository pages (`rngit/pages.py`), syntax
  highlighting (`rngit/highlight.py`), and media transcoding to WebP
  (`rngit/media.py`) are not ported.

## Stubs on both sides — not gaps

- `rnir` and `rnpkg` are attach-only stubs in both trees: Python's
  `RNS/Utilities/rnir.py` and `rnpkg.py` instantiate `RNS.Reticulum`
  and exit; `reticulum-utils/src/rnir.rs` and `rnpkg.rs` do the same.
- `Resolver.resolve_identity` is an empty stub in `RNS/Resolver.py`;
  there is no Rust resolver implementing it either.
