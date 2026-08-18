# Hardware testing

How the hardware-dependent parts of Reticulum-rs are tested. The guiding
principle: **every tier below runs the same code path**, so a bug caught
at a cheap tier is a hardware bug caught early, and a pass at the top
tier is meaningful.

## The test ladder

| Tier | What it exercises | Where | Runs |
|---|---|---|---|
| 1. Unit | codec + parsers (KISS framing, radio config encoding, status telemetry, validation rules) | `src/iface/rnode.rs` tests, `tests/rnode_iface.rs` | every CI run |
| 2. Emulator | full connect sequence + data path against a faithful device emulator | `rn node-sim`, `tests/hardware_rnode.rs` with `RETICULUM_HW_RNODE_TCP` | every CI run |
| 3. Mock bridges | protocol against scripted counterparts (SAM bridge for I2P, bridging TCP mock for RNode) | `tests/i2p_iface.rs`, `tests/rnode_iface.rs` | every CI run |
| 4. Hardware-in-the-loop | real RNode firmware on real silicon | same `tests/hardware_rnode.rs` with `RETICULUM_HW_RNODE=<port>` | on demand |
| 5. Real radio exchange | two nodes, over-the-air LoRa | manual checklist below | on demand |

### Tier 2 — the emulator

`rn node-sim` implements the RNode device side of the wire protocol:
detect burst responses, configuration echo **with SX1262-style frequency
quantization**, radio-state transitions, periodic RSSI/SNR telemetry and
optional `CMD_READY` flow control. Data frames are bridged between all
connected hosts, simulating a shared radio channel:

```
rn node-sim --tcp 127.0.0.1:4990
RETICULUM_HW_RNODE_TCP=127.0.0.1:4990 \
  cargo test -p reticulum-utils --features iface-rnode --test hardware_rnode -- --nocapture
```

### Tier 4 — hardware-in-the-loop

Point the same tests at a real device (RNode firmware >= 1.52,
provisioned EEPROM):

```
sudo chmod 666 /dev/ttyUSB2    # if not in dialout
RETICULUM_HW_RNODE=/dev/ttyUSB2 \
  cargo test -p reticulum-utils --features "iface-rnode,iface-serial" --test hardware_rnode -- --nocapture
```

The tests cover: detect + firmware gate + identity (platform/MCU), full
radio-configuration validation via `rnodeconf`, and transmission with TX
counter advancement. `rn nodeconf --port <port>` gives the same
diagnostics interactively.

### Tier 5 — over-the-air

With two nodes on one channel:

```
# node A (listener side)
rn probe --loopback        # or any transport with an RNode interface
# node B announces; A must learn the path:
rn status                  # path table shows the announce
```

For a full link/data test, run two `rs-rnsd` instances (one per port)
with an `RNodeInterface` each and exchange announces — the tier-4
`hw_packet_transmit` asserts the same TX path that carries them.

## Field report: Heltec V3 (2026-08-18)

A Heltec V3 (ESP32-S3, SX1262, 8 MB flash) was provisioned as a test
device:

* flashed RNode firmware 1.86 (and 1.80) at the reference offsets —
  bootloader **0x0** for ESP32-S3 (not 0x1000), partitions 0x8000,
  boot_app0 0xe000, app 0x10000, console 0x210000
* bootstrapped EEPROM (product 0xC1, model 0xCA 850-950 MHz, hwrev 1)
  with the MD5 checksum block, and stored the partition SHA-256 via
  `CMD_FW_HASH`

**Result:** the device answers detect (fw 1.86, platform 0x80, MCU
0x81), echoes configuration with real SX1262 frequency quantization and
streams battery/temperature telemetry — the entire serial command path
of `iface/rnode.rs` was validated against genuine firmware and silicon.
The radio itself does not come up on this board: firmware
`device_init()` requires `bt_ready`, and the ESP32-S3 BLE bring-up
(`btStart`/bluedroid) fails silently in this firmware line (see upstream
issue #73 — "serial only … BLE is not fleshed out"), so `hw_ready` stays
false and the radio reports offline. **The reference Python
`RNodeInterface` fails identically on this hardware**, which is parity —
our implementation matches the reference behaviour exactly.

The device was restored to its original firmware from the backup:

```
hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin   # full 8 MB image
uv tool run esptool --port /dev/ttyUSB2 --baud 921600 write-flash 0x0 hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin
```

Reprovisioning notes (for when a suitable single-band RNode is
available): `hw-backup/bootstrap_eeprom.py` shows the EEPROM identity
layout; the ESP32-S3 bootloader offset pitfall is the one that bites.

## I2P and Backbone hardware

* **I2P**: the hardware dependency is the SAM bridge of an I2P router.
  Tier-3 covers the protocol completely against the mock bridge
  (`tests/i2p_iface.rs`). Against a real router, run one locally
  (`i2pd --sam.enabled=true`) and point `I2pServer::new("127.0.0.1:7656", ...)`
  at it — no code changes needed.
* **Backbone**: plain TCP; "hardware" is the network itself. The
  end-to-end test covers server/client, fast-flap suppression and tunnel
  synthesis.
* **Weave**: requires WeaveMesh radio hardware; the WDCL device protocol
  has no observable surface without the device.
