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
device. **Heltec V3 is officially supported RNode hardware** (product
`0xC1`, model `0xCA` 850-950 MHz, official release builds and
`rnodeconf` support) — an earlier revision of this report wrongly
generalised a 2023 issue (#73, from when V3 support was *added*) into
"BLE not fleshed out". Corrected findings:

**What was validated against real hardware (all green):**
* full flashing flow at the reference offsets — note the ESP32-S3
  bootloader goes at **0x0**, not 0x1000 (bootloader 0x0, partitions
  0x8000, boot_app0 0xe000, app 0x10000, console 0x210000)
* EEPROM identity bootstrap (product/model/hwrev/serial/MD5 checksum/
  signature/info-lock), the `ADDR_CONF_BT` enable byte, and the
  `CMD_FW_HASH` firmware-hash handshake
* the **entire serial command protocol of `iface/rnode.rs` against
  genuine firmware 1.86 and 1.80**: detect burst responses (fw 1.86,
  platform 0x80, MCU 0x81), configuration echo with real SX1262
  frequency quantization (867,500,000 → 867,499,996 — the ±100 Hz
  validation tolerance is correct), battery/temperature telemetry,
  radio-state reporting

**What did not come up, and why (evidence-backed):**
the radio never reports online. In this firmware line the radio is
gated by `device_init()`, which requires `bt_ready`; `bt_ready` requires
`btStart()` to succeed. Probes performed:
* `CMD_HASHES` (target + calculated firmware hashes) and `CMD_DEV_HASH`
  return zeros → `device_init()`'s body never executes → `bt_ready` is
  false
* with the BT-enable byte set and a hard reset, no BLE advertisement
  appears on a scan with a working adapter (neighbors do) → the BT
  controller does not come up on this unit
* the **reference Python `RNodeInterface` fails identically** on this
  device ("Radio reporting state is offline") — behaviour parity with
  our port is exact

This is a board/unit bring-up condition (BT controller init), not a
board-support gap and not a defect in the port. Candidate causes on
this unit: its prior life as a Meshtastic node (NVS state), a
hardware/revision variant (this board exposes a CP2102 UART bridge), or
a firmware BLE bring-up issue on S3. A factory-fresh Heltec V3 (or any
classic-RNode board) provisioned via `rnodeconf --autoinstall` should
be used to complete tier-4 radio validation; the env-gated tests in
`tests/hardware_rnode.rs` need no changes for that.

The device was restored to its original firmware from the backup:

```
hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin   # full 8 MB image
uv tool run esptool --port /dev/ttyUSB2 --baud 921600 write-flash 0x0 hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin
```

Reprovisioning notes: `hw-backup/bootstrap_eeprom.py` shows the EEPROM
identity layout (plus the `ADDR_CONF_BT` byte and `CMD_FW_HASH`
handshake used above); the ESP32-S3 bootloader offset pitfall is the one
that bites.

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
