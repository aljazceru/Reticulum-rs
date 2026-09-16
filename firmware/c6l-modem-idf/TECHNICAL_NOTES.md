
---

## 2026-09-16: BIDIRECTIONAL LoRa ACHIEVED (C6L <-> RNode)

### Summary
The ESP-IDF firmware now exchanges LoRa packets in **both directions** with a
Heltec RNode (fw 1.86): RNode→C6L `hello` ×5 (RSSI −40 dBm, SNR +40 dB) and
C6L→RNode `HELLO`.

### Why it took so long — the full root-cause chain

1. **Wrong KISS command IDs** — RNode's command set (Framing.h / RNS):
   `0x01` frequency, `0x02` bandwidth, `0x03` txpower, `0x04` SF, `0x05` CR,
   `0x06` radio state, `0x08` detect, `0x00` data. Earlier tests used
   0x05/0x06/0x07/0x08/0x09, which configure CR/radio-state/lock/detect/
   implicit instead — the RNode never actually changed frequency/BW/SF.
2. **Wrong device** — USB ports swapped: `/dev/ttyUSB0` is rfsight's
   rid_sniffer node (does not speak RNode KISS); the RNode is
   `/dev/ttyUSB1`. Verify with `CMD_FW_VERSION (0x50 0xFF)` before testing.
3. **Radio never turned on** — RNode keeps its radio off until the host
   sends `CMD_RADIO_STATE = 0x01` after the detect burst + config frames
   (mirror of `RnodeRadioConfig::configuration_frames(RADIO_STATE_ON)` in
   `src/iface/rnode.rs`).
4. **Blind register writes** — regs `0x0736` (IQ errata 15.4) and `0x0889`
   (modem sensitivity) must be **read-modify-write**. Blind `0x04` writes
   clobber other bits: constant −73 dBm RSSI floor, no preamble detection.
5. **Sync word** — RNode hardcodes `[0x14, 0x24]` in `sx126x::setSyncWord()`
   (writes regs 0x0740/0x0741 literally). NOT the RadioLib
   `setSyncWord(0x12)` encoding `[0x10, 0x20]`.
6. **Full RNode init order** (sx126x.cpp `begin()`): calibrate(0x7F) →
   image-cal(863-870 → `0xD7 0xDB`) → TCXO **3.0 V** for C6L (variant.h;
   Heltec V3 uses 3.3 V) → packet type → frequency → sync word →
   DIO2-as-RF-switch → mod params → `0x0889 |= 0x04` → 9-byte packet
   params (preamble **18**, explicit, len 0xFF, CRC **on**, std IQ) →
   `0x0736 |= 0x04` **after every SetPacketParams** (the command resets
   the register) → buffer base → SetRegulatorMode(DCDC) → IRQ mask →
   SetRx.
7. **RNode wire format** — every RNode LoRa packet is
   `[header(seq<<4 | flags), payload…]`; `receive_callback` reads the
   first byte as header/split-marker. Raw payloads get misparsed.
8. **TX length** — explicit-header TX takes the payload length from the
   *last* SetPacketParams; leaving 0xFF transmits a 255-byte packet that
   fails CRC at the receiver. Set the real length before SetTx.
9. **SetTx(0x000000)** — RNode's single-shot mode. With a 1 s timeout
   parameter the chip refused to enter TX at all (mode stuck 2/STBY_RC,
   no IRQ). Use `0x83 00 00 00 00`.
10. **FIFO mechanics** — `ReadBuffer` data at buf[3] (opcode, addr,
    dummy, data…); `GetRxBufferStatus` len@buf[3] offset@buf[4]; in
    continuous RX the write pointer advances per packet, so issue
    `SetBufferBaseAddress(0,0)` after each read to prevent accumulation.
11. **LNA boost disabled** — `0x08AC = 0x96` (RNode uses it) produced a
    constant −73 dBm floor on the C6L; board-level noise from the
    ESP32-C6. Leave at default.
12. **Watchdog** — the TX-poll loop must `vTaskDelay(1)` (not
    `yield_now()`); otherwise the thread is killed and USB drops.

### Environment gotchas
- The rfsight rid_sniffer (ttyUSB0) sits centimeters away with an SX1262
  scanning 868 MHz with rotating configs — its near-field RF blankets the
  whole 868 band at ≈ −73 dBm. At 915 MHz the C6L floor is a clean −95 dBm,
  confirming the source. Keep the boards apart or test out-of-band.
- C6L re-enumerates (ttyACM1 ↔ ttyACM2) after a crash; check `ls /dev/ttyACM*`.
- GetRssiInst reads: data byte at buf[2]; RSSI = −byte/2.

### Working SPI conventions (ESP-IDF spi_master on C6L)
- CS (GPIO23) is a plain GPIO; hold LOW across the whole command.
- Byte-by-byte `transfer_in_place` per byte works for BOTH reads and
  writes (RNode's `executeOpcode` does exactly this); multi-byte writes
  also work for most commands but SetTx was only verified single-shot
  with all-byte-by-byte framing.

### Round-trip test
`tests/lora_roundtrip.py [freq_hz]` — configures the RNode on ttyUSB1,
prints C6L RX on ttyACM2, expects `hello` ×5 and the RNode receiving
`HELLO`.
