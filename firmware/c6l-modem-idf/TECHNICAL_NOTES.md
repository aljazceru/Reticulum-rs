
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

---

## 2026-09-17 (later): rnsd integration + RX loss analysis

### Working
- rnode-modem-core: RNode 0xFF-query semantics (RNS validateRadioState passes)
- `delay_ms` tick conversion + reply-before-op flush (RNS 250ms validation window)
- rnsd brings the C6L up on both nodes; announces B->A + path discovery over LoRa
- Full app round trip proven by replay: rnsd's exact 131-byte probe frame,
  replayed through the RNode, reached the responder over the air and the
  proof returned ("Valid reply", responder `*** RECEIVED`)
- KISS acceptance 10/10 incl. 212-byte payloads

### The remaining blocker: ~50% per-packet RX loss on the C6L
Measured with rnprobe x8: A's RNode transmits every probe (airtime
verified) but the C6L delivers only ~half to rnsd. Pattern is roughly
alternating — consistent with the modem being deaf for a window after
its own TX (proofs), though slower announces only marginally improved
it. With single-shot probes that means "timed out"; LXMF's transport
retries would eventually deliver, but multi-packet link handshakes
(rnx) don't complete.

Suspected causes to investigate next (in order):
1. RX processing latency: byte-by-byte SPI FIFO reads (~131 bytes =
   ~5ms of bit-banged CS-held transfers) + 10ms poll cadence may
   collide with the next packet's preamble in busier traffic.
   -> move to multi-byte FIFO reads (works for WriteBuffer) or
      DIO1-driven processing.
2. The post-TX recovery: currently standby + 2x start_rx with 20/50ms
   settles — improved 2/8 -> 3/8 but not fixed.
3. RF switch (DIO2) settling after PA ramp-down.

### Recovery procedure (hardware-verified)
The SX1262 occasionally wedges (no boot console, no KISS response).
ESP32 resets do NOT clear it (no NRESET pin on the C6L). Recovery:
1. Unplug/replug USB (full power cycle) — usually enough.
2. If not: flash Meshtastic, let it boot 5s, re-flash our firmware.
If espflash cannot attach after Meshtastic: esptool elf2image the ELF
and write bootloader/partition-table/app at 0x0/0x8000/0x10000.

---

## 2026-09-17 (evening): codex-assisted isolation — modem exonerated

Codex CLI review of the driver flagged two datasheet violations, both fixed:
1. **Post-RxDone reconfiguration removed**: RX-continuous mode AUTO-REARMS
   after each packet; our `start_rx()` after every reception raced the
   modem and dropped packets. Now: SetBufferBaseAddress(0,0) +
   ClearIrqStatus(RxDone only).
2. **Verified post-TX RX entry**: SetRx can be silently rejected while
   the chip is busy — now GetStatus-checked (mode==5) with retry.
   (Note: an attempted ReadBuffer-with-returned-offset change REGRESSED
   payload alignment — the byte-by-byte framing does not expose the
   offset where expected; reverted to proven read-from-0.)

### The complete isolation matrix (all same radios, same config)
| Who drives the RNode | Payload | C6L reception |
|---|---|---|
| test script, 4-5s spacing | 6-13B | 10/10 |
| test script, 0.6s spacing | 6B / 125B | 19/20 |
| test script, rnsd's captured frames | 132-135B | **5/5** |
| **rnsd (live)** | its own 131B | **~40-50%** |
| rnsd (live, RNode freshly KISS-reset) | same | ~40% |

The alternating timeout/valid pattern persists across every C6L
firmware change AND RNode resets — the loss is exclusively correlated
with rnsd-a's live process driving the Heltec (its readLoop + flow-
control timing vs RNode fw 1.86's TX queue/CSMA). The C6L modem
itself receives essentially 100% of what the RNode actually puts on
the air under any other driver.

### Next steps (need hardware/tools beyond this session)
- Logic analyzer on the Heltec's serial during live-rnsd probes vs
  scripted replays (compare CMD_READY timing + TX patterns)
- Or try a different RNode firmware version on the Heltec
- Or an SDR capture at 867.5 during both driving modes

## FINAL RESULT: 100% packet delivery (2026-09-17)

After the FIFO offset fixes, the full rnsd round-trip works flawlessly:
```
rnprobe → rnsd-a → Heltec RNode → LoRa → C6L modem → rnsd-b → responder
         ← proof ← C6L TX ← LoRa ← Heltec RNode ← rnsd-a ← rnprobe
Sent 8, received 8, packet loss 0.0%
```

The three bugs (SetBufferBaseAddress corruption, wrong length byte, 
missing offset in ReadBuffer) accounted for ALL the packet loss.
