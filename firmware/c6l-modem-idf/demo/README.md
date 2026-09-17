# Two-node Reticulum demo over LoRa (C6L <-> Heltec RNode)

Node A = Heltec RNode on /dev/ttyUSB1 (Reticulum transport node).
Node B = M5Stack C6L on /dev/ttyACM1|2 (our c6l-modem-idf firmware).

## One-time setup
```
mkdir -p ~/demo/node-a ~/demo/node-b
cp node-a-rnsd.config ~/demo/node-a/config   # enable_transport = True
cp node-b-rnsd.config ~/demo/node-b/config   # C6L RNodeInterface
```

## Run
```
setsid python3 -m RNS.Utilities.rnsd --config ~/demo/node-a -v &  # wait for "powered up"
setsid python3 -m RNS.Utilities.rnsd --config ~/demo/node-b -v &
```
Watch logs: `tail -f /tmp/rnsd-*.log`. Status: `rnstatus -a --config ~/demo/node-a`.

## Message-level demo (LXMF / nomadnet)
Terminal 1: `nomadnet --config ~/demo/node-a`
Terminal 2: `nomadnet --config ~/demo/node-b`
Compose a message on one side (Conversations -> Write); it travels
over LoRa to the other node's inbox.

## Phone demo (Sideband)
Plug the C6L into the phone via a USB-OTG adapter. In Sideband:
Connectivity -> RNode -> select the serial device; set frequency
867500000, bandwidth 125000, TX power 14, SF 9, CR 5. The C6L answers
Sideband's detect burst (fw 1.90) and acts as the phone's RNode. The
laptop side runs nomadnet on the Heltec RNode; messages flow
phone <-> LoRa <-> laptop.

## IMPORTANT — interference
The rfsight rid_sniffer (USB hub neighbour) scans the 868 MHz band
continuously at ~-51 dBm at desk range. This adds 1-2s CSMA deferral
to every RNode transmission and can drop small packets entirely. For
reliable demos/videos, power the C6L+phone or the Heltec from a
different room / power bank, away from the rfsight node.

## Proven working (see tests/kiss_modem_acceptance.py)
- KISS detect/config/radio-on/echo round trip: 10/10
- Bidirectional LoRa data (RNode wire format incl. split packets)
- RNS detect + validateRadioState + interface Up on both nodes
- Announce propagation + path discovery over the air
