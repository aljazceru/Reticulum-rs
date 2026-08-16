
# Reticulum-rs

**Reticulum-rs** is a Rust implementation of the [Reticulum Network Stack](https://reticulum.network/) — a cryptographic, decentralised, and resilient mesh networking protocol designed for communication over any physical layer.

This project brings Reticulum's capabilities to the Rust ecosystem, enabling embedded, and constrained deployments with maximum performance and minimal dependencies.

## Features

- 📡 Cryptographic mesh networking
- 🔐 Trustless routing via identity-based keys
- 📦 Resource transfers: arbitrary-size payloads over links with windowing,
  compression (bzip2), retries and automatic segmentation — wire-compatible
  with Python `RNS.Resource`
- 🔄 Requests & responses over links, including resource-backed transfers of
  large responses (Python `Link.request` compatible)
- 🧱 Support for multiple transport layers (TCP, UDP, serial)
- 🔌 Easily embeddable in embedded devices and tactical radios
- ✅ Python interop test-suite: resources, requests, links, announces
- 🧪 Example clients for testnets and real deployments
- 📨 `lxmf` crate: the LXMF messaging layer (byte-exact Python LXMF format)
- 🎙 `lxst` crate: LXST audio streaming, codecs and calls

## Structure

```
Reticulum-rs/
├── src/                 # Core Reticulum protocol implementation
│   ├── transport.rs     #   transport instance, routing, path requests
│   ├── resource/        #   resource transfers (outbound/inbound/manager)
│   ├── channel.rs       #   reliable channel streams over links
│   ├── iface/           #   interfaces (tcp client/server, udp, hdlc)
│   └── buffer.rs
├── reticulum-core/      # no_std protocol core (crypto, identity, packet)
├── reticulum-daemon/    # RNS daemon + config conversion
├── lxmf/                # LXMF message format, stamps, peers, router
├── lxst/                # LXST audio streaming, codecs, calls
├── tests/               # unit, interop and parity tests
│   ├── resource_transfer.rs
│   ├── parity.rs        #   ports of the Python tests/ suite vectors
│   ├── python_resources.rs  # Python interop: resources + requests
│   └── python.rs        # Python interop: announce/link/identify
├── examples/            # Example clients and servers
├── docs/                # implementation plan and notes
├── Cargo.toml           # Workspace configuration
└── LICENSE
```

## Getting Started

### Prerequisites

* Rust (edition 2021+)

### Build

```bash
cargo build --release
```

### Reticulum daemon

#### Converting config from Python Reticulum

Reticulum-rs uses TOML for configuration, whereas the original Python Reticulum uses a custom format parsed by configobj, a Python-only library. If you have an existing Python Reticulum configuration, it will be read and converted to TOML in-memory. If you want to apply the conversion and save a TOML copy, run the `convert-config` subcommand:

```bash
cargo run -p reticulum-daemon -- convert-config <config_file>
```

This leaves the original file and creates a copy with .toml extension. The converter handles boolean normalization (True/False/Yes/No → true/false), quotes string values, transforms interface declarations to TOML array-of-tables syntax, and comments out None/nil values which TOML does not support.

#### Running the daemon

```bash
# Use default config search paths (~/.config/reticulum, ~/.reticulum, /etc/reticulum)
cargo run -p reticulum-daemon

# Specify a custom config directory
cargo run -p reticulum-daemon -- --config /path/to/config/dir
cargo run -p reticulum-daemon -- -c /path/to/config/dir
```

The daemon searches for either `config` (legacy filename) or `config.toml` in the specified directory.

### Run Examples

```bash
# TCP client/server examples
cargo run --example tcp_client
cargo run --example tcp_server

# Channel examples
cargo run --example channel_server
cargo run --example channel_client

# Multi-hop transport example
cargo run --example multihop
```

### Resource transfers and requests

```rust,ignore
use reticulum::resource::{ResourceOptions, ResourceStrategy, ResourceStatus};

// Accept incoming resources on a link
transport.set_resource_strategy(link_id, ResourceStrategy::All).await;

// Send an arbitrary-size payload as a resource
transport.send_resource(&link, data).await?;

// Send a request and await the response (resource-backed when large)
let rid = transport.request(&link, "my.path", b"payload").await?;
let response = transport.await_request_response(rid, Duration::from_secs(30)).await;
```

### Python integration tests

Integration tests against the Python implementation (announces, links,
identify, resource transfers and requests) can be run with the `python-tests`
feature and setting `RETICULUM_TEST_PYTHON_DIR` (and `PYTHONPATH`) to the
location of the checked out Python Reticulum source tree. Example:
```
RETICULUM_TEST_PYTHON_DIR=../Reticulum PYTHONPATH=../Reticulum \
    cargo test python --features="python-tests"
```

## Use Cases

* 🛰 Tactical radio mesh over LoRa/serial transceivers
* 🕵️‍♂️ Covert communication using serial or sub-GHz transceivers
* 🚁 UAV-to-ground resilient C2 and telemetry
* 🧱 Decentralized infrastructure-free messaging

## License

This project is licensed under the MIT license.

---

© Beechat Network Systems Ltd. All rights reserved.
https://beechat.network/
