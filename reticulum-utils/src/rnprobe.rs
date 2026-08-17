//! `rnprobe` — probe transport instances by measuring round-trip times
//! to the fixed `rnstransport.probe` destination
//! (Python `RNS/Utilities/rnprobe.py`).

use std::path::Path;
use std::time::{Duration, Instant};

use reticulum::hash::AddressHash;
use reticulum::transport::Transport;
use crate::common::{build_tool_transport, resolve_config_dir, ToolTransportOptions};

/// Default probe payload size in bytes (Python `DEFAULT_PROBE_SIZE`).
pub const DEFAULT_PROBE_SIZE: usize = 16;

/// Default timeout in seconds (Python `DEFAULT_TIMEOUT`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ProbeOptions {
    /// Config directory (usually from `--config`).
    pub config_dir: std::path::PathBuf,
    pub size: usize,
    pub timeout: Duration,
    pub probes: usize,
    /// UDP loopback fallback ports when the config has no interfaces.
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            size: DEFAULT_PROBE_SIZE,
            timeout: DEFAULT_TIMEOUT,
            probes: 1,
            udp_loopback: Some((4996, 4997)),
        }
    }
}

pub struct ProbeResult {
    /// Round-trip time until the proof arrived.
    pub rtt: Duration,
    /// Full hash of the proved packet.
    pub packet_hash: reticulum::hash::Hash,
}

/// Send probes to a probe destination and measure the round-trip time of
/// the returned proof.
pub async fn probe(
    destination: &AddressHash,
    options: &ProbeOptions,
) -> Result<Vec<ProbeResult>, reticulum::error::RnsError> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnprobe",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    probe_with(&transport, destination, options).await
}

/// Probe using an existing transport instance.
pub async fn probe_with(
    transport: &Transport,
    destination: &AddressHash,
    options: &ProbeOptions,
) -> Result<Vec<ProbeResult>, reticulum::error::RnsError> {
    // Wait for the path to the probe destination
    // (Python prints a spinner while requesting the path).
    if !transport
        .await_path(destination, Some(options.timeout), None)
        .await
    {
        return Err(reticulum::error::RnsError::LinkNotReady);
    }

    let mut receipts = transport.receipt_events();
    let mut results = Vec::new();

    for _ in 0..options.probes {
        let payload: Vec<u8> = (0..options.size).map(|i| (i % 251) as u8).collect();

        let started = Instant::now();
        transport.send_to_destination(destination, &payload).await?;

        let proof = tokio::time::timeout(options.timeout, receipts.recv()).await;
        match proof {
            Ok(Ok(event)) => {
                results.push(ProbeResult {
                    rtt: started.elapsed(),
                    packet_hash: event.packet_hash,
                });
            }
            _ => return Err(reticulum::error::RnsError::LinkNotReady),
        }
    }

    Ok(results)
}

/// Run a probe *server*: a transport that proves packets to its probe
/// destination (what remote `rnprobe` instances probe against).
pub async fn serve(config_dir: &Path, instance_name: &str) -> std::sync::Arc<Transport> {
    let transport = std::sync::Arc::new(build_tool_transport(ToolTransportOptions {
        config_dir,
        instance_name,
        enable_transport: false,
        udp_loopback: Some((4997, 4996)),
    })
    .await);

    let probe = transport.enable_probe_destination().await;
    transport.send_announce(&probe, None).await;

    transport
}

/// Render probe results like the Python utility
/// ("Probe sent to <hash> :: valid proof received in X ms").
pub fn render_results(destination: &AddressHash, results: &[ProbeResult]) -> String {
    let mut out = String::new();
    for result in results {
        out.push_str(&format!(
            "Probe sent to {} :: valid proof received in {:.2} ms\n",
            destination,
            result.rtt.as_secs_f64() * 1000.0
        ));
    }
    if results.is_empty() {
        out.push_str(&format!("No valid proofs received from {destination}\n"));
    }
    out
}

/// UDP loopback probe demo (`rn probe --loopback`): a probe server on
/// the forward port and one probe against it. Returns the probed
/// destination alongside the results.
pub async fn run_loopback(
) -> Result<(AddressHash, Vec<ProbeResult>), reticulum::error::RnsError> {
    let server = build_tool_transport(ToolTransportOptions {
        config_dir: resolve_config_dir(None).as_path(),
        instance_name: "rnprobe-server",
        enable_transport: false,
        udp_loopback: Some((4997, 4996)),
    })
    .await;

    let probe_destination = server.enable_probe_destination().await;
    server.send_announce(&probe_destination, None).await;

    let client = build_tool_transport(ToolTransportOptions {
        config_dir: resolve_config_dir(None).as_path(),
        instance_name: "rnprobe-client",
        enable_transport: false,
        udp_loopback: Some((4996, 4997)),
    })
    .await;

    let destination = probe_destination.lock().await.desc.address_hash;
    let results = probe_with(&client, &destination, &ProbeOptions::default()).await?;
    Ok((destination, results))
}
