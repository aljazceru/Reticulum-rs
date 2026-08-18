//! `rnx` — remote command execution over Reticulum links
//! (Python `RNS/Utilities/rnx.py`).
//!
//! The listener announces a SINGLE destination `rnx.execute` and serves
//! `command` requests; the request payload is a msgpack list
//! `[command, timeout, o_limit, e_limit, stdin]` and the response is
//! `[executed, retval, stdout, stderr, stdout_len, stderr_len, started,
//! concluded]`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::hash::AddressHash;

use crate::common::{
    build_tool_transport, load_or_create_private_identity, resolve_config_dir, ToolTransportOptions,
};

pub const APP_NAME: &str = "rnx";

/// Options for the listener (`rnx --serve`).
pub struct ServeOptions {
    pub config_dir: PathBuf,
    /// Accept commands from anyone (Python `--allow-all`).
    pub allow_all: bool,
    /// Allowed remote identity hashes (Python `--allow`).
    pub allowed: Vec<AddressHash>,
    pub udp_loopback: Option<(u16, u16)>,
    /// Idle timeout for the listener before exiting (None = forever).
    pub idle_timeout: Option<Duration>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            allow_all: false,
            allowed: Vec::new(),
            udp_loopback: Some((4998, 4999)),
            idle_timeout: None,
        }
    }
}

/// Run an `rnx` listener until `idle_timeout` elapses (or forever).
/// Returns the announced destination hash.
pub async fn serve(options: &ServeOptions) -> Result<AddressHash, String> {
    let transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &options.config_dir,
            instance_name: "rnx",
            enable_transport: false,
            udp_loopback: options.udp_loopback,
        })
        .await,
    );

    // Identity persisted per-app like Python (`<storage>/identities/rnx`).
    let identity_path = options.config_dir.join("storage/identities/rnx");
    let (identity, _) = load_or_create_private_identity(&identity_path)
        .map_err(|err| err.to_string())?;

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, "execute"))
        .await;

    {
        let mut destination = destination.lock().await;
        destination.set_proof_strategy(ProofStrategy::None);
    }

    let address = destination.lock().await.desc.address_hash;

    // The command handler executes the command and builds the response.
    let allow_all = options.allow_all;
    let allowed = options.allowed.clone();
    transport
        .register_request_handler(&address, "command", move |ctx| {
            if !allow_all {
                let Some(remote) = &ctx.remote_identity else {
                    return None;
                };
                if !allowed.contains(&remote.address_hash) {
                    return None;
                }
            }

            Some(execute_request(&ctx.data))
        })
        .await;

    transport.send_announce(&destination, None).await;

    log::info!("rnx listening for commands on {address}");

    // Park until the idle timeout (if any).
    if let Some(timeout) = options.idle_timeout {
        tokio::time::sleep(timeout).await;
    } else {
        std::future::pending::<()>().await;
    }

    Ok(address)
}

/// Decode the request payload and execute the command
/// (Python `execute_received_command`).
pub fn execute_request(data: &[u8]) -> Vec<u8> {
    use rmpv::Value;

    let mut cursor = std::io::Cursor::new(data);
    let Ok(Value::Array(items)) = rmpv::decode::read_value(&mut cursor) else {
        return pack_result(None);
    };

    let command = items
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output();

    let concluded = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    match output {
        Ok(output) => pack_result(Some((output, started, concluded))),
        Err(_) => pack_result(None),
    }
}

/// Pack the response list (Python `result` layout).
fn pack_result(result: Option<(std::process::Output, f64, f64)>) -> Vec<u8> {
    use rmp::encode as mp;

    let mut out = Vec::new();
    mp::write_array_len(&mut out, 8).ok();

    match result {
        Some((output, started, concluded)) => {
            mp::write_bool(&mut out, true).ok();
            mp::write_i64(&mut out, output.status.code().unwrap_or(-1) as i64).ok();
            mp::write_bin(&mut out, &output.stdout).ok();
            mp::write_bin(&mut out, &output.stderr).ok();
            mp::write_u64(&mut out, output.stdout.len() as u64).ok();
            mp::write_u64(&mut out, output.stderr.len() as u64).ok();
            mp::write_f64(&mut out, started).ok();
            mp::write_f64(&mut out, concluded).ok();
        }
        None => {
            mp::write_bool(&mut out, false).ok();
            for _ in 0..5 {
                mp::write_nil(&mut out).ok();
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            mp::write_f64(&mut out, now).ok();
            mp::write_nil(&mut out).ok();
        }
    }

    out
}

/// Options for executing a command remotely (`rnx <command>`).
pub struct ExecOptions {
    pub config_dir: PathBuf,
    pub timeout: Duration,
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            timeout: Duration::from_secs(30),
            udp_loopback: Some((4996, 4997)),
        }
    }
}

pub struct ExecResult {
    pub executed: bool,
    pub retval: i64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Execute `command` on the remote listener identified by the announce
/// of an `rnx` destination.
pub async fn execute(
    destination: &AddressHash,
    command: &str,
    options: &ExecOptions,
) -> Result<ExecResult, String> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnx-client",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    if !transport
        .await_path(destination, Some(options.timeout), None)
        .await
    {
        return Err(format!("no path to {destination}"));
    }

    let identity = transport
        .recall(destination)
        .await
        .ok_or("could not recall identity")?;

    let desc = reticulum::destination::DestinationDesc {
        identity,
        address_hash: *destination,
        name: DestinationName::new(APP_NAME, "execute"),
    };

    let link = transport.link(desc).await;

    let mut events = transport.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;

    // Identify so the listener's allow list can match us.
    let (client_identity, _) = load_or_create_private_identity(
        &options.config_dir.join("storage/identities/rnx"),
    )
    .map_err(|err| err.to_string())?;
    let identify = link.lock().await.identify(&client_identity);
    if let Ok(packet) = identify {
        transport.send_packet(packet).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut request = Vec::new();
    use rmp::encode as mp;
    mp::write_array_len(&mut request, 5).ok();
    mp::write_str(&mut request, command).ok();
    mp::write_u64(&mut request, options.timeout.as_secs()).ok();
    mp::write_u64(&mut request, 1024 * 1024).ok();
    mp::write_u64(&mut request, 1024 * 1024).ok();
    mp::write_bin(&mut request, &[]).ok();

    let rid = transport
        .request(&link, "command", &request)
        .await
        .map_err(|e| format!("request error: {e:?}"))?;

    let response = transport
        .await_request_response(rid, options.timeout)
        .await
        .ok_or("no response from remote")?;

    let mut cursor = std::io::Cursor::new(&response);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e| format!("invalid response: {e}"))?;

    let rmpv::Value::Array(items) = value else {
        return Err("invalid response shape".to_string());
    };

    let executed = items.first().and_then(|v| v.as_bool()).unwrap_or(false);
    let retval = items.get(1).and_then(|v| v.as_i64()).unwrap_or(-1);
    let stdout = items
        .get(2)
        .and_then(|v| match v {
            rmpv::Value::Binary(bytes) => Some(bytes.to_vec()),
            _ => None,
        })
        .unwrap_or_default();
    let stderr = items
        .get(3)
        .and_then(|v| match v {
            rmpv::Value::Binary(bytes) => Some(bytes.to_vec()),
            _ => None,
        })
        .unwrap_or_default();

    Ok(ExecResult {
        executed,
        retval,
        stdout,
        stderr,
    })
}
