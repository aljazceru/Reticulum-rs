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
    let (identity, _) =
        load_or_create_private_identity(&identity_path).map_err(|err| err.to_string())?;

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
    let allowed = std::sync::Arc::new(options.allowed.clone());
    transport
        .register_async_request_handler(&address, "command", {
            let allowed = allowed.clone();
            move |ctx| {
                let allowed = allowed.clone();
                async move {
                    if !allow_all {
                        let Some(remote) = &ctx.remote_identity else {
                            return None;
                        };
                        if !allowed.contains(&remote.address_hash) {
                            return None;
                        }
                    }

                    Some(execute_request(&ctx.data).await)
                }
            }
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

/// One line from an interactive session (`exit`/`quit` stop, `clear`
/// clears the screen, anything else is a command).
#[derive(Debug, PartialEq, Eq)]
pub enum InteractiveStep {
    Stop,
    Clear,
    Run(String),
}

pub fn interactive_step(line: &str) -> InteractiveStep {
    match line.trim().to_ascii_lowercase().as_str() {
        "exit" | "quit" => InteractiveStep::Stop,
        "clear" => InteractiveStep::Clear,
        _ => InteractiveStep::Run(line.trim().to_string()),
    }
}

/// Read stdin bytes from an inline string or a file. A file wins when
/// both are set.
pub fn stdin_payload(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = file {
        return std::fs::read(path)
            .map(Some)
            .map_err(|err| format!("could not read stdin file {}: {err}", path.display()));
    }
    Ok(inline.map(|text| text.as_bytes().to_vec()))
}

/// Encode a `command` request:
/// `[command, timeout, stdout_limit, stderr_limit, stdin]`.
/// `None` limits and stdin are msgpack nil (no cap / no stdin).
pub fn encode_request(
    command: &str,
    timeout_secs: u64,
    stdout_limit: Option<u64>,
    stderr_limit: Option<u64>,
    stdin: Option<&[u8]>,
) -> Vec<u8> {
    use rmp::encode as mp;
    let mut request = Vec::new();
    mp::write_array_len(&mut request, 5).ok();
    mp::write_str(&mut request, command).ok();
    mp::write_u64(&mut request, timeout_secs).ok();
    match stdout_limit {
        Some(limit) => {
            mp::write_u64(&mut request, limit).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    match stderr_limit {
        Some(limit) => {
            mp::write_u64(&mut request, limit).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    match stdin {
        Some(data) => {
            mp::write_bin(&mut request, data).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    request
}

/// Decode the request payload and execute the command
/// (Python `execute_received_command`).
pub async fn execute_request(data: &[u8]) -> Vec<u8> {
    use rmpv::Value;

    let mut cursor = std::io::Cursor::new(data);
    let Ok(Value::Array(items)) = rmpv::decode::read_value(&mut cursor) else {
        return pack_failure(now_secs());
    };

    let command = match items.first() {
        Some(value) => value
            .as_str()
            .map(|text| text.to_string())
            .or_else(|| {
                value
                    .as_slice()
                    .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
            })
            .unwrap_or_default(),
        None => String::new(),
    };

    // [command, timeout, o_limit, e_limit, stdin]
    let timeout_secs = items
        .get(1)
        .and_then(|value| value.as_u64().or_else(|| value.as_i64().map(|n| n as u64)))
        .unwrap_or(30)
        .clamp(1, 3600);
    let stdout_limit = optional_limit(items.get(2));
    let stderr_limit = optional_limit(items.get(3));
    let stdin = optional_bytes(items.get(4));

    let started = now_secs();

    // The request handler runs while the transport handler is locked, so
    // a blocking `Command::output()` (e.g. `sleep 100000`) would stall
    // the whole transport despite the client-supplied timeout. Run the
    // child asynchronously with a kill timer instead.
    Box::pin(async move {
        let mut command_line = tokio::process::Command::new("sh");
        command_line
            .arg("-c")
            .arg(&command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            });
        let mut child = match command_line.spawn() {
            Ok(child) => child,
            Err(_) => return pack_failure(started),
        };

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let mut stdin_pipe = child.stdin.take();

        let stdout_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdout = Vec::new();
            if let Some(mut pipe) = stdout_pipe {
                let _ = pipe.read_to_end(&mut stdout).await;
            }
            stdout
        });
        let stderr_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stderr = Vec::new();
            if let Some(mut pipe) = stderr_pipe {
                let _ = pipe.read_to_end(&mut stderr).await;
            }
            stderr
        });

        if let (Some(data), Some(mut pipe)) = (stdin.as_ref(), stdin_pipe.take()) {
            use tokio::io::AsyncWriteExt;
            let _ = pipe.write_all(data).await;
        }

        let status = tokio::select! {
            status = child.wait() => status.ok(),
            _ = tokio::time::sleep(Duration::from_secs(timeout_secs.max(1))) => {
                let _ = child.start_kill();
                None
            }
        };

        let stdout = match tokio::time::timeout(Duration::from_secs(1), stdout_task).await {
            Ok(Ok(stdout)) => stdout,
            _ => Vec::new(),
        };
        let stderr = match tokio::time::timeout(Duration::from_secs(1), stderr_task).await {
            Ok(Ok(stderr)) => stderr,
            _ => Vec::new(),
        };

        let Some(status) = status else {
            return pack_failure(started);
        };

        let stdout_len = stdout.len() as u64;
        let stderr_len = stderr.len() as u64;
        let stdout = cap_output(&stdout, stdout_limit);
        let stderr = cap_output(&stderr, stderr_limit);
        pack_success(
            status.code().unwrap_or(-1) as i64,
            &stdout,
            &stderr,
            stdout_len,
            stderr_len,
            started,
            now_secs(),
        )
    })
    .await
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn optional_limit(value: Option<&rmpv::Value>) -> Option<u64> {
    let value = value?;
    if value.is_nil() {
        return None;
    }
    value.as_u64().or_else(|| {
        value
            .as_i64()
            .filter(|number| *number >= 0)
            .map(|number| number as u64)
    })
}

fn optional_bytes(value: Option<&rmpv::Value>) -> Option<Vec<u8>> {
    match value? {
        rmpv::Value::Nil => None,
        rmpv::Value::Binary(bytes) => Some(bytes.clone()),
        rmpv::Value::String(text) => text.as_str().map(|text| text.as_bytes().to_vec()),
        _ => None,
    }
}

fn cap_output(data: &[u8], limit: Option<u64>) -> Vec<u8> {
    match limit {
        None => data.to_vec(),
        Some(0) => Vec::new(),
        Some(limit) => {
            let limit = limit as usize;
            if data.len() > limit {
                data[..limit].to_vec()
            } else {
                data.to_vec()
            }
        }
    }
}

fn pack_failure(started: f64) -> Vec<u8> {
    use rmp::encode as mp;
    let mut out = Vec::new();
    mp::write_array_len(&mut out, 8).ok();
    mp::write_bool(&mut out, false).ok();
    for _ in 0..5 {
        mp::write_nil(&mut out).ok();
    }
    mp::write_f64(&mut out, started).ok();
    mp::write_nil(&mut out).ok();
    out
}

fn pack_success(
    retval: i64,
    stdout: &[u8],
    stderr: &[u8],
    stdout_len: u64,
    stderr_len: u64,
    started: f64,
    concluded: f64,
) -> Vec<u8> {
    use rmp::encode as mp;
    let mut out = Vec::new();
    mp::write_array_len(&mut out, 8).ok();
    mp::write_bool(&mut out, true).ok();
    mp::write_i64(&mut out, retval).ok();
    mp::write_bin(&mut out, stdout).ok();
    mp::write_bin(&mut out, stderr).ok();
    mp::write_u64(&mut out, stdout_len).ok();
    mp::write_u64(&mut out, stderr_len).ok();
    mp::write_f64(&mut out, started).ok();
    mp::write_f64(&mut out, concluded).ok();
    out
}

/// Decode a command response into the remote status and captured output.
pub fn decode_exec_response(data: &[u8]) -> Result<ExecResult, String> {
    let mut cursor = std::io::Cursor::new(data);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|err| format!("invalid response: {err}"))?;
    let rmpv::Value::Array(items) = value else {
        return Err("invalid response shape".to_string());
    };
    let executed = items
        .first()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let retval = items
        .get(1)
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().map(|number| number as i64))
        })
        .unwrap_or(-1);
    let stdout = bytes_field(items.get(2));
    let stderr = bytes_field(items.get(3));
    let stdout_len = items
        .get(4)
        .and_then(|value| value.as_u64())
        .unwrap_or(stdout.len() as u64);
    let stderr_len = items
        .get(5)
        .and_then(|value| value.as_u64())
        .unwrap_or(stderr.len() as u64);
    Ok(ExecResult {
        executed,
        retval,
        stdout,
        stderr,
        stdout_len,
        stderr_len,
    })
}

fn bytes_field(value: Option<&rmpv::Value>) -> Vec<u8> {
    match value {
        Some(rmpv::Value::Binary(bytes)) => bytes.clone(),
        Some(rmpv::Value::String(text)) => text
            .as_str()
            .map(|text| text.as_bytes().to_vec())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Process status to propagate for a decoded result. A command that did
/// not run yields 248; otherwise the remote code, clamped to a byte.
pub fn remote_exit_code(result: &ExecResult) -> i32 {
    if !result.executed {
        return 248;
    }
    result.retval.clamp(0, 255) as i32
}

/// Options for executing a command remotely (`rnx <command>`).
#[derive(Clone)]
pub struct ExecOptions {
    pub config_dir: PathBuf,
    pub timeout: Duration,
    pub udp_loopback: Option<(u16, u16)>,
    /// Bytes written to the remote command's stdin.
    pub stdin: Option<Vec<u8>>,
    /// Maximum stdout bytes returned. `None` means no cap.
    pub stdout_limit: Option<u64>,
    /// Maximum stderr bytes returned. `None` means no cap.
    pub stderr_limit: Option<u64>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            timeout: Duration::from_secs(30),
            udp_loopback: Some((4996, 4997)),
            stdin: None,
            stdout_limit: None,
            stderr_limit: None,
        }
    }
}

pub struct ExecResult {
    pub executed: bool,
    pub retval: i64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Untruncated stdout length reported by the remote.
    pub stdout_len: u64,
    /// Untruncated stderr length reported by the remote.
    pub stderr_len: u64,
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
    let (client_identity, _) =
        load_or_create_private_identity(&options.config_dir.join("storage/identities/rnx"))
            .map_err(|err| err.to_string())?;
    let identify = link.lock().await.identify(&client_identity);
    if let Ok(packet) = identify {
        transport.send_packet(packet).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let request = encode_request(
        command,
        options.timeout.as_secs(),
        options.stdout_limit,
        options.stderr_limit,
        options.stdin.as_deref(),
    );

    let rid = transport
        .request(&link, "command", &request)
        .await
        .map_err(|e| format!("request error: {e:?}"))?;

    let response = transport
        .await_request_response(rid, options.timeout)
        .await
        .ok_or("no response from remote")?;

    decode_exec_response(&response)
}
