//! `rnsh` — remote shell sessions over Reticulum channels
//! (Python `RNS/Utilities/rnsh`, channel-session protocol).
//!
//! Wire-compatible with the Python rnsh protocol: messages are
//! msgpack-packed channel messages with types `0xac00`-`0xac07`
//! (`MSG_MAGIC = 0xac`), the handshake is
//! identify → `VersionInfoMessage` exchange → `ExecuteCommandMessage`,
//! stream data flows as `StreamDataMessage` (2-byte big-endian header:
//! stream id with EOF/compressed flags) and the session ends with
//! `CommandExitedMessage`.

use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reticulum::channel::Message;
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::error::RnsError;
use reticulum::hash::AddressHash;
use reticulum::identity::Identity;
use reticulum::transport::Transport;

use crate::common::{
    build_tool_transport, load_or_create_private_identity, resolve_config_dir, ToolTransportOptions,
};

pub const APP_NAME: &str = "rnsh";

/// Python `rnsh` protocol constants.
const MSG_MAGIC: u16 = 0xac;
const PROTOCOL_VERSION: u32 = 1;

/// Rust rnsh software version reported in the handshake.
const SW_VERSION: &str = concat!("reticulum-rs ", env!("CARGO_PKG_VERSION"));

const MSG_NOOP: u16 = MSG_MAGIC << 8;
const MSG_WINDOW_SIZE: u16 = (MSG_MAGIC << 8) | 2;
const MSG_EXECUTE_COMMAND: u16 = (MSG_MAGIC << 8) | 3;
const MSG_STREAM_DATA: u16 = (MSG_MAGIC << 8) | 4;
const MSG_VERSION_INFO: u16 = (MSG_MAGIC << 8) | 5;
const MSG_ERROR: u16 = (MSG_MAGIC << 8) | 6;
const MSG_COMMAND_EXITED: u16 = (MSG_MAGIC << 8) | 7;

pub const STREAM_ID_STDIN: u16 = 0;
pub const STREAM_ID_STDOUT: u16 = 1;
pub const STREAM_ID_STDERR: u16 = 2;

/// One rnsh protocol channel message (Python `RNS/Utilities/rnsh/protocol.py`).
#[derive(Debug, Clone)]
pub enum RnshMessage {
    Noop,
    WindowSize {
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    },
    ExecuteCommand {
        cmdline: Option<Vec<String>>,
        pipe_stdin: bool,
        pipe_stdout: bool,
        pipe_stderr: bool,
        term: Option<String>,
    },
    StreamData {
        stream_id: u16,
        eof: bool,
        data: Vec<u8>,
    },
    VersionInfo {
        sw_version: String,
        protocol_version: u32,
    },
    Error {
        msg: Option<String>,
        fatal: bool,
    },
    CommandExited {
        return_code: Option<i32>,
    },
}

/// Serialize an `rmpv::Value` tree to msgpack bytes.
pub fn test_pack_value(value: &rmpv::Value) -> Vec<u8> {
    rmpv_to_bytes(value)
}

fn rmpv_to_bytes(value: &rmpv::Value) -> Vec<u8> {
    use rmp::encode::*;
    let mut out = Vec::new();
    match value {
        rmpv::Value::Nil => {
            let _ = write_nil(&mut out);
        }
        rmpv::Value::Boolean(b) => {
            let _ = write_bool(&mut out, *b);
        }
        rmpv::Value::Integer(i) => {
            if let Some(u) = i.as_u64() {
                // Minimal representation, matching Python umsgpack.
                let _ = write_uint(&mut out, u);
            } else {
                let _ = write_sint(&mut out, i.as_i64().unwrap_or(0));
            }
        }
        rmpv::Value::String(s) => {
            let _ = write_str(&mut out, s.as_str().unwrap_or(""));
        }
        rmpv::Value::Array(items) => {
            let _ = write_array_len(&mut out, items.len() as u32);
            for item in items {
                let mut part = rmpv_to_bytes(item);
                out.append(&mut part);
            }
        }
        rmpv::Value::Map(pairs) => {
            let _ = write_map_len(&mut out, pairs.len() as u32);
            for (key, val) in pairs {
                let mut part = rmpv_to_bytes(key);
                out.append(&mut part);
                let mut part = rmpv_to_bytes(val);
                out.append(&mut part);
            }
        }
        _ => {}
    }
    out
}

fn pack_opt_u32(value: Option<u32>) -> rmpv::Value {
    match value {
        Some(v) => v.into(),
        None => rmpv::Value::Nil,
    }
}

fn unpack_opt_u32(value: &rmpv::Value) -> Option<u32> {
    value.as_u64().map(|v| v as u32)
}

fn unpack_opt_string(value: &rmpv::Value) -> Option<String> {
    match value {
        rmpv::Value::String(s) => s.as_str().map(str::to_string),
        _ => None,
    }
}

fn unpack_opt_bool(value: &rmpv::Value) -> bool {
    matches!(value, rmpv::Value::Boolean(true))
}

impl Message for RnshMessage {
    fn message_type(&self) -> u16 {
        match self {
            Self::Noop => MSG_NOOP,
            Self::WindowSize { .. } => MSG_WINDOW_SIZE,
            Self::ExecuteCommand { .. } => MSG_EXECUTE_COMMAND,
            Self::StreamData { .. } => MSG_STREAM_DATA,
            Self::VersionInfo { .. } => MSG_VERSION_INFO,
            Self::Error { .. } => MSG_ERROR,
            Self::CommandExited { .. } => MSG_COMMAND_EXITED,
        }
    }

    fn pack(&self) -> Vec<u8> {
        match self {
            Self::Noop => Vec::new(),
            Self::WindowSize { rows, cols, hpix, vpix } => {
                let tuple = rmpv::Value::Array(vec![
                    pack_opt_u32(*rows),
                    pack_opt_u32(*cols),
                    pack_opt_u32(*hpix),
                    pack_opt_u32(*vpix),
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::ExecuteCommand { cmdline, pipe_stdin, pipe_stdout, pipe_stderr, term } => {
                let cmdline = match cmdline {
                    Some(args) => rmpv::Value::Array(
                        args.iter().map(|a| rmpv::Value::String(a.as_str().into())).collect(),
                    ),
                    None => rmpv::Value::Nil,
                };
                let tuple = rmpv::Value::Array(vec![
                    cmdline,
                    (*pipe_stdin).into(),
                    (*pipe_stdout).into(),
                    (*pipe_stderr).into(),
                    rmpv::Value::Nil, // tcflags (terminal attributes, unused)
                    match term {
                        Some(t) => rmpv::Value::String(t.as_str().into()),
                        None => rmpv::Value::Nil,
                    },
                    rmpv::Value::Nil, // rows
                    rmpv::Value::Nil, // cols
                    rmpv::Value::Nil, // hpix
                    rmpv::Value::Nil, // vpix
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::StreamData { stream_id, eof, data } => {
                // 2-byte big-endian header: id | eof<<15 (compression
                // unsupported on this side).
                let header = (stream_id & 0x3fff) | if *eof { 0x8000 } else { 0 };
                let mut packed = Vec::with_capacity(2 + data.len());
                packed.extend_from_slice(&header.to_be_bytes());
                packed.extend_from_slice(data);
                packed
            }
            Self::VersionInfo { sw_version, protocol_version } => {
                let tuple = rmpv::Value::Array(vec![
                    rmpv::Value::String(sw_version.as_str().into()),
                    (*protocol_version).into(),
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::Error { msg, fatal } => {
                let tuple = rmpv::Value::Array(vec![
                    match msg {
                        Some(m) => rmpv::Value::String(m.as_str().into()),
                        None => rmpv::Value::Nil,
                    },
                    (*fatal).into(),
                    rmpv::Value::Nil, // data dict
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::CommandExited { return_code } => match return_code {
                Some(code) => rmpv_to_bytes(&rmpv::Value::from(*code)),
                None => rmpv_to_bytes(&rmpv::Value::Nil),
            },
        }
    }

    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
        match message_type {
            MSG_NOOP => Ok(Self::Noop),
            MSG_WINDOW_SIZE => {
                let value: rmpv::Value =
                    rmpv::decode::value::read_value(&mut &packed[..]).map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::WindowSize {
                    rows: items.first().and_then(unpack_opt_u32),
                    cols: items.get(1).and_then(unpack_opt_u32),
                    hpix: items.get(2).and_then(unpack_opt_u32),
                    vpix: items.get(3).and_then(unpack_opt_u32),
                })
            }
            MSG_EXECUTE_COMMAND => {
                let value: rmpv::Value =
                    rmpv::decode::value::read_value(&mut &packed[..]).map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                let cmdline = match items.first() {
                    Some(rmpv::Value::Array(args)) => {
                        Some(args.iter().filter_map(unpack_opt_string).collect::<Vec<String>>())
                    }
                    _ => None,
                };
                Ok(Self::ExecuteCommand {
                    cmdline,
                    pipe_stdin: items.get(1).map(unpack_opt_bool).unwrap_or(false),
                    pipe_stdout: items.get(2).map(unpack_opt_bool).unwrap_or(false),
                    pipe_stderr: items.get(3).map(unpack_opt_bool).unwrap_or(false),
                    term: items.get(5).and_then(unpack_opt_string),
                })
            }
            MSG_STREAM_DATA => {
                if packed.len() < 2 {
                    return Err(RnsError::ChannelMessageTooBig);
                }
                let header = u16::from_be_bytes([packed[0], packed[1]]);
                Ok(Self::StreamData {
                    stream_id: header & 0x3fff,
                    eof: header & 0x8000 > 0,
                    data: packed[2..].to_vec(),
                })
            }
            MSG_VERSION_INFO => {
                let value: rmpv::Value =
                    rmpv::decode::value::read_value(&mut &packed[..]).map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::VersionInfo {
                    sw_version: items
                        .first()
                        .and_then(unpack_opt_string)
                        .unwrap_or_default(),
                    protocol_version: items.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                })
            }
            MSG_ERROR => {
                let value: rmpv::Value =
                    rmpv::decode::value::read_value(&mut &packed[..]).map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::Error {
                    msg: items.first().and_then(unpack_opt_string),
                    fatal: items.get(1).map(unpack_opt_bool).unwrap_or(false),
                })
            }
            MSG_COMMAND_EXITED => {
                let value: rmpv::Value =
                    rmpv::decode::value::read_value(&mut &packed[..]).map_err(|_| RnsError::ChannelMessageTooBig)?;
                Ok(Self::CommandExited {
                    return_code: value.as_i64().map(|v| v as i32),
                })
            }
            _ => Err(RnsError::ChannelMessageTooBig),
        }
    }
}

/// Options for the shell listener (`rn sh --serve`).
pub struct ServeOptions {
    pub config_dir: PathBuf,
    /// Accept sessions from any identified or unidentified peer.
    pub allow_all: bool,
    /// Remote identities allowed to start shell sessions.
    pub allowed: Vec<AddressHash>,
    /// Default command for sessions (Python `-l -- <cmd>`); remote
    /// command lines replace it when remote commands are allowed.
    pub default_command: Option<Vec<String>>,
    /// Execute remote command lines (Python default; `-C` disables).
    pub allow_remote_command: bool,
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            allow_all: false,
            allowed: Vec::new(),
            default_command: None,
            allow_remote_command: true,
            udp_loopback: Some((5001, 5002)),
        }
    }
}

fn remote_authorized(
    allow_all: bool,
    allowed: &HashSet<AddressHash>,
    remote: Option<&Identity>,
) -> bool {
    allow_all
        || remote.is_some_and(|identity| allowed.contains(&identity.address_hash))
}

/// Run an `rnsh` listener. Returns the announced destination hash; the
/// listener runs until cancelled by dropping the transport.
pub async fn serve(options: &ServeOptions) -> Result<AddressHash, String> {
    let transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &options.config_dir,
            instance_name: "rnsh",
            enable_transport: false,
            udp_loopback: options.udp_loopback,
        })
        .await,
    );

    let identity_path = options.config_dir.join("storage/identities/rnsh");
    let (identity, _) = load_or_create_private_identity(&identity_path)
        .map_err(|err| err.to_string())?;

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, "shell"))
        .await;
    destination
        .lock()
        .await
        .set_proof_strategy(ProofStrategy::All);
    let address = destination.lock().await.desc.address_hash;

    // Establish a channel per incoming link and serve exec sessions.
    let event_transport = transport.clone();
    let allow_all = options.allow_all;
    let allowed: HashSet<AddressHash> = options.allowed.iter().copied().collect();
    let default_command = options.default_command.clone();
    let allow_remote_command = options.allow_remote_command;
    tokio::spawn(async move {
        let mut link_events = event_transport.in_link_events();
        loop {
            let Ok(event) = link_events.recv().await else { return };
            match event.event {
                reticulum::destination::link::LinkEvent::Activated if allow_all => {
                    start_session(
                        event_transport.clone(),
                        event.id,
                        default_command.clone(),
                        allow_remote_command,
                    )
                    .await;
                }
                reticulum::destination::link::LinkEvent::RemoteIdentified(identity)
                    if !allow_all && remote_authorized(false, &allowed, Some(&identity)) =>
                {
                    start_session(
                        event_transport.clone(),
                        event.id,
                        default_command.clone(),
                        allow_remote_command,
                    )
                    .await;
                }
                reticulum::destination::link::LinkEvent::RemoteIdentified(_) if !allow_all => {
                    log::warn!("rnsh: unauthorized identity attempted a session");
                    let _ = event_transport.link_close(event.id).await;
                }
                _ => {}
            }
        }
    });

    transport.send_announce(&destination, None).await;
    log::info!("rnsh listening for sessions on {address}");

    Ok(address)
}

/// Locate an established inbound link by id.
async fn find_link(
    transport: &Arc<Transport>,
    link_id: reticulum::destination::link::LinkId,
) -> Option<Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>> {
    transport.find_in_link(&link_id).await
}

async fn start_session(
    transport: Arc<Transport>,
    link_id: reticulum::destination::link::LinkId,
    default_command: Option<Vec<String>>,
    allow_remote_command: bool,
) {
    let Some(link) = find_link(&transport, link_id).await else {
        return;
    };
    let (channel, mut receiver) = match transport.mk_channel::<RnshMessage>(link).await {
        Ok(pair) => pair,
        Err(_) => return,
    };

    tokio::spawn(async move {
        let mut child: Option<tokio::process::Child> = None;
        let mut version_exchanged = false;

        while let Ok(message) = receiver.recv().await {
            match message {
                RnshMessage::VersionInfo { protocol_version, .. } => {
                    if protocol_version != PROTOCOL_VERSION {
                        let _ = send_when_ready(
                            &channel,
                            RnshMessage::Error {
                                msg: Some("Incompatible protocol".into()),
                                fatal: true,
                            },
                        )
                        .await;
                        break;
                    }
                    // Reply with our version info (Python listener
                    // handshake).
                    if !send_when_ready(
                        &channel,
                        RnshMessage::VersionInfo {
                            sw_version: SW_VERSION.to_string(),
                            protocol_version: PROTOCOL_VERSION,
                        },
                    )
                    .await
                    {
                        break;
                    }
                    version_exchanged = true;
                }
                RnshMessage::ExecuteCommand { cmdline, pipe_stdin, .. } if version_exchanged => {
                    let mut command = default_command.clone().unwrap_or_default();
                    match cmdline {
                        Some(remote) if !remote.is_empty() => {
                            if !allow_remote_command {
                                let _ = send_when_ready(
                                    &channel,
                                    RnshMessage::Error {
                                        msg: Some(
                                            "Remote command line not allowed by listener".into(),
                                        ),
                                        fatal: true,
                                    },
                                )
                                .await;
                                break;
                            }
                            command = remote;
                        }
                        _ => {}
                    }

                    if command.is_empty() {
                        command = vec![std::env::var("SHELL").unwrap_or_else(|_| "sh".into())];
                    }

                    let mut builder = tokio::process::Command::new(&command[0]);
                    builder.args(&command[1..]);
                    builder.stdout(std::process::Stdio::piped());
                    builder.stderr(std::process::Stdio::piped());
                    builder.stdin(
                        if pipe_stdin {
                            std::process::Stdio::piped()
                        } else {
                            std::process::Stdio::null()
                        },
                    );
                    builder.env("TERM", std::env::var("TERM").unwrap_or_else(|_| "xterm".into()));

                    match builder.spawn() {
                        Ok(spawned) => child = Some(spawned),
                        Err(err) => {
                            let _ = send_when_ready(
                                &channel,
                                RnshMessage::Error {
                                    msg: Some(format!("Could not start command: {err}")),
                                    fatal: true,
                                },
                            )
                            .await;
                            break;
                        }
                    }
                    break;
                }
                _ => {}
            }
        }

        let Some(mut child) = child else { return };

        // Stream stdout and stderr back as StreamDataMessages.
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();

        let channel_out = channel.clone();
        let stdout_task = tokio::spawn(async move {
            if let Some(mut stdout) = stdout {
                let mut buffer = [0u8; 4096];
                loop {
                    match stdout.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !send_when_ready(
                                &channel_out,
                                RnshMessage::StreamData {
                                    stream_id: STREAM_ID_STDOUT,
                                    eof: false,
                                    data: buffer[..n].to_vec(),
                                },
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }
                }
            }
            let _ = send_when_ready(
                &channel_out,
                RnshMessage::StreamData {
                    stream_id: STREAM_ID_STDOUT,
                    eof: true,
                    data: Vec::new(),
                },
            )
            .await;
        });

        let channel_err = channel.clone();
        let stderr_task = tokio::spawn(async move {
            if let Some(mut stderr) = stderr {
                let mut buffer = [0u8; 4096];
                loop {
                    match stderr.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !send_when_ready(
                                &channel_err,
                                RnshMessage::StreamData {
                                    stream_id: STREAM_ID_STDERR,
                                    eof: false,
                                    data: buffer[..n].to_vec(),
                                },
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }
                }
            }
        });

        // If the initiator wants to pipe stdin, forward stream data to
        // the child process.
        if let Some(mut stdin) = stdin {
            let channel_stdin = channel.clone();
            tokio::spawn(async move {
                let mut receiver = channel_stdin.subscribe();
                while let Ok(message) = receiver.recv().await {
                    if let RnshMessage::StreamData { stream_id: STREAM_ID_STDIN, data, eof } =
                        message
                    {
                        if !data.is_empty() && stdin.write_all(&data).await.is_err() {
                            break;
                        }
                        if eof {
                            stdin.flush().await.ok();
                            break;
                        }
                    }
                }
            });
        }

        let _ = stdout_task.await;
        let _ = stderr_task.await;

        let status = child.wait().await;
        let return_code = status.ok().and_then(|s| s.code());
        let _ = send_when_ready(
            &channel,
            RnshMessage::CommandExited { return_code },
        )
        .await;
    });
}

async fn send_when_ready(
    channel: &reticulum::channel::Channel<RnshMessage>,
    message: RnshMessage,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if channel.is_ready().await && channel.send(&message).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Outcome of a remote command session.
pub struct CommandOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

/// Run one command in a session on the remote listener
/// (`rnsh --command <cmd> <destination>`), streaming stdin when piped.
pub async fn run_command(
    destination: &AddressHash,
    command: &str,
    options: &ServeOptions,
) -> Result<CommandOutcome, String> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnsh-client",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;
    let identity_path = options.config_dir.join("storage/identities/rnsh");
    let (client_identity, _) = load_or_create_private_identity(&identity_path)
        .map_err(|err| err.to_string())?;

    if !transport
        .await_path(destination, Some(Duration::from_secs(15)), None)
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
        name: DestinationName::new(APP_NAME, "shell"),
    };

    let link = transport.link(desc).await;

    let mut events = transport.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;
    let identify = link
        .lock()
        .await
        .identify(&client_identity)
        .map_err(|err| format!("identify failed: {err:?}"))?;
    transport.send_packet(identify).await;

    let (channel, mut receiver) = transport
        .mk_channel::<RnshMessage>(link)
        .await
        .map_err(|e| format!("channel error: {e:?}"))?;

    // Handshake: exchange version info (Python initiator sends first and
    // waits for the listener's reply).
    if !send_when_ready(
        &channel,
        RnshMessage::VersionInfo {
            sw_version: SW_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await
    {
        return Err("could not send version info".into());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut peer_version = false;
    while !peer_version {
        match tokio::time::timeout_at(deadline, receiver.recv()).await {
            Ok(Ok(RnshMessage::VersionInfo { sw_version, protocol_version })) => {
                log::info!(
                    "connected server version info: sw {sw_version}, proto {protocol_version}"
                );
                if protocol_version != PROTOCOL_VERSION {
                    return Err("incompatible protocol".into());
                }
                peer_version = true;
            }
            Ok(Ok(RnshMessage::Error { msg, .. })) => {
                return Err(msg.unwrap_or_else(|| "remote error".into()));
            }
            _ => return Err("protocol error (no version info)".into()),
        }
    }

    // Whether stdin is a pipe determines pipe_stdin on the wire. An
    // already-closed or empty stdin (e.g. `/dev/null`) is not advertised
    // at all: the Python listener closes the child's stdin on EOF and
    // then encourages a prompt process shutdown 50 ms later, which can
    // kill a fast command before its output has been streamed back.
    let (stdin_is_pipe, stdin_data) = read_initial_stdin();
    // `-c` takes a shell command line: run it through the shell on the
    // remote side (the Python tool passes an argument list after `--`).
    let cmdline: Vec<String> = if command.is_empty() {
        Vec::new()
    } else {
        vec!["sh".to_string(), "-c".to_string(), command.to_string()]
    };

    if !send_when_ready(
        &channel,
        RnshMessage::ExecuteCommand {
            cmdline: Some(cmdline),
            pipe_stdin: stdin_is_pipe,
            pipe_stdout: true,
            pipe_stderr: true,
            term: std::env::var("TERM").ok(),
        },
    )
    .await
    {
        return Err("could not send execute command".into());
    }

    // Stream piped stdin to the remote until EOF. Python's initiator
    // buffers all of stdin at startup and streams it after the execute
    // command, which also gives the listener time to start pumping the
    // command output before any EOF arrives.
    if stdin_is_pipe {
        if !stdin_data.is_empty()
            && !send_when_ready(
                &channel,
                RnshMessage::StreamData {
                    stream_id: STREAM_ID_STDIN,
                    eof: false,
                    data: stdin_data,
                },
            )
            .await
        {
            return Err("could not stream stdin".into());
        }

        // All stdin data was buffered at startup and has been sent;
        // signal EOF after a short grace so the listener's output pump
        // gets a turn before its prompt-shutdown heuristic fires.
        tokio::time::sleep(Duration::from_millis(750)).await;
        let _ = send_when_ready(
            &channel,
            RnshMessage::StreamData {
                stream_id: STREAM_ID_STDIN,
                eof: true,
                data: Vec::new(),
            },
        )
        .await;
    }

    let mut outcome = CommandOutcome {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_code: None,
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while let Ok(Ok(message)) = tokio::time::timeout_at(deadline, receiver.recv()).await {
        match message {
            RnshMessage::StreamData { stream_id: STREAM_ID_STDOUT, data, .. } => {
                outcome.stdout.extend_from_slice(&data);
            }
            RnshMessage::StreamData { stream_id: STREAM_ID_STDERR, data, .. } => {
                outcome.stderr.extend_from_slice(&data);
            }
            RnshMessage::CommandExited { return_code } => {
                outcome.exit_code = return_code;
                break;
            }
            RnshMessage::Error { msg, fatal: true, .. } => {
                return Err(msg.unwrap_or_else(|| "remote error".into()));
            }
            RnshMessage::Error { .. } => {}
            _ => {}
        }
    }

    Ok(outcome)
}

fn atty_or_true() -> bool {
    // Best-effort TTY detection without an extra dependency: assume a
    // terminal when stdout is a character device.
    unsafe { libc::isatty(0) == 1 }
}

/// Read the initial stdin contents (Python's initiator buffers all of
/// stdin at startup). Returns whether a stdin pipe should be advertised
/// and the buffered data: a TTY or a non-empty read means the remote
/// should pipe stdin, an immediately-empty closed stdin does not.
fn read_initial_stdin() -> (bool, Vec<u8>) {
    if atty_or_true() {
        return (true, Vec::new());
    }
    use std::io::Read;
    let mut buffer = Vec::new();
    let _ = std::io::stdin().lock().read_to_end(&mut buffer);
    if buffer.is_empty() {
        // An immediately-closed, empty stdin advertises no pipe at all.
        (false, buffer)
    } else {
        (true, buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use reticulum::identity::PrivateIdentity;

    #[test]
    fn authentication_is_deny_by_default_and_allow_all_is_explicit() {
        let authorized = PrivateIdentity::new_from_rand(OsRng);
        let unauthorized = PrivateIdentity::new_from_rand(OsRng);
        let allowed = HashSet::from([*authorized.address_hash()]);

        assert!(remote_authorized(
            false,
            &allowed,
            Some(authorized.as_identity())
        ));
        assert!(!remote_authorized(
            false,
            &allowed,
            Some(unauthorized.as_identity())
        ));
        assert!(!remote_authorized(false, &allowed, None));
        assert!(!remote_authorized(false, &HashSet::new(), None));
        assert!(remote_authorized(true, &HashSet::new(), None));
    }

    #[test]
    fn stream_data_packing_matches_python_format() {
        let message = RnshMessage::StreamData {
            stream_id: STREAM_ID_STDOUT,
            eof: false,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let packed = message.pack();
        assert_eq!(packed, vec![0x00, 0x01, 0xde, 0xad, 0xbe, 0xef]);

        let unpacked =
            RnshMessage::unpack(&packed, MSG_STREAM_DATA).expect("unpack stream data");
        match unpacked {
            RnshMessage::StreamData { stream_id, eof, data } => {
                assert_eq!(stream_id, STREAM_ID_STDOUT);
                assert!(!eof);
                assert_eq!(data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("unexpected {other:?}"),
        }

        let eof = RnshMessage::StreamData {
            stream_id: STREAM_ID_STDIN,
            eof: true,
            data: Vec::new(),
        }
        .pack();
        assert_eq!(eof, vec![0x80, 0x00]);
    }

    #[test]
    fn version_info_round_trips() {
        let message = RnshMessage::VersionInfo {
            sw_version: "test".into(),
            protocol_version: 1,
        };
        let packed = message.pack();
        // msgpack fixarray of 2 elements
        assert_eq!(packed[0], 0x92);
        let unpacked =
            RnshMessage::unpack(&packed, MSG_VERSION_INFO).expect("unpack version info");
        match unpacked {
            RnshMessage::VersionInfo { sw_version, protocol_version } => {
                assert_eq!(sw_version, "test");
                assert_eq!(protocol_version, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn execute_command_round_trips() {
        let message = RnshMessage::ExecuteCommand {
            cmdline: Some(vec!["echo".into(), "hi".into()]),
            pipe_stdin: true,
            pipe_stdout: true,
            pipe_stderr: false,
            term: Some("xterm".into()),
        };
        let packed = message.pack();
        let unpacked =
            RnshMessage::unpack(&packed, MSG_EXECUTE_COMMAND).expect("unpack exec");
        match unpacked {
            RnshMessage::ExecuteCommand { cmdline, pipe_stdin, pipe_stdout, pipe_stderr, term } => {
                assert_eq!(cmdline, Some(vec!["echo".into(), "hi".into()]));
                assert!(pipe_stdin);
                assert!(pipe_stdout);
                assert!(!pipe_stderr);
                assert_eq!(term, Some("xterm".into()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
