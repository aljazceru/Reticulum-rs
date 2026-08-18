//! `rnsh` — remote shell sessions over Reticulum channels
//! (Python `RNS/Utilities/rnsh`, channel-session protocol).
//!
//! The listener announces a SINGLE destination `rnsh` and starts an
//! exec session per established link: commands arrive as channel
//! messages (`SessionMessage::Command`), output is streamed back
//! (`SessionMessage::Output`), and the session ends with
//! `SessionMessage::Exit`. Interactive PTY streaming of the Python tool
//! requires a controlling terminal; the session protocol shape is
//! identical.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::channel::Message;
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;
use crate::common::{build_tool_transport, resolve_config_dir, ToolTransportOptions};
use serde::{Deserialize, Serialize};

pub const APP_NAME: &str = "rnsh";

/// One shell-session channel message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionMessage {
    /// A command to execute.
    Command(String),
    /// Chunk of command output.
    Output(Vec<u8>),
    /// Session ended with the command's return value.
    Exit(i32),
}

impl Message for SessionMessage {
    fn message_type(&self) -> u16 {
        // User-defined session messages (system range 0xff00+ avoided).
        0x0100
    }

    fn pack(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    fn unpack(packed: &[u8], _message_type: u16) -> Result<Self, reticulum::error::RnsError> {
        postcard::from_bytes(packed)
            .map_err(|_| reticulum::error::RnsError::ChannelMessageTooBig)
    }
}

/// Options for the shell listener (`rnsh --serve`).
pub struct ServeOptions {
    pub config_dir: PathBuf,
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            udp_loopback: Some((5001, 5002)),
        }
    }
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
    let identity = load_or_create(&identity_path)?;

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, "shell"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    // Establish a channel per incoming link and serve exec sessions.
    let event_transport = transport.clone();
    tokio::spawn(async move {
        let mut link_events = event_transport.in_link_events();
        loop {
            let Ok(event) = link_events.recv().await else { return };
            if !matches!(event.event, reticulum::destination::link::LinkEvent::Activated) {
                continue;
            }

            // Serve the session on this link.
            let session_transport = event_transport.clone();
            let link_id = event.id;
            tokio::spawn(async move {
                if let Some(link) = find_link(&session_transport, link_id).await {
                    run_session(session_transport, link).await;
                }
            });
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

async fn run_session(transport: Arc<Transport>, link: Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>) {
    let (channel, mut receiver) = match transport.mk_channel::<SessionMessage>(link).await {
        Ok(pair) => pair,
        Err(_) => return,
    };
    while let Ok(message) = receiver.recv().await {
        if let SessionMessage::Command(command) = message {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .output();

            match output {
                Ok(output) => {
                    let _ = channel
                        .send(&SessionMessage::Output(output.stdout))
                        .await;
                    let _ = channel
                        .send(&SessionMessage::Output(output.stderr))
                        .await;
                    let _ = channel
                        .send(&SessionMessage::Exit(output.status.code().unwrap_or(-1)))
                        .await;
                }
                Err(_) => {
                    let _ = channel.send(&SessionMessage::Exit(-1)).await;
                }
            }
        }
    }
}

fn load_or_create(path: &std::path::Path) -> Result<PrivateIdentity, String> {
    if path.exists() {
        if let Ok(hex) = std::fs::read_to_string(path) {
            if let Ok(identity) = PrivateIdentity::new_from_hex_string(hex.trim()) {
                return Ok(identity);
            }
        }
    }

    let identity = PrivateIdentity::new_from_rand(OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, identity.to_hex_string()).map_err(|e| e.to_string())?;
    Ok(identity)
}

/// Run one command in a session on the remote listener
/// (`rnsh --command <cmd> <destination>`).
pub async fn run_command(
    destination: &AddressHash,
    command: &str,
    options: &ServeOptions,
) -> Result<Vec<u8>, String> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnsh-client",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

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

    let (channel, mut receiver) = transport
        .mk_channel::<SessionMessage>(link)
        .await
        .map_err(|e| format!("channel error: {e:?}"))?;

    channel
        .send(&SessionMessage::Command(command.to_string()))
        .await
        .map_err(|e| format!("send failed: {e:?}"))?;

    let mut output = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while let Ok(Ok(message)) = tokio::time::timeout_at(deadline, receiver.recv()).await {
        match message {
            SessionMessage::Output(chunk) => output.extend_from_slice(&chunk),
            SessionMessage::Exit(_) => break,
            _ => {}
        }
    }

    Ok(output)
}
