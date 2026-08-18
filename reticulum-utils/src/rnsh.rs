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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reticulum::channel::Message;
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::hash::AddressHash;
use reticulum::identity::Identity;
use reticulum::transport::Transport;
use crate::common::{
    build_tool_transport, load_or_create_private_identity, resolve_config_dir, ToolTransportOptions,
};
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
    /// Accept sessions from any identified or unidentified peer.
    pub allow_all: bool,
    /// Remote identities allowed to start shell sessions.
    pub allowed: Vec<AddressHash>,
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            allow_all: false,
            allowed: Vec::new(),
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
    tokio::spawn(async move {
        let mut link_events = event_transport.in_link_events();
        loop {
            let Ok(event) = link_events.recv().await else { return };
            match event.event {
                reticulum::destination::link::LinkEvent::Activated if allow_all => {
                    start_session(event_transport.clone(), event.id).await;
                }
                reticulum::destination::link::LinkEvent::RemoteIdentified(identity)
                    if !allow_all && remote_authorized(false, &allowed, Some(&identity)) =>
                {
                    start_session(event_transport.clone(), event.id).await;
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
) {
    let Some(link) = find_link(&transport, link_id).await else {
        return;
    };
    let (channel, mut receiver) = match transport.mk_channel::<SessionMessage>(link).await {
        Ok(pair) => pair,
        Err(_) => return,
    };

    tokio::spawn(async move {
        while let Ok(message) = receiver.recv().await {
            if let SessionMessage::Command(command) = message {
                let output = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .output();

                match output {
                    Ok(output) => {
                        if !output.stdout.is_empty()
                            && !send_when_ready(
                                &channel,
                                SessionMessage::Output(output.stdout),
                            )
                            .await
                        {
                            break;
                        }
                        if !output.stderr.is_empty()
                            && !send_when_ready(
                                &channel,
                                SessionMessage::Output(output.stderr),
                            )
                            .await
                        {
                            break;
                        }
                        let _ = send_when_ready(
                            &channel,
                            SessionMessage::Exit(output.status.code().unwrap_or(-1)),
                        )
                        .await;
                    }
                    Err(_) => {
                        let _ = send_when_ready(&channel, SessionMessage::Exit(-1)).await;
                    }
                }
            }
        }
    });
}

async fn send_when_ready(
    channel: &reticulum::channel::Channel<SessionMessage>,
    message: SessionMessage,
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
}
