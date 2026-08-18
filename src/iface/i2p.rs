//! I2P interface — Python `RNS.Interfaces.I2PInterface` parity (Phase 5.6)
//! via the SAMv3 bridge protocol spoken directly
//! (`RNS.vendor.i2plib`).
//!
//! The SAM bridge exposes stream transports over I2P:
//!
//! * each stream operation (`SESSION CREATE`, `STREAM CONNECT`,
//!   `STREAM ACCEPT`) opens a fresh TCP connection to the SAM bridge,
//!   performs the `HELLO` handshake and the command; the socket then
//!   carries the raw stream data
//! * sessions persist on the bridge side by name, so the server
//!   interface creates one transient session and accepts streams on it
//!   while client peers connect their own session's streams to the
//!   server's published destination
//!
//! Packets over an established stream are HDLC framed exactly like the
//! TCP interfaces (Python `I2PInterfacePeer.process_outgoing`).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::hdlc::Hdlc;
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Default SAM bridge address (Python `i2plib.DEFAULT_ADDRESS`).
pub const DEFAULT_SAM_ADDRESS: (&str, u16) = ("127.0.0.1", 7656);

/// Protocol MTU of I2P streams (Python `I2PInterfacePeer.HW_MTU`).
pub const HW_MTU: usize = 1064;

/// Nominal bitrate guess for I2P tunnels
/// (Python `I2PInterface.BITRATE_GUESS`).
pub const BITRATE_GUESS: u64 = 256_000;

/// Reconnect wait between tunnel re-establishments
/// (Python `I2PInterfacePeer.RECONNECT_WAIT`).
pub const RECONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The fixed SAM protocol versions (Python `i2plib.DEFAULT_MIN_VER`).
const SAM_MIN_VERSION: &str = "3.1";
const SAM_MAX_VERSION: &str = "3.1";

/// A parsed SAM reply line.
#[derive(Debug, Clone)]
pub struct SamReply {
    pub cmd: String,
    pub action: String,
    pub opts: std::collections::HashMap<String, String>,
}

impl SamReply {
    fn parse(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, ' ');
        let cmd = parts.next()?.to_string();
        let action = parts.next()?.to_string();
        let rest = parts.next().unwrap_or("");

        let mut opts = std::collections::HashMap::new();
        for token in rest.split(' ') {
            if token.is_empty() {
                continue;
            }
            match token.split_once('=') {
                Some((key, value)) => opts.insert(key.to_string(), value.to_string()),
                None => opts.insert(token.to_string(), "true".to_string()),
            };
        }

        Some(Self { cmd, action, opts })
    }

    pub fn ok(&self) -> bool {
        self.opts.get("RESULT").map(String::as_str) == Some("OK")
    }
}

/// Read one `\n`-terminated SAM reply line.
async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<SamReply, RnsError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return Err(RnsError::ConnectionError),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > 8192 {
                    return Err(RnsError::OutOfMemory);
                }
            }
            Err(_) => return Err(RnsError::ConnectionError),
        }
    }

    let text = String::from_utf8_lossy(&line).trim().to_string();
    SamReply::parse(&text).ok_or(RnsError::PacketError)
}

/// Open a connection to the SAM bridge and perform the HELLO handshake.
async fn sam_connect(sam_addr: &str) -> Result<TcpStream, RnsError> {
    let mut socket = TcpStream::connect(sam_addr)
        .await
        .map_err(|_| RnsError::ConnectionError)?;

    socket.set_nodelay(true).ok();

    let (mut reader, mut writer) = socket.split();

    writer
        .write_all(format!("HELLO VERSION MIN={SAM_MIN_VERSION} MAX={SAM_MAX_VERSION}\n").as_bytes())
        .await
        .map_err(|_| RnsError::ConnectionError)?;

    let mut buf = BufReader::new(&mut reader);
    let reply = read_reply(&mut buf).await?;
    if !reply.ok() {
        return Err(RnsError::ConnectionError);
    }

    drop(buf);

    Ok(socket)
}

/// A SAM session handle: creates a transient stream session and allows
/// opening/accepting streams over it
/// (Python `i2plib.create_session` + `stream_connect`/`stream_accept`).
pub struct SamSession {
    sam_addr: String,
    session_id: String,
    /// The SAM control connection that created this session. SAM bridges
    /// invalidate a session when this socket closes, so it must live for the
    /// entire lifetime of the session handle.
    _control_socket: TcpStream,
    /// Base64 local destination (from `SESSION STATUS`).
    pub destination: String,
}

impl SamSession {
    /// Create a transient STREAM session on the bridge
    /// (Python `i2plib.create_session(..., style="STREAM",
    /// destination=TRANSIENT)`).
    pub async fn create(sam_addr: &str, session_id: &str) -> Result<Self, RnsError> {
        let mut socket = sam_connect(sam_addr).await?;
        let destination;

        let command = format!(
            "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION=TRANSIENT\n"
        );

        {
            let (mut reader, mut writer) = socket.split();
            writer
                .write_all(command.as_bytes())
                .await
                .map_err(|_| RnsError::ConnectionError)?;

            let mut buf = BufReader::new(&mut reader);
            let reply = read_reply(&mut buf).await?;
            if !reply.ok() {
                return Err(RnsError::ConnectionError);
            }

            destination = reply
                .opts
                .get("DESTINATION")
                .cloned()
                .ok_or(RnsError::IncorrectHash)?;
        }

        Ok(Self {
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            destination,
            _control_socket: socket,
        })
    }

    /// Open an outbound stream to a base64 destination; the returned
    /// socket carries the raw stream data afterwards
    /// (Python `i2plib.stream_connect`).
    pub async fn stream_connect(&self, destination: &str) -> Result<TcpStream, RnsError> {
        let mut socket = sam_connect(&self.sam_addr).await?;

        let command =
            format!("STREAM CONNECT ID={} DESTINATION={destination} SILENT=false\n", self.session_id);

        {
            let (mut reader, mut writer) = socket.split();
            writer
                .write_all(command.as_bytes())
                .await
                .map_err(|_| RnsError::ConnectionError)?;

            let mut buf = BufReader::new(&mut reader);
            let reply = read_reply(&mut buf).await?;
            if !reply.ok() {
                return Err(RnsError::ConnectionError);
            }
        }

        Ok(socket)
    }

    /// Accept an inbound stream on the session; the returned socket
    /// carries the raw stream data afterwards
    /// (Python `i2plib.stream_accept`).
    pub async fn stream_accept(&self) -> Result<(TcpStream, String), RnsError> {
        let mut socket = sam_connect(&self.sam_addr).await?;

        let command = format!("STREAM ACCEPT ID={} SILENT=false\n", self.session_id);
        let remote;

        {
            let (mut reader, mut writer) = socket.split();
            writer
                .write_all(command.as_bytes())
                .await
                .map_err(|_| RnsError::ConnectionError)?;

            let mut buf = BufReader::new(&mut reader);
            let reply = read_reply(&mut buf).await?;
            if !reply.ok() {
                return Err(RnsError::ConnectionError);
            }

            remote = reply.opts.get("DESTINATION").cloned().unwrap_or_default();
        }

        Ok((socket, remote))
    }

    /// The `.b32.i2p` address of the local destination
    /// (Python `Destination.base32`: base32 of `sha256(destination)`
    /// truncated to 52 chars).
    pub fn b32(&self) -> String {
        destination_b32(&self.destination)
    }
}

/// Base64 (I2P alphabet) decoding for destination handling.
fn i2p_b64_decode(data: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let table: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .to_vec();

    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in data.as_bytes() {
        if byte == b'=' {
            break;
        }
        let value = table.iter().position(|&c| c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    Some(out)
}

/// Compute the `.b32.i2p` address of a base64 destination
/// (Python `Destination.base32`).
pub fn destination_b32(destination_b64: &str) -> String {
    use sha2::Digest;

    let bytes = i2p_b64_decode(destination_b64).unwrap_or_default();
    let hash = sha2::Sha256::digest(&bytes);

    // RFC 4648 base32, lower-case, truncated to 52 characters.
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in hash.iter() {
        acc = (acc << 8) | *byte as u32;
        bits += 8;
        while bits >= 5 && out.len() < 52 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }

    out
}

/// One HDLC-framed stream peer over an established I2P stream
/// (Python `I2PInterfacePeer`): either an initiator connecting out to a
/// published destination, or spawned by [`I2pServer`] for an accepted
/// stream.
pub struct I2pPeer {
    /// Base64 destination to connect to (initiator mode).
    pub target_destination: Option<String>,
    /// SAM bridge address.
    pub sam_addr: String,
    /// Session id for initiator connections.
    pub session_id: String,
    /// Already-established stream (spawned mode).
    pub connected_stream: Option<TcpStream>,
    /// Interface manager of the owning transport, used to flag tunnel
    /// synthesis once the stream is up (Python `wants_tunnel`).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
}

impl I2pPeer {
    /// Create a spawned peer for an accepted stream
    /// (Python `incoming_connection` handler).
    pub fn new_from_stream(name: impl Into<String>, stream: TcpStream) -> Self {
        let _ = name;
        Self {
            target_destination: None,
            sam_addr: String::new(),
            session_id: String::new(),
            connected_stream: Some(stream),
            iface_manager: None,
        }
    }

    /// Create an initiator peer connecting to a published destination
    /// (Python `I2PInterfacePeer(target_i2p_dest=...)`).
    pub fn new_initiator(sam_addr: &str, session_id: &str, destination: &str) -> Self {
        Self {
            target_destination: Some(destination.to_string()),
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            connected_stream: None,
            iface_manager: None,
        }
    }

    /// Attach the interface manager of the owning transport
    /// (used for tunnel-synthesis signalling).
    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();
        let inner = context.inner.clone();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            // Establish the stream: spawned peers use their handed-over
            // stream once; initiators (re)connect through SAM. (The guard
            // is scoped so it is never held across an await.)
            let connected = inner.lock().unwrap().connected_stream.take();
            let stream = match connected {
                Some(stream) => stream,
                None => {
                    let (target, sam_addr, session_id) = {
                        let inner = inner.lock().unwrap();
                        (
                            inner.target_destination.clone(),
                            inner.sam_addr.clone(),
                            inner.session_id.clone(),
                        )
                    };

                    let Some(target) = target else { break };

                    let session = match SamSession::create(&sam_addr, &session_id).await {
                        Ok(session) => session,
                        Err(_) => {
                            log::warn!(
                                "i2p_peer: could not create SAM session, retrying in {}s",
                                RECONNECT_WAIT.as_secs()
                            );
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    };

                    match session.stream_connect(&target).await {
                        Ok(stream) => {
                            log::info!("i2p_peer: tunnel established to {target}");
                            stream
                        }
                        Err(_) => {
                            log::warn!(
                                "i2p_peer: tunnel not ready, retrying in {}s",
                                RECONNECT_WAIT.as_secs()
                            );
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    }
                }
            };

            stats.set_online(true);

            // The tunnel is up: request tunnel synthesis from the
            // transport (Python sets `wants_tunnel = True` and
            // `Transport.synthesize_tunnel` runs).
            let manager_of = inner.lock().unwrap().iface_manager.clone();
            if let Some(manager) = manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
            }

            let (read_half, write_half) = stream.into_split();

            let rx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    use crate::iface::hdlc::HdlcDecoder;

                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames: std::vec::Vec<std::vec::Vec<u8>> =
                        std::vec::Vec::new();

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = stop.cancelled() => true,
                            result = stream.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    decoder.feed(&buffer[..n], |frame| {
                                        if frame.len() > 2 {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx.read().expect("ifac lock").clone();
                                            match crate::iface::ifac::decode(&frame, ifac.as_deref()) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("i2p_peer: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        if let Ok(packet) =
                                            Packet::deserialize(&mut InputBuffer::new(&plain))
                                        {
                                            stats.count_rx(plain.len());
                                            let _ = rx_channel
                                                .send(RxMessage { address: iface_address, packet })
                                                .await;
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            break;
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let tx_channel = tx_channel.clone();
                let channel_ifac = channel_ifac.clone();
                let mut stream = write_half;

                tokio::spawn(async move {
                    loop {
                        let mut buffer = [0u8; 2048];
                        let mut hdlc_buffer = [0u8; 2048 + 256];

                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            message = tx_channel.recv() => match message {
                                Some(message) => message,
                                None => break,
                            },
                        };

                        let packet = message.packet;
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire =
                                crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());

                            let mut framed = OutputBuffer::new(&mut hdlc_buffer[..]);
                            if Hdlc::encode(&wire, &mut framed).is_ok()
                                && stream.write_all(framed.as_slice()).await.is_ok()
                            {
                                let _ = stream.flush().await;
                                stats.count_tx(wire.len());
                            } else {
                                break;
                            }
                        }
                    }
                })
            };

            let _ = tokio::join!(tx_task, rx_task);
            stats.set_online(false);

            if inner.lock().unwrap().target_destination.is_none() {
                // spawned peer: done when its stream ends
                break;
            }

            log::info!("i2p_peer: tunnel lost, reconnecting in {}s", RECONNECT_WAIT.as_secs());
            tokio::time::sleep(RECONNECT_WAIT).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for I2pPeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// The I2P server interface: owns a connectable SAM session and spawns
/// an [`I2pPeer`] for every accepted stream
/// (Python `I2PInterface` with `connectable = yes`).
pub struct I2pServer {
    /// SAM bridge address.
    pub sam_addr: String,
    /// Session id (must be unique among local sessions).
    pub session_id: String,
    /// Established session once created; the destination is needed by
    /// embedders to publish (discovery data / manual peers).
    pub session: Arc<tokio::sync::RwLock<Option<Arc<SamSession>>>>,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl I2pServer {
    pub fn new<T: Into<String>>(
        sam_addr: T,
        session_id: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            sam_addr: sam_addr.into(),
            session_id: session_id.into(),
            session: Arc::new(tokio::sync::RwLock::new(None)),
            iface_manager,
        }
    }

    /// The published base64 destination of the server session, once
    /// established (empty string before).
    pub async fn destination(&self) -> String {
        self.session
            .read()
            .await
            .as_ref()
            .map(|session| session.destination.clone())
            .unwrap_or_default()
    }

    /// The published `.b32.i2p` address, once established.
    pub async fn b32(&self) -> String {
        self.session
            .read()
            .await
            .as_ref()
            .map(|session| session.b32())
            .unwrap_or_default()
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let sam_addr = { context.inner.lock().unwrap().sam_addr.clone() };
        let session_id = { context.inner.lock().unwrap().session_id.clone() };
        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let session_slot = { context.inner.lock().unwrap().session.clone() };

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            // Establish the connectable session.
            let session = match SamSession::create(&sam_addr, &session_id).await {
                Ok(session) => Arc::new(session),
                Err(_) => {
                    log::warn!(
                        "i2p_server: SAM session not ready (is the I2P router running with SAM enabled?), retrying"
                    );
                    tokio::time::sleep(RECONNECT_WAIT).await;
                    continue;
                }
            };

            log::info!(
                "i2p_server: session {} connectable as {}.b32.i2p",
                session_id,
                session.b32()
            );

            *session_slot.write().await = Some(session.clone());
            stats.set_online(true);

            // Accept loop: each accepted stream becomes a spawned peer.
            loop {
                if context.cancel.is_cancelled() {
                    break;
                }

                match session.stream_accept().await {
                    Ok((stream, remote)) => {
                        log::debug!("i2p_server: accepted stream from {remote}");

                        // Capture the server's access code for inheritance
                        // before locking the manager (no guard across await).
                        let inherited = context
                            .channel
                            .ifac
                            .read()
                            .expect("ifac lock")
                            .clone();

                        let mut manager = iface_manager.lock().await;
                        let address = manager.spawn(
                            I2pPeer::new_from_stream(format!("{session_id}-peer"), stream),
                            I2pPeer::spawn,
                        );

                        // Spawned peers inherit the server's access code
                        // (Python I2PInterfacePeer ifac inheritance).
                        if inherited.is_some() {
                            manager.with_iface_ifac(&address, |slot| {
                                *slot.write().expect("ifac lock") = inherited.clone();
                            });
                        }
                    }
                    Err(_) => {
                        log::warn!("i2p_server: stream accept failed, recreating session");
                        break;
                    }
                }
            }

            stats.set_online(false);
            *session_slot.write().await = None;
            tokio::time::sleep(RECONNECT_WAIT).await;
        }
    }
}

impl Interface for I2pServer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// Run an initiator I2P interface until cancelled: connects to a
/// published destination and keeps the peer alive
/// (Python `I2PInterface(peers=[...])`).
pub async fn i2p_peer_interface(
    transport: &crate::transport::Transport,
    sam_addr: &str,
    session_id: &str,
    destination: &str,
    name: &str,
) -> Result<crate::hash::AddressHash, RnsError> {
    let manager = transport.iface_manager();
    let mut manager = manager.lock().await;

    Ok(manager.spawn_named(
        name,
        I2pPeer::new_initiator(sam_addr, session_id, destination),
        I2pPeer::spawn,
    ))
}
