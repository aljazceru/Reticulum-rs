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
//! * sessions persist on the bridge side by name. A connectable server
//!   reuses one destination private key, stored the way Python
//!   `I2PController.server_tunnel` stores it (`storage/i2p/<hash>.i2p`).
//!   Without that key the session stays `DESTINATION=TRANSIENT`. Client
//!   peers connect their own session's streams to the published destination
//!
//! Packets over an established stream are HDLC framed exactly like the
//! TCP interfaces (Python `I2PInterfacePeer.process_outgoing`).

use std::path::{Path, PathBuf};
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

/// Python `Destination.default_sig_type` (`EdDSA_SHA512_Ed25519`).
const SAM_SIGNATURE_EDDSA_SHA512_ED25519: &str = "7";

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

/// Open a TCP connection to the SAM bridge. The caller performs HELLO.
async fn tcp_sam(sam_addr: &str) -> Result<TcpStream, RnsError> {
    let socket = TcpStream::connect(sam_addr)
        .await
        .map_err(|_| RnsError::ConnectionError)?;
    socket.set_nodelay(true).ok();
    Ok(socket)
}

/// Open a connection to the SAM bridge and perform the HELLO handshake.
async fn sam_connect(sam_addr: &str) -> Result<TcpStream, RnsError> {
    let mut socket = tcp_sam(sam_addr).await?;
    hello(&mut socket).await?;
    Ok(socket)
}

async fn sam_command<S>(io: &mut S, command: &str) -> Result<SamReply, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    io.write_all(command.as_bytes())
        .await
        .map_err(|_| RnsError::ConnectionError)?;
    read_reply(io).await
}

async fn hello<S>(io: &mut S) -> Result<(), RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let reply = sam_command(
        io,
        &format!("HELLO VERSION MIN={SAM_MIN_VERSION} MAX={SAM_MAX_VERSION}\n"),
    )
    .await?;
    if !reply.ok() {
        return Err(RnsError::ConnectionError);
    }
    Ok(())
}

/// `DEST GENERATE` on a fresh SAM socket (Python `i2plib.new_destination`).
/// The reply has no `RESULT`; the private key is `PRIV`.
async fn generate_private_key<S>(io: &mut S) -> Result<String, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    hello(io).await?;
    let reply = sam_command(
        io,
        &format!("DEST GENERATE SIGNATURE_TYPE={SAM_SIGNATURE_EDDSA_SHA512_ED25519}\n"),
    )
    .await?;
    reply
        .opts
        .get("PRIV")
        .cloned()
        .filter(|key| !key.is_empty())
        .ok_or(RnsError::PacketError)
}

/// `SESSION CREATE`. `destination` is `TRANSIENT` or a private-key blob
/// (Python `destination.private_key.base64`). The returned string is the
/// public destination from `SESSION STATUS`.
async fn session_create<S>(
    io: &mut S,
    session_id: &str,
    destination: &str,
) -> Result<String, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let reply = sam_command(
        io,
        &format!("SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={destination}\n"),
    )
    .await?;
    if !reply.ok() {
        return Err(RnsError::ConnectionError);
    }
    reply
        .opts
        .get("DESTINATION")
        .cloned()
        .ok_or(RnsError::IncorrectHash)
}

/// Read a persisted I2P private key. `Ok(None)` when the file is absent.
///
/// A trailing newline is stripped: SAM requests are one line, and a text
/// editor saving the Python key file would otherwise split `SESSION CREATE`.
fn read_destination_key(path: &Path) -> Result<Option<String>, RnsError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let key = text.trim();
            if key.is_empty() {
                Err(RnsError::Storage)
            } else {
                Ok(Some(key.to_string()))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(RnsError::Storage),
    }
}

fn write_destination_key(path: &Path, key: &str) -> Result<(), RnsError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| RnsError::Storage)?;
        }
    }
    // Python writes `private_key.base64` with no extra newline.
    std::fs::write(path, key).map_err(|_| RnsError::Storage)
}

/// Load or mint the private key Python passes as `DESTINATION=`.
///
/// `connect` is one SAM socket per call. Generation uses its own socket
/// (Python `new_destination` closes that connection before
/// `create_session`).
async fn destination_parameter<S, F, Fut>(
    key_path: Option<&Path>,
    connect: &mut F,
) -> Result<String, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<S, RnsError>>,
{
    let Some(path) = key_path else {
        return Ok("TRANSIENT".to_string());
    };
    if let Some(key) = read_destination_key(path)? {
        return Ok(key);
    }
    let mut io = connect().await?;
    let key = generate_private_key(&mut io).await?;
    drop(io);
    write_destination_key(path, &key)?;
    Ok(key)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Key file for a connectable I2P interface
/// (Python `I2PController.server_tunnel`).
///
/// `storage_path` is `Reticulum.storagepath`. `identity_hash` is
/// `Transport.identity.hash` (the truncated 16-byte hash), not a full
/// SHA-256. An existing old-format file wins over the name+identity file.
pub fn i2p_destination_key_path(
    storage_path: impl AsRef<Path>,
    interface_name: &str,
    identity_hash: &[u8],
) -> PathBuf {
    let i2p_dir = storage_path.as_ref().join("i2p");
    let name_hash = sha256_bytes(interface_name.as_bytes());
    let old_path = i2p_dir.join(format!("{}.i2p", hex_encode(&sha256_bytes(&name_hash))));
    if old_path.is_file() {
        return old_path;
    }
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(&name_hash);
    material.extend_from_slice(&sha256_bytes(identity_hash));
    i2p_dir.join(format!("{}.i2p", hex_encode(&sha256_bytes(&material))))
}

/// A SAM session handle: one stream session, plus connect/accept
/// (Python `i2plib.create_session` + `stream_connect`/`stream_accept`).
///
/// `S` defaults to [`TcpStream`]. Tests pass a scripted socket instead of
/// a live bridge.
pub struct SamSession<S = TcpStream> {
    sam_addr: String,
    session_id: String,
    /// The SAM control connection that created this session. SAM bridges
    /// invalidate a session when this socket closes, so it must live for the
    /// entire lifetime of the session handle.
    _control_socket: S,
    /// Base64 public destination (from `SESSION STATUS`, not the private key).
    pub destination: String,
}

impl<S> SamSession<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Create a STREAM session over sockets from `connect`.
    ///
    /// `key_path` persists the destination the way
    /// `I2PController.server_tunnel` does. `None` asks for
    /// `DESTINATION=TRANSIENT` (existing [`SamSession::create`] callers).
    /// Each `connect` call is a new SAM socket: tests inject a fake
    /// transcript here instead of opening TCP.
    pub async fn create_on<F, Fut>(
        sam_addr: &str,
        session_id: &str,
        key_path: Option<&Path>,
        mut connect: F,
    ) -> Result<Self, RnsError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<S, RnsError>>,
    {
        let destination_param = destination_parameter(key_path, &mut connect).await?;
        let mut socket = connect().await?;
        hello(&mut socket).await?;
        let destination = session_create(&mut socket, session_id, &destination_param).await?;
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

        let command = format!(
            "STREAM CONNECT ID={} DESTINATION={destination} SILENT=false\n",
            self.session_id
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

impl SamSession<TcpStream> {
    /// Create a transient STREAM session on the bridge
    /// (Python `i2plib.create_session(..., destination=TRANSIENT)`).
    ///
    /// Source-compatible with existing callers. Pass a key file to
    /// [`SamSession::create_with_key`] or [`SamSession::create_on`] for a
    /// stable destination.
    pub async fn create(sam_addr: &str, session_id: &str) -> Result<Self, RnsError> {
        Self::create_on(sam_addr, session_id, None, || tcp_sam(sam_addr)).await
    }

    /// Create a STREAM session that reuses the private key at `key_path`
    /// (Python `I2PController.server_tunnel`). The same file makes a later
    /// create request the same `DESTINATION=`.
    pub async fn create_with_key(
        sam_addr: &str,
        session_id: &str,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, RnsError> {
        let path = key_path.as_ref();
        Self::create_on(sam_addr, session_id, Some(path), || tcp_sam(sam_addr)).await
    }
}

/// Base64 (I2P alphabet) decoding for destination handling.
fn i2p_b64_decode(data: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let table: Vec<u8> =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".to_vec();

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
                    let mut frames: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();

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

            log::info!(
                "i2p_peer: tunnel lost, reconnecting in {}s",
                RECONNECT_WAIT.as_secs()
            );
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
    /// Persisted destination private key. `None` keeps
    /// `DESTINATION=TRANSIENT` so [`I2pServer::new`] stays source-compatible.
    destination_key: Option<PathBuf>,
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
            destination_key: None,
        }
    }

    /// Reuse the private key at `key_path` for the published destination.
    pub fn with_destination_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.destination_key = Some(key_path.into());
        self
    }

    /// Persist the destination under Python's `storage/i2p/<hash>.i2p` name.
    ///
    /// `identity_hash` is `Transport.identity.hash` (truncated).
    pub fn with_stable_destination(
        self,
        storage_path: impl AsRef<Path>,
        interface_name: &str,
        identity_hash: &[u8],
    ) -> Self {
        self.with_destination_key(i2p_destination_key_path(
            storage_path,
            interface_name,
            identity_hash,
        ))
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
        let destination_key = { context.inner.lock().unwrap().destination_key.clone() };

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            // Establish the connectable session. A configured key file is
            // reused so the published address survives a restart.
            let session = match &destination_key {
                Some(path) => SamSession::create_with_key(&sam_addr, &session_id, path).await,
                None => SamSession::create(&sam_addr, &session_id).await,
            };
            let session = match session {
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
                        let inherited = context.channel.ifac.read().expect("ifac lock").clone();

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "reticulum-i2p-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One scripted SAM socket. Replies are served in order; every written
    /// line is appended to `log`.
    struct ScriptedSam {
        incoming: VecDeque<u8>,
        write_buf: Vec<u8>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl AsyncRead for ScriptedSam {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.incoming.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(this.incoming.len());
            let bytes: Vec<u8> = this.incoming.drain(..n).collect();
            buf.put_slice(&bytes);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedSam {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.write_buf.extend_from_slice(data);
            while let Some(pos) = this.write_buf.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = this.write_buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line).trim().to_string();
                this.log.lock().unwrap().push(text);
            }
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Successive SAM connections, each with its own reply lines.
    struct Transcript {
        stages: Mutex<VecDeque<Vec<String>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Transcript {
        fn new(stages: Vec<Vec<&str>>) -> Self {
            let stages = stages
                .into_iter()
                .map(|lines| lines.into_iter().map(str::to_string).collect())
                .collect();
            Self {
                stages: Mutex::new(stages),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn connect(&self) -> Result<ScriptedSam, RnsError> {
            let lines = self
                .stages
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(RnsError::ConnectionError)?;
            let mut incoming = VecDeque::new();
            for line in lines {
                incoming.extend(line.into_bytes());
                incoming.push_back(b'\n');
            }
            Ok(ScriptedSam {
                incoming,
                write_buf: Vec::new(),
                log: self.log.clone(),
            })
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    fn requested_destination(requests: &[String]) -> String {
        requests
            .iter()
            .find(|line| line.starts_with("SESSION CREATE"))
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|token| token.strip_prefix("DESTINATION="))
            })
            .unwrap()
            .to_string()
    }

    #[test]
    fn destination_key_path_matches_python_server_tunnel() {
        // Vectors from Python `hashlib.sha256`, which is `Identity.full_hash`,
        // and `hexrep(..., delimit=False)`. Name "testiface", identity hash
        // sixteen 0x11 bytes (truncated `Transport.identity.hash`).
        let tmp = TempDir::new();
        let storage = tmp.0.join("storage");
        let identity = [0x11u8; 16];
        let path = i2p_destination_key_path(&storage, "testiface", &identity);
        assert_eq!(
            path,
            storage
                .join("i2p")
                .join("8d290c37f9bf4deb5548fad60d53c789a3e521c1b6019c94cebbe8b7c50b81a4.i2p")
        );

        let old = storage
            .join("i2p")
            .join("83a4a268a09ee04976ae488dcfa91c2a248b364166858523d3dded9efcbde406.i2p");
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, "legacy-key").unwrap();
        assert_eq!(
            i2p_destination_key_path(&storage, "testiface", &identity),
            old
        );

        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let server = I2pServer::new("127.0.0.1:7656", "sid", manager).with_stable_destination(
            &storage,
            "testiface",
            &identity,
        );
        assert_eq!(server.destination_key.as_deref(), Some(old.as_path()));
    }

    #[tokio::test]
    async fn second_create_requests_the_same_destination() {
        let tmp = TempDir::new();
        let key_path = tmp.0.join("i2p").join("node.i2p");
        let private_key = "stable-priv-key";
        let public_dest = "public-dest";

        let first = Transcript::new(vec![
            vec![
                "HELLO REPLY RESULT=OK VERSION=3.1",
                "DEST REPLY PUB=public-dest PRIV=stable-priv-key",
            ],
            vec![
                "HELLO REPLY RESULT=OK VERSION=3.1",
                "SESSION STATUS RESULT=OK DESTINATION=public-dest",
            ],
        ]);
        let session = SamSession::create_on("injected", "sess", Some(key_path.as_path()), || {
            let conn = first.connect();
            async move { conn }
        })
        .await
        .expect("first create");
        assert_eq!(session.destination, public_dest);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), private_key);
        let first_requests = first.requests();
        assert!(
            first_requests
                .iter()
                .any(|line| line == "DEST GENERATE SIGNATURE_TYPE=7"),
            "missing key must be minted with DEST GENERATE: {first_requests:?}"
        );
        assert_eq!(requested_destination(&first_requests), private_key);
        drop(session);

        let second = Transcript::new(vec![vec![
            "HELLO REPLY RESULT=OK VERSION=3.1",
            "SESSION STATUS RESULT=OK DESTINATION=public-dest",
        ]]);
        let again = SamSession::create_on("injected", "sess", Some(key_path.as_path()), || {
            let conn = second.connect();
            async move { conn }
        })
        .await
        .expect("second create");
        let second_requests = second.requests();
        assert!(
            second_requests
                .iter()
                .all(|line| !line.starts_with("DEST GENERATE")),
            "existing key must not be regenerated: {second_requests:?}"
        );
        assert_eq!(
            requested_destination(&second_requests),
            requested_destination(&first_requests)
        );
        assert_eq!(again.destination, public_dest);
    }

    #[tokio::test]
    async fn newline_terminated_key_file_is_the_same_destination() {
        let tmp = TempDir::new();
        let key_path = tmp.0.join("node.i2p");
        std::fs::write(&key_path, "same-key\n").unwrap();
        let transcript = Transcript::new(vec![vec![
            "HELLO REPLY RESULT=OK VERSION=3.1",
            "SESSION STATUS RESULT=OK DESTINATION=pub",
        ]]);
        let _session = SamSession::create_on("injected", "sess", Some(key_path.as_path()), || {
            let conn = transcript.connect();
            async move { conn }
        })
        .await
        .expect("create from stored key");
        assert_eq!(requested_destination(&transcript.requests()), "same-key");
    }

    #[tokio::test]
    async fn create_without_key_file_stays_transient() {
        let transcript = Transcript::new(vec![vec![
            "HELLO REPLY RESULT=OK VERSION=3.1",
            "SESSION STATUS RESULT=OK DESTINATION=transient-pub",
        ]]);
        let session = SamSession::create_on("injected", "sess", None, || {
            let conn = transcript.connect();
            async move { conn }
        })
        .await
        .expect("transient create");
        assert_eq!(session.destination, "transient-pub");
        assert_eq!(requested_destination(&transcript.requests()), "TRANSIENT");
        assert!(transcript
            .requests()
            .iter()
            .all(|line| !line.starts_with("DEST GENERATE")));
    }
}
