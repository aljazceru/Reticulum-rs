//! Local shared-instance interfaces, a port of `RNS/Interfaces/LocalInterface.py`
//! (v1.4.2) including its `BackboneInterface` model.
//!
//! * [`LocalServer`] is the shared instance: a listener on `127.0.0.1`
//!   (default port 37428, `Reticulum.SHARED_INSTANCE_PORT`) or on the
//!   abstract unix domain socket `\0rns/<instance_name>`. Every accepted
//!   connection is spawned as a full peer interface in the same
//!   [`InterfaceManager`], so the daemon transport relays frames between
//!   all connected local clients and its own interfaces - exactly like
//!   `LocalServerInterface.incoming_connection` spawning a
//!   `LocalClientInterface` per client.
//! * [`LocalClient`] connects this transport to an existing shared instance
//!   with the same HDLC framing.
//!
//! Wire format on both sides is HDLC framing (`0x7E` flags, `0x7D` escapes)
//! around serialized Reticulum packets, identical to `TCPInterface`. Empty
//! frames (`0x7E 0x7E`) are keepalives and are ignored, matching
//! `if len(frame) > RNS.Reticulum.HEADER_MINSIZE` in `LocalInterface.py`.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::iface::hdlc::Hdlc;
use crate::iface::hdlc::HdlcDecoder;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;
use super::InterfaceManager;

/// `Reticulum.SHARED_INSTANCE_PORT`
pub const SHARED_INSTANCE_PORT: u16 = 37428;

/// `LocalClientInterface.RECONNECT_WAIT` in seconds
pub const RECONNECT_WAIT: Duration = Duration::from_secs(8);

/// `LocalClientInterface.HW_MTU`
const HW_MTU: usize = 262144;

/// Python ignores frames of at most `Reticulum.HEADER_MINSIZE` bytes
/// (2 + 1 + TRUNCATED_HASHLENGTH/8 = 19).
const HEADER_MINSIZE: usize = 19;

const PACKET_TRACE: bool = false;

/// Address of a shared Reticulum instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedInstanceAddress {
    /// TCP shared instance (`shared_instance_type = tcp`), always on loopback
    Tcp { port: u16 },
    /// Abstract unix domain socket (`shared_instance_type = domain`),
    /// bound to `\0rns/<instance_name>` (`LocalInterface.py` address format).
    #[cfg(unix)]
    UnixAbstract { instance_name: String },
}

impl SharedInstanceAddress {
    pub fn tcp(port: u16) -> Self {
        Self::Tcp { port }
    }

    /// Abstract socket address `\0rns/<instance_name>` (the leading NUL byte
    /// marks the Linux abstract namespace).
    #[cfg(unix)]
    pub fn unix_abstract(instance_name: impl Into<String>) -> Self {
        Self::UnixAbstract {
            instance_name: instance_name.into(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Tcp { port } => format!("127.0.0.1:{port}"),
            #[cfg(unix)]
            Self::UnixAbstract { instance_name } => format!("\0rns/{instance_name}"),
        }
    }
}

/// Owned halves of an accepted or connected local stream.
enum LocalStreamRead {
    Tcp(tokio::net::tcp::OwnedReadHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedReadHalf),
}

enum LocalStreamWrite {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedWriteHalf),
}

async fn stream_read(stream: &mut LocalStreamRead, buffer: &mut [u8]) -> io::Result<usize> {
    match stream {
        LocalStreamRead::Tcp(stream) => stream.read(buffer).await,
        #[cfg(unix)]
        LocalStreamRead::Unix(stream) => stream.read(buffer).await,
    }
}

async fn stream_write_all(stream: &mut LocalStreamWrite, data: &[u8]) -> io::Result<()> {
    match stream {
        LocalStreamWrite::Tcp(stream) => {
            stream.write_all(data).await?;
            stream.flush().await
        }
        #[cfg(unix)]
        LocalStreamWrite::Unix(stream) => {
            stream.write_all(data).await?;
            stream.flush().await
        }
    }
}

enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

/// Shared instance listener (`LocalServerInterface`).
///
/// Every accepted client connection is spawned as a [`LocalClient`] peer
/// interface in the same interface manager, making local clients full peers
/// of the daemon transport.
pub struct LocalServer {
    address: SharedInstanceAddress,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl LocalServer {
    pub fn new(
        address: SharedInstanceAddress,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            address,
            iface_manager,
        }
    }

    pub fn address(&self) -> &SharedInstanceAddress {
        &self.address
    }

    async fn bind(address: &SharedInstanceAddress) -> Option<Listener> {
        match address {
            SharedInstanceAddress::Tcp { port } => {
                let listener = TcpListener::bind(("127.0.0.1", *port)).await.ok()?;
                Some(Listener::Tcp(listener))
            }
            #[cfg(unix)]
            SharedInstanceAddress::UnixAbstract { instance_name } => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr as UnixSocketAddr;

                let socket_address =
                    UnixSocketAddr::from_abstract_name(format!("rns/{instance_name}").as_bytes())
                        .ok()?;
                let listener = std::os::unix::net::UnixListener::bind_addr(&socket_address).ok()?;
                listener.set_nonblocking(true).ok()?;
                let listener = tokio::net::UnixListener::from_std(listener).ok()?;
                Some(Listener::Unix(listener))
            }
        }
    }

    async fn accept(listener: &mut Listener) -> Option<LocalClient> {
        match listener {
            Listener::Tcp(listener) => {
                let (stream, peer) = listener.accept().await.ok()?;
                let _ = stream.set_nodelay(true);
                Some(LocalClient::new_from_stream(
                    format!("{peer}"),
                    StreamType::Tcp(stream),
                ))
            }
            #[cfg(unix)]
            Listener::Unix(listener) => {
                let (stream, _) = listener.accept().await.ok()?;
                Some(LocalClient::new_from_stream(
                    "local".to_string(),
                    StreamType::Unix(stream),
                ))
            }
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let address = context.inner.lock().unwrap().address.clone();
        let iface_manager = context.inner.lock().unwrap().iface_manager.clone();
        let stats = context.channel.stats.clone();

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = Self::bind(&address).await;

            let mut listener = match listener {
                Some(listener) => listener,
                None => {
                    log::warn!("local_server: couldn't bind to <{}>", address.describe());
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            log::info!(
                "local_server: shared instance listening on <{}>",
                address.describe()
            );
            stats.set_online(true);

            // Drain tx messages: actual clients are spawned as their own
            // interfaces in the manager (see TcpServer::spawn).
            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            loop {
                if context.cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    client = Self::accept(&mut listener) => {
                        if let Some(client) = client {
                            let mut iface_manager = iface_manager.lock().await;
                            let address =
                                iface_manager.spawn(client, LocalClient::spawn);
                            // Interfaces spawned by the shared instance are
                            // local client interfaces
                            // (Python `is_local_shared_instance`).
                            iface_manager.set_iface_local_client(&address);
                        }
                    }
                }
            }

            stats.set_online(false);
            let _ = tx_task.await;
        }
    }
}

impl Interface for LocalServer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// An already connected stream handed to a [`LocalClient`].
pub enum StreamType {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

/// Local client interface (`LocalClientInterface`).
///
/// Used in two modes, matching the Python class:
///
/// * spawned by [`LocalServer`] for an accepted connection
///   (`connected_socket` mode, no reconnect),
/// * created directly to attach this transport to an existing shared
///   instance (reconnects with [`RECONNECT_WAIT`] while cancelled).
pub struct LocalClient {
    name: String,
    address: Option<SharedInstanceAddress>,
    stream: Option<StreamType>,
}

impl LocalClient {
    /// Create a client that connects to a shared instance at `address`.
    pub fn new(name: impl Into<String>, address: SharedInstanceAddress) -> Self {
        Self {
            name: name.into(),
            address: Some(address),
            stream: None,
        }
    }

    /// Create a client for an already connected stream (server side).
    pub fn new_from_stream(name: impl Into<String>, stream: StreamType) -> Self {
        Self {
            name: name.into(),
            address: None,
            stream: Some(stream),
        }
    }

    async fn connect(address: &SharedInstanceAddress) -> Option<StreamType> {
        match address {
            SharedInstanceAddress::Tcp { port } => {
                let stream = TcpStream::connect(("127.0.0.1", *port)).await.ok()?;
                let _ = stream.set_nodelay(true);
                Some(StreamType::Tcp(stream))
            }
            #[cfg(unix)]
            SharedInstanceAddress::UnixAbstract { instance_name } => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr as UnixSocketAddr;

                let socket_address =
                    UnixSocketAddr::from_abstract_name(format!("rns/{instance_name}").as_bytes())
                        .ok()?;
                let stream = std::os::unix::net::UnixStream::connect_addr(&socket_address).ok()?;
                stream.set_nonblocking(true).ok()?;
                Some(StreamType::Unix(
                    tokio::net::UnixStream::from_std(stream).ok()?,
                ))
            }
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let name = context.inner.lock().unwrap().name.clone();
        let address = context.inner.lock().unwrap().address.clone();
        let mut stream = context.inner.lock().unwrap().stream.take();

        if let Some(address) = &address {
            log::debug!(
                "local_client[{}]: connecting to shared instance <{}>",
                name,
                address.describe()
            );
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        // A pre-set stream is a server-accepted connection that never
        // reconnects (Python `connected_socket` mode).
        let server_side = stream.is_some();

        'outer: loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let connected = match stream.take() {
                Some(stream) => Some(stream),
                None => {
                    let Some(target) = address.as_ref() else {
                        break;
                    };

                    // drain tx queue while disconnected, retry periodically
                    let mut tx_channel = tx_channel.lock().await;
                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => break,
                        Some(_) = tx_channel.recv() => continue,
                        connected = Self::connect(target) => connected,
                    }
                }
            };

            let stream = match connected {
                Some(stream) => stream,
                None => {
                    stats.set_online(false);

                    log::info!(
                        "local_client[{}]: couldn't connect to <{}>, retrying",
                        name,
                        address.as_ref().map(|a| a.describe()).unwrap_or_default()
                    );

                    let retry_at = tokio::time::Instant::now() + RECONNECT_WAIT;
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            biased;
                            _ = context.cancel.cancelled() => break 'outer,
                            Some(_) = tx_channel.recv() => {}
                            _ = tokio::time::sleep_until(retry_at) => break,
                        }
                    }
                    continue;
                }
            };

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let (read_half, write_half) = match stream {
                StreamType::Tcp(stream) => {
                    let (read, write) = stream.into_split();
                    (LocalStreamRead::Tcp(read), LocalStreamWrite::Tcp(write))
                }
                #[cfg(unix)]
                StreamType::Unix(stream) => {
                    let (read, write) = stream.into_split();
                    (LocalStreamRead::Unix(read), LocalStreamWrite::Unix(write))
                }
            };

            stats.set_online(true);
            log::debug!(
                "local_client[{}]: connected to <{}>",
                name,
                address
                    .as_ref()
                    .map(|a| a.describe())
                    .unwrap_or_else(|| "client".into())
            );

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames = Vec::new();

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            result = stream_read(&mut stream, &mut buffer[..]) => match result {
                                Ok(0) => {
                                    log::debug!("local_client: connection closed");
                                    stop.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    frames.clear();
                                    decoder.feed(&buffer[..n], |frame| {
                                        // ignore keepalive and noise frames like
                                        // LocalInterface.handle_hdlc
                                        if frame.len() > HEADER_MINSIZE {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        match Packet::deserialize(&mut InputBuffer::new(&frame)) {
                                            Ok(packet) => {
                                                if PACKET_TRACE {
                                                    log::trace!(
                                                        "local_client: rx << ({}) {}",
                                                        iface_address,
                                                        packet
                                                    );
                                                }
                                                stats.count_rx(frame.len());
                                                let _ = rx_channel
                                                    .send(RxMessage {
                                                        address: iface_address,
                                                        packet,
                                                    })
                                                    .await;
                                            }
                                            Err(_) => {
                                                log::debug!(
                                                    "local_client: couldn't decode packet"
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::debug!("local_client: connection error {}", e);
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let mut stream = write_half;

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            Some(message) = tx_channel.recv() => message,
                        };

                        if PACKET_TRACE {
                            log::trace!(
                                "local_client: tx >> ({}) {}",
                                iface_address,
                                message.packet
                            );
                        }

                        let packet = message.packet;
                        let mut buffer = [0u8; 8192 + 16];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let frame = Hdlc::encode_frame_vec(output.as_slice());
                            if stream_write_all(&mut stream, &frame).await.is_ok() {
                                stats.count_tx(output.offset());
                            }
                        }
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            stats.set_online(false);
            log::debug!("local_client[{}]: disconnected", name);

            if server_side {
                break;
            }
        }

        iface_stop.cancel();
    }
}

impl Interface for LocalClient {
    fn mtu() -> usize {
        HW_MTU
    }
}
