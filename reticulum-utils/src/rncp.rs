//! `rncp` — file transfer utility over resources
//! (port of `RNS/Utilities/rncp.py`).
//!
//! Protocol-visible parts mirrored from the Python tool:
//!
//! * destination: `RNS.Destination(identity, IN, SINGLE, "rncp", "receive")`
//! * transfers: `RNS.Resource(file, link, metadata={"name": <filename>})`
//!   — the metadata is a msgpack map with one `name` key holding the
//!   basename as bytes
//! * the sender identifies on the link with its persistent `rncp` identity
//!   (`<configdir>/storage/identities/rncp`) so the receiver can
//!   authenticate it against `-a/--allowed` hashes
//! * fetch: request path `fetch_file` with the remote file path as data;
//!   responses are msgpack `True` (file follows as a resource), `False`
//!   (not found) or the raw byte `0xF0` (`REQ_FETCH_NOT_ALLOWED`)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::link::{Link, LinkEvent, LinkEventData};
use reticulum::destination::{DestinationDesc, DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::resource::{
    RequestContext, ResourceOptions, ResourceStatus, ResourceStrategy,
};
use reticulum::transport::Transport;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::common::{
    load_or_create_private_identity, prettyhexrep, resolve_config_dir, build_tool_transport,
    ToolTransportOptions,
};

/// Python `rncp.py` `APP_NAME`.
pub const APP_NAME: &str = "rncp";
/// Python `rncp.py` `REQ_FETCH_NOT_ALLOWED`.
pub const REQ_FETCH_NOT_ALLOWED: i32 = 0xF0;

/// Request timeout (Python `Transport.PATH_REQUEST_TIMEOUT`, 15 s).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The `rncp` destination name: app `rncp`, aspect `receive`.
pub fn destination_name() -> DestinationName {
    DestinationName::new(APP_NAME, "receive")
}

// ---------------------------------------------------------------------------
// Metadata wire format: msgpack {"name": <basename bytes>}
// ---------------------------------------------------------------------------

/// Pack resource metadata like Python `umsgpack.packb({"name": name})`.
pub fn pack_metadata(filename: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(filename.len() + 16);
    rmp::encode::write_map_len(&mut out, 1).expect("write map len");
    rmp::encode::write_str(&mut out, "name").expect("write key");
    rmp::encode::write_bin(&mut out, filename.as_bytes()).expect("write value");
    out
}

/// Unpack resource metadata packed by [`pack_metadata`] (or Python
/// `umsgpack`). Returns the value of the `name` entry.
///
/// The name may arrive as a msgpack bin (our writer, `umsgpack.packb(bytes)`)
/// or as a str (Python callers passing a `str`), so both are accepted.
pub fn unpack_metadata(data: &[u8]) -> Option<String> {
    fn read_value(cursor: &mut &[u8]) -> Option<Vec<u8>> {
        let mut attempt = *cursor;
        if let Ok(len) = rmp::decode::read_bin_len(&mut attempt) {
            let len = len as usize;
            if attempt.len() >= len {
                return Some(attempt[..len].to_vec());
            }
        }
        read_str_value(cursor)
    }

    fn read_str_value(cursor: &mut &[u8]) -> Option<Vec<u8>> {
        use std::io::Read as _;
        // `read_str_len` consumes the marker + length; the data follows raw.
        let len = rmp::decode::read_str_len(cursor).ok()? as usize;
        let mut value = vec![0u8; len];
        cursor.read_exact(&mut value).ok()?;
        Some(value)
    }

    let mut cursor: &[u8] = data;
    if rmp::decode::read_map_len(&mut cursor).ok()? < 1 {
        return None;
    }
    loop {
        let key = read_str_value(&mut cursor)?;
        let value = read_value(&mut cursor)?;
        if key == b"name" {
            return String::from_utf8(value).ok();
        }
    }
}

/// Reduce a received filename to a safe basename
/// (Python `os.path.basename` + save-path jail check).
pub fn sanitize_filename(name: &str) -> String {
    let basename = name.rsplit('/').next().unwrap_or("").rsplit('\\').next().unwrap_or("");
    let cleaned: String = basename
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    if cleaned.is_empty() {
        "rncp.incoming".to_string()
    } else {
        cleaned
    }
}

/// Choose a non-existing target path inside `dir`, appending `.1`, `.2`, …
/// when the file already exists (Python rncp receive behaviour).
pub fn unique_path(dir: &Path, filename: &str) -> PathBuf {
    let filename = sanitize_filename(filename);
    let direct = dir.join(&filename);
    if !direct.exists() {
        return direct;
    }
    for counter in 1.. {
        let candidate = dir.join(format!("{filename}.{counter}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

// ---------------------------------------------------------------------------
// Response value packing (msgpack, like Python umsgpack.packb)
// ---------------------------------------------------------------------------

fn msgpack_bool(value: bool) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_bool(&mut out, value).expect("write bool");
    out
}

/// `umsgpack.packb(0xF0)` on the Python side encodes the value as a
/// positive-fixint/uint8; mirror those exact bytes.
fn msgpack_fetch_not_allowed() -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_u8(&mut out, REQ_FETCH_NOT_ALLOWED as u8).expect("write uint");
    out
}

/// Interpret a response payload as a msgpack bool/int like Python does.
#[derive(Debug, PartialEq, Eq)]
pub enum FetchResponse {
    Allowed,
    NotFound,
    NotAllowed,
    Unknown,
}

pub fn parse_fetch_response(data: &[u8]) -> FetchResponse {
    use rmp::decode::{read_marker, RmpRead};
    use rmp::Marker;
    // rmp's width-specific readers are strict about markers, so dispatch on
    // the marker itself (bool, or the uint8 Python umsgpack.packb(0xF0)
    // produces: [0xcc, 0xf0]).
    let mut cursor: &[u8] = data;
    match read_marker(&mut cursor) {
        Ok(Marker::True) => FetchResponse::Allowed,
        Ok(Marker::False) => FetchResponse::NotFound,
        Ok(Marker::U8) => match cursor.read_data_u8() {
            Ok(value) if value == REQ_FETCH_NOT_ALLOWED as u8 => FetchResponse::NotAllowed,
            _ => FetchResponse::Unknown,
        },
        _ => FetchResponse::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Identity handling
// ---------------------------------------------------------------------------

/// Load (or create) the persistent `rncp` identity for a config directory.
pub fn rncp_identity(config_dir: &Path, explicit: Option<&Path>) -> Result<PrivateIdentity, String> {
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config_dir.join("storage/identities").join(APP_NAME));
    let (identity, created) =
        load_or_create_private_identity(&path).map_err(|err| err.to_string())?;
    if created {
        log::info!("No valid saved identity found, creating new at {}", path.display());
    } else {
        log::info!("Loaded rncp identity from {}", path.display());
    }
    Ok(identity)
}

// ---------------------------------------------------------------------------
// Listener (`rn cp --serve`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub config_dir: Option<PathBuf>,
    /// Directory to store received files in (Python `-s/--save`).
    pub save_dir: PathBuf,
    /// Allowed sender identity hashes (Python `-a`).
    pub allowed: Vec<AddressHash>,
    /// Accept anyone (Python `-n/--no-auth`).
    pub no_auth: bool,
    /// Serve fetch requests (Python `-F/--allow-fetch`).
    pub allow_fetch: bool,
    /// Restrict fetch requests to paths under this directory
    /// (Python `-j/--jail`).
    pub jail: Option<PathBuf>,
    /// Announce every N seconds; 0 = only once at startup (Python `-b`).
    pub announce_interval: u64,
    pub no_compress: bool,
    pub identity_path: Option<PathBuf>,
    pub udp_loopback: Option<(u16, u16)>,
}

fn sender_allowed(
    no_auth: bool,
    allowed: &HashSet<AddressHash>,
    sender: Option<&AddressHash>,
) -> bool {
    no_auth || sender.is_some_and(|sender| allowed.contains(sender))
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: None,
            save_dir: PathBuf::from("."),
            allowed: vec![],
            no_auth: false,
            allow_fetch: false,
            jail: None,
            announce_interval: 0,
            no_compress: false,
            identity_path: None,
            udp_loopback: None,
        }
    }
}

/// The hash the listener announces (`rncp.receive` for its identity).
pub async fn serve_destination_hash(transport: &mut Transport, identity: &PrivateIdentity) -> AddressHash {
    let destination = transport.add_destination(identity.clone(), destination_name()).await;
    let hash = destination.lock().await.desc.address_hash;
    hash
}

/// Run the rncp listener until Ctrl-C. Returns when interrupted.
pub async fn serve(options: ServeOptions) -> Result<(), String> {
    let shutdown = CancellationToken::new();
    serve_with_shutdown(options, shutdown).await
}

/// Run the rncp listener until Ctrl-C or `shutdown` is cancelled
/// (used by the loopback tests).
pub async fn serve_with_shutdown(options: ServeOptions, shutdown: CancellationToken) -> Result<(), String> {
    let config_dir = resolve_config_dir(options.config_dir.as_deref());
    std::fs::create_dir_all(&config_dir).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(&options.save_dir).map_err(|err| err.to_string())?;

    let mut transport = build_tool_transport(ToolTransportOptions {
        config_dir: &config_dir,
        instance_name: "rncp-listener",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    let identity = rncp_identity(&config_dir, options.identity_path.as_deref())?;
    let destination_hash = serve_destination_hash(&mut transport, &identity).await;

    // Authentication is opt-out only. An empty allowlist is deliberately
    // deny-all, rather than silently turning the listener into an open relay.
    let allow_all = options.no_auth;
    if options.allowed.is_empty() && !options.no_auth {
        log::warn!("No allowed identities configured, rncp will not accept any files! (use --no-auth to accept anyone)");
    }
    let allowed: HashSet<AddressHash> = options.allowed.iter().copied().collect();

    let transport = Arc::new(transport);

    // Wait for the configured interfaces to come up (UDP binds retry on
    // address conflicts) so the startup announce is not sent into the void.
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            if transport.interface_stats().await.iter().any(|stats| stats.online) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !transport.interface_stats().await.iter().any(|stats| stats.online) {
            log::warn!("rncp: no interface came up within 15s; announcing anyway");
        }
    }

    // Announce at startup (and periodically when requested).
    {
        let transport = transport.clone();
        let destination = transport
            .get_in_destination(&destination_hash)
            .await
            .expect("rncp destination");
        let interval = options.announce_interval;
        transport.send_announce(&destination, None).await;
        log::info!("rncp listening on {}", prettyhexrep(destination_hash.as_slice()));
        println!(
            "Identity     : {}\nListening on : {}",
            prettyhexrep(identity.address_hash().as_slice()),
            prettyhexrep(destination_hash.as_slice())
        );
        if interval > 0 {
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    transport.send_announce(&destination, None).await;
                }
            });
        }
    }

    // Fetch request handler (Python `fetch_request`).
    if options.allow_fetch {
        let handler_transport = transport.clone();
        let allow_fetch_all = allow_all;
        let fetch_allowed = allowed.clone();
        let jail = options.jail.clone();
        let auto_compress = !options.no_compress;
        let handler = move |ctx: RequestContext| -> Option<Vec<u8>> {
            if !allow_fetch_all {
                let allowed_here = sender_allowed(
                    false,
                    &fetch_allowed,
                    ctx.remote_identity
                        .as_ref()
                        .map(|identity| &identity.address_hash),
                );
                if !allowed_here {
                    log::warn!("Fetch request from unauthenticated sender rejected");
                    return Some(msgpack_fetch_not_allowed());
                }
            }

            let requested = String::from_utf8_lossy(&ctx.data).trim().to_string();
            let file_path = match &jail {
                Some(jail) => {
                    let jail = jail.canonicalize().unwrap_or_else(|_| jail.clone());
                    let candidate = jail.join(sanitize_filename(&requested));
                    let canonical = candidate.canonicalize().unwrap_or(candidate);
                    if !canonical.starts_with(&jail) {
                        log::warn!("Disallowing fetch request for {canonical:?} outside of fetch jail {jail:?}");
                        return Some(msgpack_fetch_not_allowed());
                    }
                    canonical
                }
                None => PathBuf::from(&requested),
            };

            if !file_path.is_file() {
                log::info!("Client-requested file not found: {}", file_path.display());
                return Some(msgpack_bool(false));
            }

            let name = file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let data = match std::fs::read(&file_path) {
                Ok(data) => data,
                Err(err) => {
                    log::error!("Could not read file {}: {err}", file_path.display());
                    return None;
                }
            };

            log::info!("Sending file {} to client", file_path.display());
            let handler_transport = handler_transport.clone();
            let metadata = pack_metadata(&name);
            let link_id = ctx.link_id;
            tokio::spawn(async move {
                if let Some(link) = handler_transport.find_in_link(&link_id).await {
                    let opts = ResourceOptions {
                        metadata: Some(metadata),
                        auto_compress,
                        ..Default::default()
                    };
                    if let Err(err) = handler_transport
                        .send_resource_with_options(&link, data, opts)
                        .await
                    {
                        log::error!("Could not send file to client: {err:?}");
                    }
                }
            });

            Some(msgpack_bool(true))
        };
        transport
            .register_request_handler(&destination_hash, "fetch_file", handler)
            .await;
        log::info!("Fetch requests allowed");
    }

    let mut link_events = transport.in_link_events();
    let mut resource_events = transport.resource_events().await;
    let mut identified: std::collections::HashMap<AddressHash, AddressHash> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            event = link_events.recv() => {
                let LinkEventData { id, event, .. } = match event {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        log::warn!("rncp: missed {count} link events");
                        continue;
                    }
                    Err(_) => break,
                };
                match event {
                    LinkEvent::Activated => {
                        log::info!("Incoming link established");
                        transport.set_resource_strategy(id, ResourceStrategy::All).await;
                    }
                    LinkEvent::RemoteIdentified(identity) => {
                        let sender = identity.address_hash;
                        log::info!("Sender identified as {}", prettyhexrep(sender.as_slice()));
                        identified.insert(id, sender);
                        if !allow_all && !allowed.contains(&sender) {
                            log::warn!("Sender not allowed, tearing down link");
                            let _ = transport.link_close(id).await;
                        }
                    }
                    LinkEvent::Closed => {
                        log::info!("Link closed");
                    }
                    _ => {}
                }
            }
            event = resource_events.recv() => {
                let event = match event {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        log::warn!("rncp: missed {count} resource events");
                        continue;
                    }
                    Err(_) => break,
                };
                match event.status {
                    ResourceStatus::Complete => {
                        let Some(data) = event.data else {
                            log::warn!("Invalid data received, ignoring resource");
                            continue;
                        };
                        if !allow_all {
                            let sender_ok =
                                sender_allowed(false, &allowed, identified.get(&event.link_id));
                            if !sender_ok {
                                log::warn!(
                                    "Resource {} from unauthenticated sender, discarding",
                                    prettyhexrep(event.hash.as_slice())
                                );
                                continue;
                            }
                        }
                        let name = event
                            .metadata
                            .as_deref()
                            .and_then(unpack_metadata)
                            .unwrap_or_default();
                        let path = unique_path(&options.save_dir, &name);
                        if let Err(err) = std::fs::write(&path, &data) {
                            log::error!("Could not save received file to {}: {err}", path.display());
                            continue;
                        }
                        log::info!("Saved received file to {}", path.display());
                        println!("Received file saved to {}", path.display());
                    }
                    ResourceStatus::Failed | ResourceStatus::Corrupt => {
                        log::info!("Resource failed");
                    }
                    ResourceStatus::Rejected => {
                        log::info!("Resource rejected");
                    }
                    _ => {}
                }
            }
            _ = shutdown.cancelled() => {
                log::info!("rncp listener shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("rncp listener shutting down");
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sender (`rn cp <file> <destination>`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub config_dir: Option<PathBuf>,
    pub file: PathBuf,
    pub destination: AddressHash,
    pub timeout: Duration,
    pub no_compress: bool,
    pub silent: bool,
    pub identity_path: Option<PathBuf>,
    pub udp_loopback: Option<(u16, u16)>,
}

/// Establish a link to an announced destination, identifying with the rncp
/// identity on the way (shared by `send` and `fetch`).
async fn connect(
    transport: &Transport,
    destination: &AddressHash,
    identity: &PrivateIdentity,
    timeout: Duration,
    silent: bool,
) -> Result<Arc<Mutex<Link>>, String> {
    if !transport.has_path(destination).await {
        println!("Path to {} requested", prettyhexrep(destination.as_slice()));
    }
    let desc: DestinationDesc = crate::rnpath::wait_for_destination(transport, destination, timeout)
        .await
        .ok_or_else(|| "Path not found".to_string())?;
    if !silent {
        println!("Establishing link with {}", prettyhexrep(destination.as_slice()));
    }

    let mut events = transport.out_link_events();
    let link = transport.link(desc).await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "Link establishment with {} timed out",
                prettyhexrep(destination.as_slice())
            ));
        }
        let Ok(Ok(LinkEventData { event, .. })) =
            tokio::time::timeout_at(deadline, events.recv()).await
        else {
            return Err("Link establishment failed".to_string());
        };
        if matches!(event, LinkEvent::Activated) {
            break;
        }
    }

    // Identify so the remote can authenticate us.
    let packet = link
        .lock()
        .await
        .identify(identity)
        .map_err(|err| format!("could not identify: {err:?}"))?;
    transport.send_packet(packet).await;

    // Accept incoming resources (fetch responses).
    let link_id = *link.lock().await.id();
    transport.set_resource_strategy(link_id, ResourceStrategy::All).await;

    Ok(link)
}

/// Send a file to a remote rncp listener. Returns the saved-file message on
/// success.
pub async fn send(options: SendOptions) -> Result<String, String> {
    let config_dir = resolve_config_dir(options.config_dir.as_deref());
    std::fs::create_dir_all(&config_dir).map_err(|err| err.to_string())?;

    let data = std::fs::read(&options.file)
        .map_err(|_| format!("File not found: {}", options.file.display()))?;
    let name = options
        .file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &config_dir,
        instance_name: "rncp-sender",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    let identity = rncp_identity(&config_dir, options.identity_path.as_deref())?;
    let link = connect(&transport, &options.destination, &identity, options.timeout, options.silent).await?;

    if !options.silent {
        println!("Advertising file resource");
    }
    let resource_hash = transport
        .send_resource_with_options(
            &link,
            data,
            ResourceOptions {
                metadata: Some(pack_metadata(&name)),
                auto_compress: !options.no_compress,
                ..Default::default()
            },
        )
        .await
        .map_err(|err| format!("Could not start transfer: {err:?}"))?;

    wait_for_transfer(
        &transport,
        &resource_hash,
        options.timeout.max(Duration::from_secs(60)),
        !options.silent,
    )
    .await?;

    let _ = transport.link_close(*link.lock().await.id()).await;
    Ok(format!(
        "{} copied to {}",
        options.file.display(),
        prettyhexrep(options.destination.as_slice())
    ))
}

// ---------------------------------------------------------------------------
// Fetch (`rn cp --fetch <file> <destination>`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub config_dir: Option<PathBuf>,
    /// Path of the file on the remote system.
    pub file: String,
    pub destination: AddressHash,
    pub timeout: Duration,
    pub silent: bool,
    /// Directory to save the fetched file in (Python `-s/--save`).
    pub save_dir: Option<PathBuf>,
    pub identity_path: Option<PathBuf>,
    pub udp_loopback: Option<(u16, u16)>,
}

/// Fetch a file from a remote rncp listener that allows fetching.
pub async fn fetch(options: FetchOptions) -> Result<String, String> {
    let config_dir = resolve_config_dir(options.config_dir.as_deref());
    std::fs::create_dir_all(&config_dir).map_err(|err| err.to_string())?;

    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &config_dir,
        instance_name: "rncp-fetcher",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    let identity = rncp_identity(&config_dir, options.identity_path.as_deref())?;
    let link = connect(&transport, &options.destination, &identity, options.timeout, options.silent).await?;

    if !options.silent {
        println!("Requesting file from remote");
    }
    let request_id = transport
        .request(&link, "fetch_file", options.file.as_bytes())
        .await
        .map_err(|err| format!("Could not send fetch request: {err:?}"))?;

    let response = transport
        .await_request_response(request_id, options.timeout)
        .await
        .ok_or_else(|| "Fetch request failed due to an unknown error (probably not authorised)".to_string())?;

    match parse_fetch_response(&response) {
        FetchResponse::Allowed => {}
        FetchResponse::NotFound => {
            return Err(format!(
                "Fetch request failed, the file {} was not found on the remote",
                options.file
            ))
        }
        FetchResponse::NotAllowed => {
            return Err(format!(
                "Fetch request failed, fetching the file {} was not allowed by the remote",
                options.file
            ))
        }
        FetchResponse::Unknown => {
            return Err("Fetch request failed due to an error on the remote system".to_string())
        }
    }

    // The response resource follows; wait for it to complete.
    let deadline = tokio::time::Instant::now() + options.timeout.max(Duration::from_secs(60));
    let mut events = transport.resource_events().await;
    let saved = loop {
        assert!(tokio::time::Instant::now() < deadline, "transfer timed out");
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| "transfer timed out".to_string())?
            .map_err(|_| "resource events closed".to_string())?;
        if event.status != ResourceStatus::Complete {
            continue;
        }
        let Some(data) = event.data else { continue };
        let name = event
            .metadata
            .as_deref()
            .and_then(unpack_metadata)
            .unwrap_or_else(|| sanitize_filename(&options.file));
        let dir = options.save_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        let path = unique_path(&dir, &name);
        std::fs::write(&path, &data).map_err(|err| err.to_string())?;
        break path;
    };

    let _ = transport.link_close(*link.lock().await.id()).await;
    Ok(format!(
        "{} fetched from {} (saved to {})",
        options.file,
        prettyhexrep(options.destination.as_slice()),
        saved.display()
    ))
}

// ---------------------------------------------------------------------------
// Transfer progress tracking (shared by send)
// ---------------------------------------------------------------------------

/// Wait for a sent resource to conclude, printing progress while it runs.
///
/// Progress lines are flushed so `\r` updates render live.
pub async fn wait_for_transfer(
    transport: &Transport,
    resource_hash: &AddressHash,
    timeout: Duration,
    show_progress: bool,
) -> Result<(), String> {
    let mut events = transport.resource_events().await;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_percent = -1.0f64;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("The transfer timed out".to_string());
        }
        let event = tokio::time::timeout(remaining, events.recv())
            .await
            .map_err(|_| "The transfer timed out".to_string())?
            .map_err(|_| "resource events closed".to_string())?;
        if &AddressHash::new_from_hash(&event.hash) != resource_hash {
            continue;
        }
        match event.status {
            ResourceStatus::Complete => {
                if show_progress {
                    print!("\rTransfer complete  100.0%\n");
                }
                return Ok(());
            }
            ResourceStatus::Failed | ResourceStatus::Corrupt => {
                return Err("The transfer failed".to_string());
            }
            ResourceStatus::Rejected => {
                return Err("The file was not accepted by the remote".to_string());
            }
            status => {
                if show_progress {
                    let percent = (event.progress * 100.0 * 10.0).round() / 10.0;
                    if percent > last_percent {
                        last_percent = percent;
                        print!("\rTransferring file {percent:.1}%");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
                let _ = status;
            }
        }
    }
}

/// Generate a random identity — exposed for tests.
pub fn new_identity() -> PrivateIdentity {
    PrivateIdentity::new_from_rand(OsRng)
}

/// Print the persistent rncp identity and the destination hash it listens
/// on, then exit (Python `rncp.py -p/--print-identity`).
pub async fn print_identity(config_dir: &Path, identity_path: Option<&Path>) -> Result<(String, String), String> {
    let identity = rncp_identity(config_dir, identity_path)?;
    let destination = SingleInputDestination::new(identity.clone(), destination_name());
    Ok((
        prettyhexrep(identity.address_hash().as_slice()),
        prettyhexrep(destination.desc.address_hash.as_slice()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip_matches_python_layout() {
        let packed = pack_metadata("hello.txt");
        // msgpack: fixmap1(0x81), fixstr4(0xa4) "name", bin8(0xc4) len data
        assert_eq!(packed[0], 0x81);
        assert_eq!(packed[1], 0xa4);
        assert_eq!(&packed[2..6], b"name");
        assert_eq!(packed[6], 0xc4);
        assert_eq!(packed[7], b"hello.txt".len() as u8);
        assert_eq!(&packed[8..], b"hello.txt");
        assert_eq!(unpack_metadata(&packed).as_deref(), Some("hello.txt"));
    }

    #[test]
    fn metadata_unpack_str_value() {
        // Python implementations may pack the name as a str instead of bin.
        let mut packed = Vec::new();
        rmp::encode::write_map_len(&mut packed, 1).unwrap();
        rmp::encode::write_str(&mut packed, "name").unwrap();
        rmp::encode::write_str(&mut packed, "alt.txt").unwrap();
        assert_eq!(unpack_metadata(&packed).as_deref(), Some("alt.txt"));
    }

    #[test]
    fn filename_sanitizing() {
        assert_eq!(sanitize_filename("/etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("../../secret"), "secret");
        assert_eq!(sanitize_filename(""), "rncp.incoming");
        assert_eq!(sanitize_filename("dir/file.bin"), "file.bin");
    }

    #[test]
    fn unique_path_numbers_collisions() {
        let dir = std::env::temp_dir().join(format!("rncp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = unique_path(&dir, "a.txt");
        assert_eq!(first, dir.join("a.txt"));
        std::fs::write(&first, b"1").unwrap();
        let second = unique_path(&dir, "a.txt");
        assert_eq!(second, dir.join("a.txt.1"));
        std::fs::write(&second, b"2").unwrap();
        let third = unique_path(&dir, "a.txt");
        assert_eq!(third, dir.join("a.txt.2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_response_parsing() {
        assert_eq!(parse_fetch_response(&msgpack_bool(true)), FetchResponse::Allowed);
        assert_eq!(parse_fetch_response(&msgpack_bool(false)), FetchResponse::NotFound);
        assert_eq!(
            parse_fetch_response(&msgpack_fetch_not_allowed()),
            FetchResponse::NotAllowed
        );
        assert_eq!(parse_fetch_response(&[0xff, 0xff]), FetchResponse::Unknown);
    }

    #[test]
    fn authentication_requires_no_auth_or_an_explicit_match() {
        let sender = AddressHash::new_from_slice(&[1; 32]);
        let stranger = AddressHash::new_from_slice(&[2; 32]);
        let empty = HashSet::new();
        let allowed = HashSet::from([sender]);

        assert!(!sender_allowed(false, &empty, Some(&sender)));
        assert!(!sender_allowed(false, &empty, None));
        assert!(sender_allowed(true, &empty, Some(&stranger)));
        assert!(sender_allowed(true, &empty, None));
        assert!(sender_allowed(false, &allowed, Some(&sender)));
        assert!(!sender_allowed(false, &allowed, Some(&stranger)));
    }
}
