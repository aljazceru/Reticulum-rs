//! rncp loopback tests: file transfers over UDP between two in-process
//! transports, using the same code paths as the `rn cp` CLI (config-dir
//! driven transports, persistent identities, metadata, chunking).

use std::path::PathBuf;
use std::time::Duration;

use reticulum::destination::DestinationName;
use reticulum::destination::SingleInputDestination;
use reticulum::identity::PrivateIdentity;
use reticulum_utils::common::load_or_create_private_identity;
use reticulum_utils::rncp::{self, FetchOptions, SendOptions, ServeOptions};
use tokio_util::sync::CancellationToken;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-rncp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_udp_config(dir: &PathBuf, listen_port: u16, forward_port: u16) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        format!(
            "[[interfaces]]\nname = \"Loopback UDP\"\ntype = \"UDPInterface\"\nenabled = true\n\
             listen_ip = \"127.0.0.1\"\nlisten_port = {listen_port}\n\
             forward_ip = \"127.0.0.1\"\nforward_port = {forward_port}\n"
        ),
    )
    .unwrap();
}

/// The `rncp.receive` destination hash for the identity stored at
/// `config_dir/storage/identities/rncp` (what the listener announces).
fn rncp_destination_hash(config_dir: &PathBuf) -> reticulum::hash::AddressHash {
    let (identity, _) =
        load_or_create_private_identity(&config_dir.join("storage/identities/rncp")).unwrap();
    SingleInputDestination::new(identity, DestinationName::new(rncp::APP_NAME, "receive"))
        .desc
        .address_hash
}

fn test_file(dir: &PathBuf, size: usize) -> PathBuf {
    let path = dir.join("payload.bin");
    // Deliberately poorly-compressible data so the resource engine moves the
    // full chunked stream.
    let data: Vec<u8> = (0..size).map(|i| ((i * 31 + (i / 251) * 17) % 256) as u8).collect();
    std::fs::write(&path, data).unwrap();
    path
}

async fn wait_for_file(dir: &PathBuf, name: &str, timeout: Duration) -> Option<PathBuf> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        for entry in std::fs::read_dir(dir).ok()? {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().starts_with(name) {
                return Some(entry.path());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn send_file_over_udp_loopback() {
    let server_config = temp_dir("server");
    let client_config = temp_dir("client");
    let save_dir = temp_dir("received");
    write_udp_config(&server_config, 4651, 4652);
    write_udp_config(&client_config, 4652, 4651);

    let destination = rncp_destination_hash(&server_config);
    let payload = test_file(&client_config, 180_000);

    // Listener: accept anyone (as `rn cp --serve --no-auth` would).
    let shutdown = CancellationToken::new();
    let serve_task = {
        let options = ServeOptions {
            config_dir: Some(server_config.clone()),
            save_dir: save_dir.clone(),
            no_auth: true,
            ..Default::default()
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move { rncp::serve_with_shutdown(options, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    let message = rncp::send(SendOptions {
        config_dir: Some(client_config.clone()),
        file: payload.clone(),
        destination,
        timeout: Duration::from_secs(30),
        no_compress: false,
        silent: true,
        identity_path: None,
        udp_loopback: None,
    })
    .await
    .expect("transfer");
    assert!(message.contains("copied to"), "{message}");

    let received = wait_for_file(&save_dir, "payload.bin", Duration::from_secs(10))
        .await
        .expect("received file");
    assert_eq!(
        std::fs::read(&received).unwrap(),
        std::fs::read(&payload).unwrap(),
        "received bytes must match"
    );

    shutdown.cancel();
    serve_task.await.expect("serve task").expect("serve ok");
}

#[tokio::test]
async fn fetch_file_over_udp_loopback() {
    let server_config = temp_dir("fetch-server");
    let client_config = temp_dir("fetch-client");
    let save_dir = temp_dir("fetch-received");
    write_udp_config(&server_config, 4661, 4662);
    write_udp_config(&client_config, 4662, 4661);

    // A file the server is willing to serve from its jail.
    let jail = server_config.join("shared");
    std::fs::create_dir_all(&jail).unwrap();
    let remote_file = jail.join("remote.txt");
    std::fs::write(&remote_file, b"fetch me over the loopback interface\n").unwrap();

    let destination = rncp_destination_hash(&server_config);

    let shutdown = CancellationToken::new();
    let serve_task = {
        let options = ServeOptions {
            config_dir: Some(server_config.clone()),
            save_dir: server_config.clone(),
            no_auth: true,
            allow_fetch: true,
            jail: Some(jail.clone()),
            ..Default::default()
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move { rncp::serve_with_shutdown(options, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    let message = rncp::fetch(FetchOptions {
        config_dir: Some(client_config.clone()),
        file: remote_file.display().to_string(),
        destination,
        timeout: Duration::from_secs(30),
        silent: true,
        save_dir: Some(save_dir.clone()),
        identity_path: None,
        udp_loopback: None,
    })
    .await
    .expect("fetch");
    assert!(message.contains("fetched from"), "{message}");

    let received = save_dir.join("remote.txt");
    assert_eq!(
        std::fs::read(&received).unwrap(),
        std::fs::read(&remote_file).unwrap()
    );

    shutdown.cancel();
    serve_task.await.expect("serve task").expect("serve ok");
}

#[tokio::test]
async fn unauthenticated_sender_is_rejected() {
    let server_config = temp_dir("auth-server");
    let client_config = temp_dir("auth-client");
    let save_dir = temp_dir("auth-received");
    write_udp_config(&server_config, 4671, 4672);
    write_udp_config(&client_config, 4672, 4671);

    let destination = rncp_destination_hash(&server_config);
    let payload = test_file(&client_config, 4096);

    // Listener with an allowed list that does *not* include the sender.
    let allowed = PrivateIdentity::new_from_rand(rand_core::OsRng)
        .address_hash()
        .to_hex_string();
    let allowed = reticulum_utils::common::parse_hash(&allowed).unwrap();
    let shutdown = CancellationToken::new();
    let serve_task = {
        let options = ServeOptions {
            config_dir: Some(server_config.clone()),
            save_dir: save_dir.clone(),
            allowed: vec![allowed],
            ..Default::default()
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move { rncp::serve_with_shutdown(options, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The transfer itself completes at the resource layer, but the server
    // discards the file because the sender is not on the allowed list.
    let _ = rncp::send(SendOptions {
        config_dir: Some(client_config.clone()),
        file: payload.clone(),
        destination,
        timeout: Duration::from_secs(20),
        no_compress: false,
        silent: true,
        identity_path: None,
        udp_loopback: None,
    })
    .await;

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !save_dir.join("payload.bin").exists(),
        "unauthenticated sender's file must not be saved"
    );

    shutdown.cancel();
    let _ = serve_task.await;
}
