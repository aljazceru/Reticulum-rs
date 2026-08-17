//! IFAC (interface access code) interop against the Python reference
//! (Phase 5.1): a Rust TCP client connects to a Python `TCPServerInterface`
//! configured with a passphrase; announces must flow both directions with
//! access-code-protected packets, and packets from a peer without the
//! passphrase must be dropped.

#![cfg(feature = "python-tests")]

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::ifac::{IfacKey, DEFAULT_IFAC_SIZE};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const PASSPHRASE: &str = "interop-secret";
const IFAC_BYTES: usize = 8; // python config `ifac_size = 64` bits

fn python_dir() -> String {
    std::env::var("RETICULUM_TEST_PYTHON_DIR")
        .expect("set RETICULUM_TEST_PYTHON_DIR to the reference Reticulum checkout")
}

fn py_config(name: &str) -> String {
    let fixture = format!("{}/tests/rns-py-configs/{name}", env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("rn-ifac-py-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(format!("{fixture}/config"), dir.join("config")).unwrap();
    dir.to_str().unwrap().to_string()
}

async fn spawn_announce_example(config: &str) -> (Child, tokio::sync::mpsc::Receiver<String>) {
    let script = format!("{}/Examples/Announce.py", python_dir());

    let mut child = Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--config")
        .arg(config)
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start Announce.py");

    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py: {line}");
            let _ = tx.send(line).await;
        }
    });

    (child, rx)
}

async fn next_line_containing(
    rx: &mut tokio::sync::mpsc::Receiver<String>,
    needle: &str,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while let Some(line) = rx.recv().await {
        if line.contains(needle) {
            return Some(line);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
    }
    None
}

#[tokio::test]
async fn ifac_protected_tcp_exchange_with_python() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let config = py_config("tcp-ifac");
    let (mut child, mut lines) = spawn_announce_example(&config).await;

    next_line_containing(
        &mut lines,
        "Announce example running",
        Duration::from_secs(15),
    )
    .await
    .expect("python announce example ready");

    // Rust TCP client with the same access code.
    let transport =
        TransportConfig::new("ifac-client", &PrivateIdentity::new_from_rand(OsRng), false).build();

    let iface = {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        let address = manager.spawn(TcpClient::new("127.0.0.1:4381"), TcpClient::spawn);
        manager.set_iface_ifac(&address, None, Some(PASSPHRASE), IFAC_BYTES);
        address
    };

    // Give the TCP connection time to establish.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Request announces from the Python side; they must arrive
    // access-code protected and unwrap correctly.
    let mut announces = transport.recv_announces().await;
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(b"\n")
        .await
        .unwrap();

    let announced = tokio::time::timeout(Duration::from_secs(15), announces.recv()).await;
    assert!(
        matches!(&announced, Ok(Ok(_))),
        "must receive an access-code protected announce from python"
    );

    // Announce from the Rust side: the Python announce handler must
    // receive it through the IFAC-protected TCP link.
    // Match the aspect filter of the Python example's announce handler
    // (example_utilities.announcesample.fruits) so it prints a
    // "Received an announce from" line.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("example_utilities", "announcesample.fruits"),
    );
    transport
        .send_announce(
            &Arc::new(tokio::sync::Mutex::new(destination)),
            Some(b"from rust"),
        )
        .await;

    let received = next_line_containing(
        &mut lines,
        "Received an announce from",
        Duration::from_secs(15),
    )
    .await;
    assert!(received.is_some(), "python must receive the rust announce");

    let _ = child.start_kill();
    let _ = iface;
}

#[tokio::test]
async fn ifac_rejects_packets_without_the_passphrase() {
    // A UDP pair where the receiver expects an access code but the sender
    // does not apply one: the packets must be dropped.
    let receiver =
        TransportConfig::new("ifac-recv", &PrivateIdentity::new_from_rand(OsRng), false).build();

    let sender =
        TransportConfig::new("ifac-send", &PrivateIdentity::new_from_rand(OsRng), false).build();

    let recv_iface = {
        let manager = receiver.iface_manager();
        let mut manager = manager.lock().await;
        let address = manager.spawn(
            UdpInterface::new("127.0.0.1:4392", Some("127.0.0.1:4393"), true),
            UdpInterface::spawn,
        );
        manager.set_iface_ifac(&address, Some("private-net"), None, DEFAULT_IFAC_SIZE);
        address
    };

    {
        let manager = sender.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4393", Some("127.0.0.1:4392"), true),
            UdpInterface::spawn,
        );
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("ifac", "unprotected"),
    );
    let mut announces = receiver.recv_announces().await;
    sender
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let leaked = tokio::time::timeout(Duration::from_secs(3), announces.recv()).await;
    assert!(
        leaked.is_err(),
        "unprotected announces must be dropped on access-code interfaces"
    );

    // With the matching access code configured, the announce flows.
    {
        let manager = sender.iface_manager();
        let manager = manager.lock().await;
        let stats = manager.stats();
        let address = stats.first().unwrap().address;
        drop(manager);
        let manager = sender.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_ifac(&address, Some("private-net"), None, DEFAULT_IFAC_SIZE);
    }

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("ifac", "protected"),
    );
    sender
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let received = tokio::time::timeout(Duration::from_secs(10), announces.recv()).await;
    assert!(
        matches!(received, Ok(Ok(_))),
        "announces must flow once both sides share the access code"
    );

    let _ = recv_iface;
    let _ = IfacKey::derive(None, None, 1);
}
