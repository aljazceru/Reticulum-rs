//! Full-stack interop with a PYTHON node in the middle routing between
//! two Rust endpoints (the drop-in-replacement proof): Rust A <->
//! Python transport <-> Rust C. Exercises announce propagation, path
//! requests, link establishment (LR relay + LRPROOF validation in the
//! PYTHON middle), and bidirectional link data through the Python node.

use std::process::Stdio;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::destination::link::LinkEvent;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

fn python_dir() -> String {
    std::env::var("RETICULUM_TEST_PYTHON_DIR").expect("RETICULUM_TEST_PYTHON_DIR")
}

async fn spawn_middle(listen_a: u16, forward_a: u16, listen_c: u16, forward_c: u16) -> Child {
    let script = format!("{}/tests/py-interop/middle.py", env!("CARGO_MANIFEST_DIR"));

    let mut child = Command::new("python3")
        .arg("-u")
        .arg(script)
        .arg(listen_a.to_string())
        .arg(forward_a.to_string())
        .arg(listen_c.to_string())
        .arg(forward_c.to_string())
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn middle");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("middle: {line}");
            let _ = tx.send(line).await;
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(line)) = timeout(Duration::from_millis(200), rx.recv()).await {
            if line.contains("MIDDLE-READY") {
                break;
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    child
}

/// A Rust endpoint facing the Python middle on one UDP interface.
async fn rust_endpoint(name: &str, listen: u16, forward: u16) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = TransportConfig::new(name, &identity, false).build();

    {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{listen}"),
                Some(format!("127.0.0.1:{forward}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    transport
}

#[tokio::test]
async fn link_through_python_middle_node() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    // Topology: rust-a <-> python <-> rust-c.
    // Rust A talks to the middle on 4702/4701; Rust C on 4704/4703.
    let mut middle = spawn_middle(4701, 4702, 4703, 4704).await;

    let a = rust_endpoint("rust-a", 4702, 4701).await;
    let c = rust_endpoint("rust-c", 4704, 4703).await;

    // C announces a destination; A must learn it THROUGH the Python node.
    let destination = c
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("interop", "middle"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    c.send_announce(&destination, Some(b"via-python")).await;

    let mut announces = a.recv_announces().await;
    let announce = tokio::time::timeout(Duration::from_secs(30), announces.recv())
        .await
        .expect("announce must propagate through the Python middle")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;
    assert_eq!(desc.address_hash, dest_hash);

    // A links to C through the Python middle: the LR and the returning
    // LRPROOF are relayed by the Python transport node.
    let link = a.link(desc).await;
    let mut events = a.out_link_events();
    let activated = tokio::time::timeout(Duration::from_secs(30), events.recv()).await;
    assert!(
        matches!(activated, Ok(Ok(_))),
        "link must activate through the Python middle (LR relay + proof validation)"
    );

    // Bidirectional data: A -> C over the link.
    let mut received = c.in_link_events();
    let payload = b"hello through python middle";
    a.send_to_out_links(&dest_hash, payload).await;

    let event = tokio::time::timeout(Duration::from_secs(30), received.recv())
        .await
        .expect("data A->C must arrive through the Python middle")
        .expect("channel");
    match event.event {
        LinkEvent::Data(data) => assert_eq!(data.as_slice(), payload),
        other => panic!("expected data event, got {other:?}"),
    }

    // C -> A: the Python middle must route the reverse direction.
    let mut a_received = a.out_link_events();
    let reply = b"reply through python middle";

    let link_id = *link.lock().await.id();
    let response_packet = {
        let link = c.find_in_link(&link_id).await.expect("in link on C");
        let link = link.lock().await;
        link.data_packet(reply).expect("data packet")
    };
    c.send_packet(response_packet).await;

    let event = tokio::time::timeout(Duration::from_secs(30), a_received.recv())
        .await
        .expect("data C->A must arrive through the Python middle")
        .expect("channel");
    match event.event {
        LinkEvent::Data(payload) => assert_eq!(payload.as_slice(), reply),
        other => panic!("expected data event, got {other:?}"),
    }

    let _ = &mut middle;
    let _ = middle.start_kill();
    let _ = middle.wait().await;
}

#[tokio::test]
async fn python_endpoint_through_rust_middle() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    // Topology: python-a <-> rust-middle <-> python-c. The RUST node is
    // the intermediary: it must relay the Python announce, path request,
    // link request, LRPROOF and link data.
    // The Python endpoints are driven by partner.py in "announce"/"link"
    // modes.
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let middle = TransportConfig::new("rust-middle", &identity, true)
        .set_retransmit(true)
        .build();

    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4712", Some("127.0.0.1:4711"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4714", Some("127.0.0.1:4713"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Python C announces through the Rust middle; Python A links to it.
    // partner.py does announce-and-wait / announce-and-link.
    let script = format!(
        "{}/tests/py-interop/middle_endpoints.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut a_child = Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--role")
        .arg("initiator")
        .arg("--listen")
        .arg("4711")
        .arg("--forward")
        .arg("4712")
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python initiator");

    let mut c_child = Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--role")
        .arg("destination")
        .arg("--listen")
        .arg("4713")
        .arg("--forward")
        .arg("4714")
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python destination");

    let c_stderr = c_child.stderr.take().expect("c stderr");
    tokio::spawn(async move {
        let mut lines = BufReader::new(c_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("py-c-err: {line}");
        }
    });
    let a_stderr = a_child.stderr.take().expect("a stderr");
    tokio::spawn(async move {
        let mut lines = BufReader::new(a_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("py-a-err: {line}");
        }
    });

    let c_stdout = c_child.stdout.take().expect("c stdout");
    let (c_tx, c_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(c_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-c: {line}");
            let _ = c_tx.send(line).await;
        }
    });

    let a_stdout = a_child.stdout.take().expect("a stdout");
    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(a_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-a: {line}");
            let _ = a_tx.send(line).await;
        }
    });

    async fn wait_line(
        rx: &mut tokio::sync::mpsc::Receiver<String>,
        needle: &str,
        timeout: Duration,
    ) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if let Ok(line) = tokio::time::timeout_at(deadline, rx.recv()).await {
                match line {
                    Some(line) if line.contains(needle) => return Some(line),
                    Some(_) => continue,
                    None => return None,
                }
            }
        }
        None
    }

    // The Python destination announces; the initiator links and sends.
    let established = wait_line(&mut a_rx, "LINK-ESTABLISHED", Duration::from_secs(60)).await;
    assert!(
        established.is_some(),
        "Python link must establish through the Rust middle"
    );

    let echoed = wait_line(&mut a_rx, "ECHO-RECEIVED", Duration::from_secs(30)).await;
    assert!(
        echoed.is_some(),
        "Python echo must round-trip through the Rust middle"
    );

    let _ = c_rx;

    let _ = a_child.start_kill();
    let _ = c_child.start_kill();
    let _ = a_child.wait().await;
    let _ = c_child.wait().await;
}
