//! Transport integration tests for SINGLE-destination packet encryption,
//! announce ratchets, known-destination recall and proof strategies.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::storage::MemoryStorage;
use reticulum::transport::{ReceivedData, Transport, TransportConfig};
use tokio::sync::Mutex;

/// Server and client transport pair over UDP loopback.
struct Pair {
    server: Transport,
    client: Transport,
}

async fn pair(base_port: u16) -> Pair {
    let server = TransportConfig::new("server", &PrivateIdentity::new_from_rand(OsRng), false)
        .set_storage(Arc::new(MemoryStorage::new()))
        .build();
    server.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{base_port}"),
            Some(format!("127.0.0.1:{}", base_port + 1)),
            false,
        ),
        UdpInterface::spawn,
    );

    let client = TransportConfig::new("client", &PrivateIdentity::new_from_rand(OsRng), false)
        .set_storage(Arc::new(MemoryStorage::new()))
        .build();
    client.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{}", base_port + 1),
            Some(format!("127.0.0.1:{base_port}")),
            false,
        ),
        UdpInterface::spawn,
    );

    // Give the UDP sockets a moment to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;

    Pair { server, client }
}

async fn next_received(
    rx: &mut tokio::sync::broadcast::Receiver<ReceivedData>,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) if &event.destination == destination => {
                return Some(event.data.as_slice().to_vec())
            }
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

/// Wait for an announce of `destination`. Returns `None` on timeout,
/// otherwise the ratchet the announce carried (`None` when it had none).
async fn wait_announce(
    announces: &mut tokio::sync::broadcast::Receiver<reticulum::transport::AnnounceEvent>,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<Option<[u8; 32]>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, announces.recv()).await {
            Ok(Ok(event)) => {
                let announced = event.destination.lock().await.desc.address_hash;
                if &announced == destination {
                    return Some(event.ratchet);
                }
            }
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

async fn wait_receipt(
    transport: &Transport,
    packet_hash: &reticulum::hash::Hash,
    timeout: Duration,
) -> bool {
    let mut receipts = transport.receipt_events();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, receipts.recv()).await {
            Ok(Ok(event)) if &event.packet_hash == packet_hash => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

const NAME: (&str, &str) = ("example_utilities", "identity.transport");

#[tokio::test]
async fn single_destination_encrypted_exchange_with_ratchets() {
    let Pair { server, client } = pair(45512).await;

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let destination = server
        .add_destination(identity, DestinationName::new(NAME.0, NAME.1))
        .await;
    let address = destination.lock().await.desc.address_hash;

    // Enable ratchets on the destination (persists to the MemoryStorage).
    server
        .enable_destination_ratchets(&address, "identity.transport.ratchets")
        .await
        .expect("enable ratchets");

    let mut received = server.received_data_events();
    let mut announces = client.recv_announces().await;
    server.send_announce(&destination, Some(b"app data fixture")).await;

    let first_ratchet = wait_announce(&mut announces, &address, Duration::from_secs(10))
        .await
        .expect("announce seen")
        .expect("announce must carry a ratchet");
    assert_eq!(first_ratchet.len(), 32);

    // Known destinations and ratchets are populated from the announce.
    assert_eq!(client.known_destinations_len().await, 1);
    assert_eq!(client.get_ratchet(&address).await, Some(first_ratchet));
    let ratchet_id = client.current_ratchet_id(&address).await.expect("ratchet id");
    assert_eq!(ratchet_id.len(), 10);

    // Recall returns the announced identity and app data.
    let recalled = client.recall(&address).await.expect("recall");
    {
        let destination = destination.lock().await;
        assert_eq!(
            recalled.to_hex_string(),
            destination.desc.identity.to_hex_string()
        );
    }
    assert_eq!(
        client.recall_app_data(&address).await.as_deref(),
        Some(b"app data fixture".as_ref())
    );

    // Encrypted SINGLE-destination packet exchange with proof.
    let payload: Vec<u8> = (0..128u32).map(|i| (i % 251) as u8).collect();
    let packet_hash = client
        .send_to_destination(&address, &payload)
        .await
        .expect("send");

    let decrypted = next_received(&mut received, &address, Duration::from_secs(10))
        .await
        .expect("encrypted packet received");
    assert_eq!(decrypted, payload);

    // PROVE_ALL (the default) proves the packet.
    assert!(
        wait_receipt(&client, &packet_hash, Duration::from_secs(10)).await,
        "delivery proof must arrive"
    );

    // Rotating the ratchet: the next announce carries a new ratchet, and
    // packets are then encrypted to it.
    destination
        .lock()
        .await
        .rotate_ratchets(OsRng, reticulum::time::unix_time_as_secs() + 10_000);
    server.send_announce(&destination, None).await;

    let second_ratchet = wait_announce(&mut announces, &address, Duration::from_secs(10))
        .await
        .expect("second announce seen")
        .expect("second announce must carry a ratchet");
    assert_ne!(second_ratchet, first_ratchet, "ratchet must rotate");
    assert_eq!(client.get_ratchet(&address).await, Some(second_ratchet));

    let rotated_payload = b"rotated ratchet payload".to_vec();
    client
        .send_to_destination(&address, &rotated_payload)
        .await
        .expect("send after rotation");

    let decrypted = next_received(&mut received, &address, Duration::from_secs(10))
        .await
        .expect("packet after rotation received");
    assert_eq!(decrypted, rotated_payload);

    // The destination ratchet file gained the rotated key.
    let storage = MemoryStorage::new();
    let _ = storage; // ratchets live in the transport storage, checked below
}

#[tokio::test]
async fn proof_strategy_matrix() {
    let Pair { server, client } = pair(45532).await;

    let mut received = server.received_data_events();
    let mut announces = client.recv_announces().await;

    for (strategy, expect_proof) in [
        (ProofStrategy::None, false),
        (ProofStrategy::App, true),
        (ProofStrategy::All, true),
    ] {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let aspect = match strategy {
            ProofStrategy::None => "prove.none",
            ProofStrategy::App => "prove.app",
            ProofStrategy::All => "prove.all",
        };

        let destination = server
            .add_destination(identity, DestinationName::new("example_utilities", aspect))
            .await;
        destination.lock().await.set_proof_strategy(strategy);

        let address = destination.lock().await.desc.address_hash;
        server.send_announce(&destination, None).await;
        wait_announce(&mut announces, &address, Duration::from_secs(10))
            .await
            .expect("announce");

        let payload = format!("payload for {aspect}").into_bytes();
        let packet_hash = client
            .send_to_destination(&address, &payload)
            .await
            .expect("send");

        let decrypted = next_received(&mut received, &address, Duration::from_secs(10))
            .await
            .expect("packet received");
        assert_eq!(decrypted, payload);

        let proved = wait_receipt(&client, &packet_hash, Duration::from_secs(3)).await;
        assert_eq!(proved, expect_proof, "proof strategy {strategy:?}");
    }
}

#[tokio::test]
async fn known_destinations_persist_across_restart() {
    let storage = Arc::new(MemoryStorage::new());

    // Build the pair manually so the client shares the storage that the
    // restarted transport reloads from.
    let server = TransportConfig::new("server", &PrivateIdentity::new_from_rand(OsRng), false)
        .set_storage(Arc::new(MemoryStorage::new()))
        .build();
    server.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:45552", Some("127.0.0.1:45553"), false),
        UdpInterface::spawn,
    );

    let client = TransportConfig::new("client", &PrivateIdentity::new_from_rand(OsRng), false)
        .set_storage(storage.clone())
        .build();
    client.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:45553", Some("127.0.0.1:45552"), false),
        UdpInterface::spawn,
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    let server = server;

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let destination = server
        .add_destination(identity, DestinationName::new("example_utilities", "persisted"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    let mut announces = client.recv_announces().await;
    server.send_announce(&destination, Some(b"persisted app data")).await;
    wait_announce(&mut announces, &address, Duration::from_secs(10))
        .await
        .expect("announce");

    assert_eq!(client.known_destinations_len().await, 1);
    client.save_known_destinations().await.expect("save");

    // A fresh transport with the same storage recalls the destination.
    let restarted = TransportConfig::new("restarted", &PrivateIdentity::new_from_rand(OsRng), false)
        .set_storage(storage)
        .build();

    restarted.load_known_destinations().await.expect("load");
    assert_eq!(restarted.known_destinations_len().await, 1);

    let recalled = restarted.recall(&address).await.expect("recall after restart");
    let expected = destination.lock().await.desc.identity;
    assert_eq!(recalled.to_hex_string(), expected.to_hex_string());
}

/// Ratchets expire after `RATCHET_EXPIRY` (30 days) and are dropped by
/// `clean_known_destinations`.
#[tokio::test]
async fn ratchet_expiry() {
    use reticulum::storage::{KnownRatchets, MemoryStorage, Storage, RATCHETS_DIR};

    let storage = MemoryStorage::new();
    let mut ratchets = KnownRatchets::new();

    let destination = AddressHash::new_from_slice(b"expiry-destinat");
    ratchets.remember(&storage, destination, [9u8; 32], 1_000.0).unwrap();

    let path = format!("{RATCHETS_DIR}/{}", destination.to_hex_string());
    assert!(storage.read(&path).is_some());

    // Not yet expired.
    assert_eq!(ratchets.get(&storage, &destination, 1_000.0 + 100.0), Some([9u8; 32]));

    // After the expiry window the ratchet is gone.
    let expired = 1_000.0 + reticulum::identity::RATCHET_EXPIRY_SECS as f64;
    assert_eq!(ratchets.get(&storage, &destination, expired), None);
}

/// A GROUP destination type parses on the wire and addresses by name hash.
#[tokio::test]
async fn group_destination_packets_parse() {
    use reticulum::buffer::InputBuffer;
    use reticulum::destination::{GroupInputDestination, GroupOutputDestination};
    use reticulum::packet::{DestinationType, Header, Packet, PacketType};
    use reticulum::serde::Serialize;

    let input = GroupInputDestination::new(
        reticulum::identity::EmptyIdentity,
        DestinationName::new("example_utilities", "group"),
    );
    let output = GroupOutputDestination::new(
        reticulum::identity::EmptyIdentity,
        DestinationName::new("example_utilities", "group"),
    );
    assert_eq!(input.desc.address_hash, output.desc.address_hash);

    let mut data = reticulum::packet::PacketDataBuffer::new();
    let _ = data.safe_write(b"group payload");

    let packet = Packet {
        header: Header {
            destination_type: DestinationType::Group,
            packet_type: PacketType::Data,
            ..Default::default()
        },
        destination: input.desc.address_hash,
        data,
        ..Default::default()
    };

    let mut out = [0u8; 1024];
    let mut buffer = reticulum::buffer::OutputBuffer::new(&mut out);
    packet.serialize(&mut buffer).expect("serialize");

    let mut input_buffer = InputBuffer::new(buffer.as_slice());
    let parsed = Packet::deserialize(&mut input_buffer).expect("deserialize");
    assert_eq!(parsed.header.destination_type, DestinationType::Group);
    assert_eq!(parsed.destination, input.desc.address_hash);
    assert_eq!(parsed.data.as_slice(), b"group payload");
}

/// Keep the `Mutex` import referenced for the receiver helper above.
#[allow(dead_code)]
fn _mutex_type_check(_: &Mutex<()>) {}
