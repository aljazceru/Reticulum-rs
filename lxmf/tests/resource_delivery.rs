//! Resource-backed LXMF delivery of large messages over UDP loopback.

use std::time::Duration;

use lxmf::router::{
    AnnounceInfo, DeliveryConfig, LxmEvent, LxmRouter, RouterConfig,
};
use lxmf::{delivery_destination_hash, LXMessage, DIRECT};
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;

async fn build_transport(name: &str, bind: &str, forward: &str) -> Transport {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id, true));
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind, Some(forward), false),
        UdpInterface::spawn,
    );
    transport
}
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

fn fixed_identity(key_hex: &str) -> PrivateIdentity {
    PrivateIdentity::new_from_hex_string(key_hex).expect("valid identity")
}

const ALICE_KEY: &str = "f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964c\
                         fb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7";
const BOB_KEY: &str = "d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add65\
                       0ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697";

fn temp_storage(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("lxmf-resource-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[tokio::test]
async fn large_message_delivered_as_resource() {

    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport_a = build_transport("alice", "127.0.0.1:41011", "127.0.0.1:41012").await;
    let transport_b = build_transport("bob", "127.0.0.1:41012", "127.0.0.1:41011").await;

    let router_a = LxmRouter::new(
        transport_a,
        alice_identity.clone(),
        temp_storage("alice"),
        Some("Alice"),
        Some(DeliveryConfig {
            identity: Some(alice_identity.clone()),
            display_name: Some("Alice".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;
    let router_b = LxmRouter::new(
        transport_b,
        bob_identity.clone(),
        temp_storage("bob"),
        Some("Bob"),
        Some(DeliveryConfig {
            identity: Some(bob_identity.clone()),
            display_name: Some("Bob".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;

    let mut events_a = router_a.subscribe();
    let mut events_b = router_b.subscribe();

    router_a.announce_delivery().await;
    router_b.announce_delivery().await;

    // wait for mutual announces
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                events_a.recv().await,
                Ok(LxmEvent::Announce(AnnounceInfo::Delivery { .. }))
            ) {
                return;
            }
        }
    })
    .await
    .expect("alice learned bob announce");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                events_b.recv().await,
                Ok(LxmEvent::Announce(AnnounceInfo::Delivery { .. }))
            ) {
                return;
            }
        }
    })
    .await
    .expect("bob learned alice announce");

    // A large message that cannot fit in a single link packet is delivered
    // as a resource transfer (Python `LXMessage.__as_resource`).
    let content: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Big", &content);
    router_b.send(&mut message, &bob_identity).await.expect("send");

    let received = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match events_a.recv().await.expect("event") {
                LxmEvent::Received(message) => return message,
                LxmEvent::SendFailed { reason, .. } => {
                    panic!("unexpected send failure: {reason:?}")
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("large message within timeout");

    assert_eq!(received.content, content);
    assert_eq!(received.source_hash, bob_delivery);
    assert!(received.signature_validated, "source announced earlier");
    assert_eq!(received.method, DIRECT);
}
