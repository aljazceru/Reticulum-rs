//! Transport control parity tests (Phase 6.2 / 6.3 / 6.8):
//! * announce ingress limiting holds and later releases announces
//! * announce egress cap defers and queues announces
//! * interface mode announce-forwarding policy
//! * `await_path` resolves for announced destinations
//!
//! The ingress/egress unit semantics are covered in `iface::control::tests`;
//! these tests exercise the wiring inside the transport.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::control::{IfaceControlParams, InterfaceMode};
use reticulum::iface::udp::UdpInterface;
use reticulum::iface::{InterfaceManager, TxMessage, TxMessageType};
use reticulum::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};
use reticulum::transport::{Transport, TransportConfig};

/// Two Rust transports bridged over a UDP interface pair.
struct Pair {
    a: Transport,
    b: Transport,
    a_iface: AddressHash,
}

async fn pair(name: &str, port_a: u16, port_b: u16) -> Pair {
    let a = TransportConfig::new(
        format!("rust-{name}-a"),
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    )
    .set_retransmit(true)
    .build();

    let b = TransportConfig::new(
        format!("rust-{name}-b"),
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    )
    .set_retransmit(true)
    .build();

    let a_iface = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_a}"),
                Some(format!("127.0.0.1:{port_b}")),
                true,
            ),
            UdpInterface::spawn,
        )
    };

    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_b}"),
                Some(format!("127.0.0.1:{port_a}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    // Give the sockets time to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;

    Pair { a, b, a_iface }
}

async fn iface_of(transport: &Transport) -> AddressHash {
    let manager: Arc<tokio::sync::Mutex<InterfaceManager>> = transport.iface_manager();
    let manager = manager.lock().await;
    manager.stats().first().map(|stat| stat.address).unwrap()
}

async fn announce_distinct(transport: &Transport, app: &str) -> AddressHash {
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new(app, "ingress"),
    );
    let hash = destination.desc.address_hash;
    transport
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;
    hash
}

#[tokio::test]
async fn ingress_limiting_holds_and_releases_announces() {
    let Pair { a, b, a_iface } = pair("ingress", 4312, 4313).await;

    // Shorten the control windows so the test runs quickly.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        let params = IfaceControlParams {
            ic_burst_freq_new: 5.0,
            ic_burst_penalty: Duration::from_secs(1),
            ic_burst_hold: Duration::from_millis(500),
            ic_held_release_interval: Duration::from_millis(300),
            ..IfaceControlParams::default()
        };
        manager.with_control(&a_iface, |control| control.set_params(params));
    }

    // A burst of distinct-destination announces from the peer trips the
    // new-interface ingress limit (ic_burst_freq_new = 3 Hz).
    let mut held_destinations = Vec::new();
    for _ in 0..10 {
        held_destinations.push(announce_distinct(&b, "burst").await);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // The interface must now be ingress limited.
    let limited = async {
        for _ in 0..40 {
            let manager = a.iface_manager();
            let manager = manager.lock().await;
            if manager
                .with_control(&a_iface, |control| {
                    control.should_ingress_limit(tokio::time::Instant::now())
                })
                .unwrap_or(false)
            {
                return true;
            }
            drop(manager);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(
        limited,
        "interface should be ingress limited after announce burst"
    );

    // At least one of the burst destinations must have been held (no path
    // learned yet).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut known = 0;
    for dest in &held_destinations {
        if a.has_path(dest).await {
            known += 1;
        }
    }
    assert!(
        known < 10,
        "not all burst announces should be processed immediately"
    );

    // Once the burst penalty has elapsed, the ticker releases held
    // announces and the paths become known.
    let released = async {
        for _ in 0..250 {
            let mut all_known = true;
            for dest in &held_destinations {
                if !a.has_path(dest).await {
                    all_known = false;
                }
            }
            if all_known {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(
        released,
        "held announces must be released after the burst penalty"
    );
}

#[tokio::test]
async fn announce_cap_queues_forwarded_announces() {
    let Pair { a, a_iface, .. } = pair("egress", 4322, 4323).await;

    // A slow radio bitrate makes the announce cap bite.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_bitrate(&a_iface, 1200);
    }

    // Two forwarded (hops > 0) announces: the first spends the airtime
    // budget, the second must be queued.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: announce_packet(2),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: announce_packet(3),
            })
            .await;
    }

    let queued = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&a_iface, |control| control.queued_announces_len())
            .unwrap_or(0)
    };
    assert!(
        queued >= 1,
        "second forwarded announce must be queued by the announce cap"
    );
}

#[tokio::test]
async fn mode_policy_blocks_roaming_to_roaming_announces() {
    let Pair { a, .. } = pair("modes", 4332, 4333).await;

    // A second interface on the forwarding node, so both endpoints of the
    // policy decision are managed by the same transport.
    let iface_a = iface_of(&a).await;
    let iface_b = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4334", Some("127.0.0.1:4335"), true),
            UdpInterface::spawn,
        )
    };

    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_mode(&iface_a, InterfaceMode::Roaming);
        manager.set_iface_mode(&iface_b, InterfaceMode::Roaming);
    }

    let blocked = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.announce_forwarding_allowed(&iface_b, Some(iface_a))
    };
    assert!(
        !blocked,
        "announces from roaming-mode interfaces must not be forwarded onto roaming-mode interfaces"
    );

    let allowed_local = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.announce_forwarding_allowed(&iface_b, None)
    };
    assert!(
        allowed_local,
        "locally originated announces bypass mode gating"
    );
}

#[tokio::test]
async fn control_params_override_defaults() {
    let Pair { a, a_iface, .. } = pair("params", 4342, 4343).await;

    // Disable both the new and steady-state burst thresholds.
    let params = IfaceControlParams {
        ic_burst_freq_new: 100.0,
        ic_burst_freq: 100.0,
        ..IfaceControlParams::default()
    };
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.with_control(&a_iface, |control| control.set_params(params));
    }

    // Feed announce samples directly: even a dense burst stays under the
    // raised threshold.
    for _ in 0..10 {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.received_announce(&a_iface);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let limited = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&a_iface, |control| {
                control.should_ingress_limit(tokio::time::Instant::now())
            })
            .unwrap_or(false)
    };
    assert!(
        !limited,
        "raised burst threshold must disable ingress limiting"
    );
}

#[tokio::test]
async fn await_path_resolves_for_announced_destinations() {
    let Pair { a, b, .. } = pair("await", 4352, 4353).await;

    // An unknown destination can never resolve.
    let unknown = AddressHash::new_from_rand(OsRng);
    let found = a
        .await_path(&unknown, Some(Duration::from_millis(300)), None)
        .await;
    assert!(!found, "no path can resolve for an unannounced destination");

    // The peer announces a destination shortly: await_path resolves as
    // soon as the announce arrives.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("awaited", "dest"),
    );
    let hash = destination.desc.address_hash;

    let dest_arc = Arc::new(tokio::sync::Mutex::new(destination));
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        b.send_announce(&dest_arc, None).await;
    });

    let found = a
        .await_path(&hash, Some(Duration::from_secs(10)), None)
        .await;
    assert!(found, "await_path must resolve once the peer announces");
}

fn announce_packet(hops: u8) -> Packet {
    let mut data = PacketDataBuffer::new();
    data.safe_write(&[1u8; 32]);
    data.safe_write(&[2u8; 32]);
    data.safe_write(&[3u8; 10]);
    data.safe_write(&[0u8; 5]);
    data.safe_write(&42u64.to_be_bytes()[3..8]);
    data.safe_write(&[4u8; 64]);

    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type2,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        },
        ifac: None,
        destination: AddressHash::new_from_rand(OsRng),
        transport: None,
        context: PacketContext::None,
        data,
    }
}
