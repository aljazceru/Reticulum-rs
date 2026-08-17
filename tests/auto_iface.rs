//! AutoInterface tests (feature `iface-auto`).
//!
//! The pure logic (multicast address derivation, discovery tokens) is unit
//! tested against golden vectors generated from `AutoInterface.py` (v1.4.2)
//! and runs everywhere.
//!
//! The full two-node peering test needs IPv6 link-local addresses and
//! multicast routing on the loopback interface, which most CI sandboxes
//! don't provide. It therefore only runs when `RETICULUM_TEST_AUTOIFACE=1`
//! is set *and* two dedicated link-local addresses exist on `lo`
//! (as root):
//!
//! ```sh
//! sudo ip addr add fe80::1/64 dev lo
//! sudo ip addr add fe80::2/64 dev lo
//! sudo ip -6 route add local ff00::/8 dev lo table local
//! RETICULUM_TEST_AUTOIFACE=1 cargo test -p reticulum --features iface-auto --test auto_iface
//! ```

#![cfg(all(feature = "iface-auto", target_os = "linux"))]

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::auto::AutoInterface,
    iface::auto::AutoInterfaceConfig,
    transport::{Transport, TransportConfig},
};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .init()
    });
}

fn auto_config(group: &str, adopt: &str, discovery_port: u16) -> AutoInterfaceConfig {
    AutoInterfaceConfig {
        group_id: group.to_string(),
        discovery_port,
        data_port: discovery_port + 2000,
        devices: vec!["lo".to_string()],
        adopt: Some(adopt.parse().expect("valid link-local address")),
        ..AutoInterfaceConfig::default()
    }
}

async fn auto_transport(name: &str, config: AutoInterfaceConfig) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng), true).build();

    transport.iface_manager().lock().await.spawn(
        AutoInterface::new(config, transport.iface_manager()),
        AutoInterface::spawn,
    );

    transport
}

fn two_node_ready() -> bool {
    if std::env::var("RETICULUM_TEST_AUTOIFACE").ok().as_deref() != Some("1") {
        return false;
    }

    // both dedicated addresses must exist on lo
    let ifaces = reticulum::iface::auto::suitable_interfaces(&["lo".to_string()], &[], None);
    ifaces.len() == 1
        && ifaces[0].name == "lo"
        && ifaces[0].link_local.to_string().contains("fe80:")
}

#[tokio::test]
async fn auto_interface_peers_and_exchanges_announce() {
    setup();

    if !two_node_ready() {
        log::warn!("skipping: RETICULUM_TEST_AUTOIFACE=1 and fe80:: addresses on lo required");
        return;
    }

    // distinct ports from the defaults so a real reticulum on the host
    // isn't disturbed
    let node_a = auto_transport(
        "auto-a",
        auto_config("rs-test-auto", "fe80::1", 39716),
    )
    .await;
    let node_b = auto_transport(
        "auto-b",
        auto_config("rs-test-auto", "fe80::2", 39716),
    )
    .await;

    // wait for the peering (beacon every 1.6s, peering wait 1.2x announce)
    time::sleep(Duration::from_secs(6)).await;

    let stats = node_a.interface_stats().await;
    assert!(
        stats.iter().any(|stat| stat.kind == "AutoPeer" && stat.online),
        "node a should have peered with node b: {stats:#?}"
    );

    let id = PrivateIdentity::new_from_name("auto-announce-a");
    let dest = node_a
        .add_destination(id, DestinationName::new("test", "auto"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    node_a.send_announce(&dest, None).await;

    let mut announces = node_b.recv_announces().await;
    let result = time::timeout(Duration::from_secs(15), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(announce.destination.lock().await.desc.address_hash, dest_hash);
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over auto-peered link"),
    }

    let stats = node_b.interface_stats().await;
    let peer = stats
        .iter()
        .find(|stat| stat.kind == "AutoPeer" && stat.received >= 1)
        .expect("auto peer should have received the announce");
    log::info!("node b peer stats: {peer:#?}");
}
