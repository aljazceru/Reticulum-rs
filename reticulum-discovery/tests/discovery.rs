//! End-to-end network interface discovery: node A announces a
//! discoverable TCP server interface, node B's `InterfaceDiscovery`
//! validates the announce, tracks it and auto-connects to it.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use reticulum_discovery::{
    DiscoveredStatus, InterfaceAnnouncer, InterfaceDiscovery, InterfaceInfo,
};

async fn udp_bridge(
    a: &Arc<Transport>,
    b: &Arc<Transport>,
    port_a: u16,
    port_b: u16,
) {
    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_a}"),
                Some(format!("127.0.0.1:{port_b}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
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
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn discovery_announce_validate_and_autoconnect() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);

    let a = Arc::new(
        TransportConfig::new("disc-a", &identity_a, false)
            .build(),
    );
    let b = Arc::new(
        TransportConfig::new("disc-b", &identity_b, false)
            .build(),
    );

    // UDP bridge for the discovery announces.
    udp_bridge(&a, &b, 4432, 4433).await;

    // A also runs a TCP server interface which it announces as
    // discoverable.
    let tcp_port = 4434u16;
    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            TcpServer::new(format!("127.0.0.1:{tcp_port}"), a.iface_manager()),
            TcpServer::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Low stamp value keeps the test fast.
    let announcer = InterfaceAnnouncer::start(
        &a,
        &identity_a,
        4,
        Duration::from_millis(300),
    )
    .await;

    announcer
        .announce_interface(InterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            transport: false,
            transport_id: *identity_a.address_hash(),
            name: Some("test-server".to_string()),
            latitude: None,
            longitude: None,
            height: None,
            reachable_on: Some("127.0.0.1".to_string()),
            port: Some(tcp_port),
            frequency: None,
            bandwidth: None,
            spreadingfactor: None,
            codingrate: None,
            channel: None,
            modulation: None,
            ifac_netname: None,
            ifac_netkey: None,
        })
        .await;

    // B listens with a matching required stamp value and autoconnect.
    let discovery = InterfaceDiscovery::start(&b, 4, true).await;

    // The announce must arrive and validate.
    let discovered = async {
        for _ in 0..200 {
            if discovery.discovered_count().await >= 1 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(discovered, "discovery announce must be received and validated");

    let table = discovery.list().await;
    assert_eq!(table.len(), 1);
    assert_eq!(table[0].info.name.as_deref(), Some("test-server"));
    assert_eq!(table[0].info.port, Some(tcp_port));
    assert_eq!(table[0].status(), DiscoveredStatus::Available);

    // Auto-connect to the discovered TCP interface.
    let connected = discovery.connect_discovered().await;
    assert!(connected >= 1, "discovered TCP interface must be auto-connected");

    let stats = b.interface_stats().await;
    assert!(
        stats.iter().any(|stat| stat.kind == "TcpClient"),
        "b must have a connected TCP client interface"
    );
}
