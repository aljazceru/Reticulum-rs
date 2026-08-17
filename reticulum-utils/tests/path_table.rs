//! Path table snapshot tests (Phase 8: `rnpath -t` / `rnstatus`).

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use reticulum_utils::rnpath;

async fn udp_pair(server_port: u16, client_port: u16) -> (Transport, Transport) {
    let server = TransportConfig::new("srv", &PrivateIdentity::new_from_rand(OsRng), false).build();
    let client = TransportConfig::new("cli", &PrivateIdentity::new_from_rand(OsRng), false).build();
    server
        .iface_manager()
        .lock()
        .await
        .spawn(
            UdpInterface::new(
                format!("127.0.0.1:{server_port}"),
                Some(format!("127.0.0.1:{client_port}")),
                false,
            ),
            UdpInterface::spawn,
        );
    client
        .iface_manager()
        .lock()
        .await
        .spawn(
            UdpInterface::new(
                format!("127.0.0.1:{client_port}"),
                Some(format!("127.0.0.1:{server_port}")),
                false,
            ),
            UdpInterface::spawn,
        );
    (server, client)
}

#[tokio::test]
async fn snapshot_reflects_announced_paths() {
    let (server, client) = udp_pair(4601, 4602).await;

    let destination = server
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "paths"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    server.send_announce(&destination, None).await;

    let found = rnpath::wait_for_path(&client, &dest_hash, Duration::from_secs(10))
        .await
        .expect("path should be found");
    assert_eq!(found.destination, dest_hash);
    assert_eq!(found.hops, 1);

    // Next hop for a directly connected destination is the destination itself.
    let (via, iface) = client.next_hop(&dest_hash).await.expect("next hop");
    assert_eq!(via, dest_hash);
    assert!(!iface.as_slice().iter().all(|b| *b == 0));

    let snapshot = client.path_table_snapshot().await;
    let entry = snapshot
        .iter()
        .find(|entry| entry.destination == dest_hash)
        .expect("snapshot contains the announced destination");
    assert_eq!(entry.hops, 1);
    assert_eq!(entry.via, dest_hash);

    // rnpath table helpers: filtered and hop-limited views.
    let table = rnpath::path_table(&client, Some(&dest_hash), None).await;
    assert_eq!(table.len(), 1);
    let none = rnpath::path_table(&client, Some(&dest_hash), Some(0)).await;
    assert!(none.is_empty());
    assert!(client.has_path(&dest_hash).await);
    assert_eq!(client.hops_to(&dest_hash).await, Some(1));

    // Link counters: none yet.
    let counts = client.link_counts().await;
    assert_eq!(counts.link_table, 0);
    assert_eq!(counts.inbound, 0);
    assert_eq!(counts.outbound, 0);
}

#[tokio::test]
async fn status_report_shows_paths_and_interfaces() {
    let (server, client) = udp_pair(4611, 4612).await;
    let destination = server
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "status"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    server.send_announce(&destination, None).await;
    assert!(
        rnpath::wait_for_path(&client, &dest_hash, Duration::from_secs(10))
            .await
            .is_some()
    );

    let report = reticulum_utils::rnstatus::collect(&client, false).await;
    assert!(report.paths.iter().any(|entry| entry.destination == dest_hash));
    // One UDP interface on the client.
    assert_eq!(report.interfaces.len(), 1);
    assert_eq!(report.interfaces[0].status, "Up");
    let text = report.render();
    assert!(text.contains("Path table (1 entries)"));
    assert!(text.contains("Standalone instance"));
    let json = report.to_json();
    assert!(json.contains("\"transport_id\""));
}
