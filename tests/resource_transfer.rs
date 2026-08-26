//! Resource transfer tests: unit tests for wire formats (against Python
//! golden vectors) and end-to-end loopback transfers over a local link.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use rand_core::OsRng;
use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::DestinationName;
use reticulum::hash::{AddressHash, Hash};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::resource::{
    self, advertisement::ResourceAdvertisement, msgpack_bin, pack_response, request_id,
    unpack_request, unpack_response, ResourceOptions, ResourceStatus, ResourceStrategy,
};
use reticulum::resource::manager::RequestEvent;
use reticulum::transport::{Transport, TransportConfig};

fn setup_logging() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn advertisement_pack_matches_python() {
    let expected = load_vectors()["adv1"].clone();

    let adv = ResourceAdvertisement {
        transfer_size: 1234,
        data_size: 1000,
        parts: 4,
        hash: Hash::new((0u8..32).collect::<Vec<u8>>().try_into().unwrap()),
        random_hash: [0xAA; 4],
        original_hash: Hash::new((32u8..64).collect::<Vec<u8>>().try_into().unwrap()),
        segment_index: 1,
        total_segments: 1,
        request_id: None,
        flags: 0,
        hashmap: vec![1, 2, 3, 4],
    };

    let packed = adv.pack();
    assert_eq!(hex(&packed), expected);

    let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack");
    assert_eq!(unpacked.transfer_size, 1234);
    assert_eq!(unpacked.data_size, 1000);
    assert_eq!(unpacked.parts, 4);
    assert_eq!(unpacked.hash, adv.hash);
    assert_eq!(unpacked.random_hash, adv.random_hash);
    assert_eq!(unpacked.original_hash, adv.original_hash);
    assert_eq!(unpacked.flags, 0);
    assert_eq!(unpacked.hashmap, vec![1, 2, 3, 4]);
    assert!(unpacked.request_id.is_none());
}

#[test]
fn advertisement_pack_with_flags_matches_python() {
    let expected = load_vectors()["adv2"].clone();

    let adv = ResourceAdvertisement {
        transfer_size: 1234,
        data_size: 1000,
        parts: 4,
        hash: Hash::new((0u8..32).collect::<Vec<u8>>().try_into().unwrap()),
        random_hash: [0xAA; 4],
        original_hash: Hash::new((32u8..64).collect::<Vec<u8>>().try_into().unwrap()),
        segment_index: 1,
        total_segments: 1,
        request_id: Some(AddressHash::new([0x0f; 16])),
        flags: 0x3f,
        hashmap: vec![1, 2, 3, 4],
    };

    let packed = adv.pack();
    assert_eq!(hex(&packed), expected);

    let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack");
    assert_eq!(unpacked.flags, 0x3f);
    assert!(unpacked.encrypted());
    assert!(unpacked.compressed());
    assert!(unpacked.split());
    // with all bits set, both request and response flags are set
    assert!(unpacked.is_request());
    assert!(unpacked.is_response());
    assert!(unpacked.has_metadata());
    assert_eq!(
        unpacked.request_id,
        Some(AddressHash::new([0x0f; 16]))
    );
}

fn load_vectors() -> std::collections::HashMap<String, String> {
    let raw = std::fs::read_to_string("tests/fixtures_msgpack.json").expect("fixtures");
    serde_json::from_str(&raw).expect("fixture json")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn request_and_response_wire_formats_match_python() {
    let vectors = load_vectors();
    let golden_req = vectors["req"].as_str();
    let golden_resp = vectors["resp"].as_str();

    let req_bytes = hex_to_bytes(golden_req);
    let (time, path_hash, data) = unpack_request(&req_bytes).expect("unpack request");
    assert!((time - 12345.678).abs() < 0.001);
    assert_eq!(path_hash.as_slice(), &[0x11; 16]);
    assert_eq!(data, b"payload");

    let resp_bytes = hex_to_bytes(golden_resp);
    let (rid, response) = unpack_response(&resp_bytes).expect("unpack response");
    assert_eq!(rid.as_slice(), &[0x22; 16]);
    assert_eq!(response, b"response-data");

    // `unpack_response` unwraps binary elements to their contents, so a
    // byte-for-byte roundtrip re-wraps them as msgpack bins first.
    let re_packed = pack_response(&rid, &msgpack_bin(&response));
    assert_eq!(hex(&re_packed), golden_resp);

    // Request id is the truncated hash of the packed request
    let rid = request_id(&req_bytes);
    assert_eq!(rid.as_slice().len(), 16);
}

#[test]
fn hashmap_update_wire_format_matches_python() {
    let golden = load_vectors()["hmu"].clone();
    let mut packed = Vec::new();
    rmp::encode::write_array_len(&mut packed, 2).unwrap();
    rmp::encode::write_uint(&mut packed, 3).unwrap();
    rmp::encode::write_bin(&mut packed, &[0x33; 8]).unwrap();
    assert_eq!(hex(&packed), golden);
}

#[test]
fn compression_roundtrip() {
    // Highly repetitive data compresses; random data does not.
    let repetitive = vec![0xAB; 10000];
    let (compressed, did_compress) =
        resource::maybe_compress(&repetitive, true, resource::AUTO_COMPRESS_MAX_SIZE);
    if cfg!(feature = "bz2") {
        assert!(did_compress);
        assert!(compressed.len() < repetitive.len());
        let decompressed = resource::decompress(&compressed, 1_000_000).expect("decompress");
        assert_eq!(decompressed, repetitive);

        let random: Vec<u8> = (0..1000u32).map(|i| (i * 7919 % 256) as u8).collect();
        let (unchanged, did_not) =
            resource::maybe_compress(&random, true, resource::AUTO_COMPRESS_MAX_SIZE);
        // random-ish data may or may not compress; whatever the result it
        // must round-trip
        if did_not {
            let back = resource::decompress(&unchanged, 1_000_000).expect("decompress");
            assert_eq!(back, random);
        } else {
            assert_eq!(unchanged.len(), random.len());
        }
    } else {
        assert!(!did_compress);
        assert_eq!(compressed, repetitive);
    }
}

/// Two transports connected over loopback UDP with an active link.
async fn connected_pair(server_port: u16, client_port: u16) -> (Transport, Transport, Arc<Mutex<Link>>) {
    let server_identity = PrivateIdentity::new_from_rand(OsRng);
    let server =
        TransportConfig::new("srv", &server_identity, false).build();
    let client = TransportConfig::new(
        "cli",
        &PrivateIdentity::new_from_rand(OsRng),
        false,
    )
    .build();

    server.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{server_port}"),
            Some(format!("127.0.0.1:{client_port}")),
            false,
        ),
        UdpInterface::spawn,
    );
    client.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{client_port}"),
            Some(format!("127.0.0.1:{server_port}")),
            false,
        ),
        UdpInterface::spawn,
    );

    let destination = server
        .add_destination(server_identity, DestinationName::new("test", "resources"))
        .await;
    let hash = destination.lock().await.desc.address_hash;
    server.send_announce(&destination, None).await;

    let mut announces = client.recv_announces().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let desc = loop {
        assert!(tokio::time::Instant::now() < deadline, "no announce");
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.destination.lock().await.desc.address_hash == hash {
            break event.destination.lock().await.desc;
        }
    };

    let mut client_events = client.out_link_events();
    let link = client.link(desc).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "link inactive");
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            break;
        }
    }

    // wait for the server to register the inbound link
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let link_id = *link.lock().await.id();
    loop {
        assert!(tokio::time::Instant::now() < deadline, "server link missing");
        if server.find_in_link(&link_id).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (server, client, link)
}

#[tokio::test]
async fn resource_transfer_roundtrip() {
    setup_logging();
    let (server, client, link) = connected_pair(4311, 4312).await;

    // Accept all resources on the server side of the link
    let link_id = *link.lock().await.id();
    server.set_resource_strategy(link_id, ResourceStrategy::All).await;

    let mut resource_events = server.resource_events().await;

    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    client.send_resource(&link, payload.clone()).await.expect("send resource");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    let received = received.expect("resource did not complete");
    assert_eq!(received, payload);

    // Wait for the client to see the completion (proof validation)
    let mut client_events = client.resource_events().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "sender completion missing");
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            break;
        }
    }
}

#[tokio::test]
async fn resource_transfer_tiny() {
    let (server, client, link) = connected_pair(4321, 4322).await;
    let link_id = *link.lock().await.id();
    server.set_resource_strategy(link_id, ResourceStrategy::All).await;

    let mut resource_events = server.resource_events().await;
    let payload = b"tiny resource payload".to_vec();
    client.send_resource(&link, payload.clone()).await.expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    assert_eq!(received.expect("tiny resource"), payload);
}

#[tokio::test]
async fn resource_transfer_with_metadata() {
    let (server, client, link) = connected_pair(4331, 4332).await;
    let link_id = *link.lock().await.id();
    server.set_resource_strategy(link_id, ResourceStrategy::All).await;

    let mut resource_events = server.resource_events().await;
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 249) as u8).collect();
    let metadata = b"some metadata".to_vec();
    let options = ResourceOptions {
        metadata: Some(metadata.clone()),
        ..Default::default()
    };
    client
        .send_resource_with_options(&link, payload.clone(), options)
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                got = Some((data, event.metadata));
                break;
            }
        }
    }
    let (data, meta) = got.expect("resource with metadata");
    assert_eq!(data, payload);
    assert_eq!(meta, Some(metadata));
}

#[tokio::test]
async fn request_response_roundtrip() {
    let (server, client, link) = connected_pair(4341, 4342).await;

    // Register a request handler on the server destination
    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");

    let dest_hash = destination.lock().await.desc.address_hash;
    server
        .register_request_handler(&dest_hash, "echo", |ctx| Some(reticulum::resource::msgpack_bin(&ctx.data)))
        .await;

    // Send a request and await the response
    let rid = client
        .request(&link, "echo", b"hello request")
        .await
        .expect("request");

    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await;
    assert_eq!(response, Some(b"hello request".to_vec()));
}

#[tokio::test]
async fn request_response_large_resource_backed() {
    let (server, client, link) = connected_pair(4351, 4352).await;

    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");
    let dest_hash = destination.lock().await.desc.address_hash;

    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    let response_payload = payload.clone();

    server
        .register_request_handler(&dest_hash, "bulk", move |_ctx| {
            Some(msgpack_bin(&response_payload))
        })
        .await;

    let rid = client.request(&link, "bulk", b"send-me-data").await.expect("request");

    let response = client
        .await_request_response(rid, Duration::from_secs(60))
        .await;
    assert_eq!(response, Some(payload));
}

#[tokio::test]
async fn split_response_can_be_awaited_after_completion_event() {
    let (server, client, link) = connected_pair(4353, 4354).await;

    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");
    let dest_hash = destination.lock().await.desc.address_hash;
    let payload: Vec<u8> = (0..(resource::MAX_EFFICIENT_SIZE + 4096) as u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let response_payload = payload.clone();
    server
        .register_request_handler(&dest_hash, "split-bulk", move |_ctx| {
            Some(msgpack_bin(&response_payload))
        })
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request(&link, "split-bulk", b"late-await")
        .await
        .expect("request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let event = tokio::time::timeout_at(deadline, request_events.recv())
            .await
            .expect("response event timeout")
            .expect("request event channel");
        if matches!(event.event, RequestEvent::Response { request_id, .. } if request_id == rid) {
            break;
        }
    }

    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await;
    assert_eq!(response, Some(payload));
}

#[tokio::test]
async fn resource_transfer_reject_oversized() {
    let (server, client, link) = connected_pair(4361, 4362).await;
    // Default strategy is None: advertisements are ignored
    let mut resource_events = server.resource_events().await;
    let payload = vec![0u8; 1000];
    client.send_resource(&link, payload).await.expect("send");

    // no acceptance event should arrive
    let result =
        tokio::time::timeout(Duration::from_secs(2), resource_events.recv()).await;
    if let Ok(Ok(event)) = result {
        // any event other than a completion is fine
        assert_ne!(event.status, ResourceStatus::Complete);
    }
}
