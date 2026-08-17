//! Buffer stream tests: Rust round-trips and wire-format vectors.

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use reticulum::buffer_stream::{
    create_bidirectional_buffer, StreamDataMessage, MAX_DATA_LEN,
};
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
            .init()
    });
}

async fn build_transport(name: &str, bind: &str, forward: &str) -> (Transport, PrivateIdentity) {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id, true));
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind, Some(forward), false),
        UdpInterface::spawn,
    );
    (transport, id)
}

/// Two transports exchange a stream over a channel: the wire frames must
/// match the Python `StreamDataMessage` layout.
#[tokio::test]
async fn buffer_round_trip() {
    setup();

    let (transport_a, id_a) = build_transport("a", "127.0.0.1:8181", "127.0.0.1:8182").await;
    let (transport_b, _) = build_transport("b", "127.0.0.1:8182", "127.0.0.1:8181").await;

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;

    let dest = transport_a
        .add_destination(id_a, DestinationName::new("test", "buffers.stream"))
        .await;
    transport_a.send_announce(&dest, None).await;
    let announce = recv_announces.recv().await.unwrap();

    let link = transport_b.link(announce.destination.lock().await.desc).await;
    let (channel_b, receiver_b) =
        transport_b.mk_channel::<StreamDataMessage>(link).await.unwrap();

    let event = in_link_events.recv().await.unwrap();
    let (channel_a, receiver_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.find_in_link(&event.id).await.unwrap();
            transport_a.mk_channel::<StreamDataMessage>(link).await.unwrap()
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        out_link_events.recv().await.unwrap().event,
        LinkEvent::Activated
    ));

    // Wait for the channel to be ready before writing
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !channel_b.is_ready().await {
        assert!(tokio::time::Instant::now() < deadline, "channel not ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // B writes a stream to A; A writes a stream back
    let stream_b = create_bidirectional_buffer(&channel_b, receiver_b, 1, 2);
    let stream_a = create_bidirectional_buffer(&channel_a, receiver_a, 2, 1);

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

    // write from B
    let mut writer_b = stream_b.writer;
    writer_b.write_all(&payload).await.expect("write");
    log::debug!("TEST: write_all done");
    writer_b.shutdown().await.expect("eof");
    log::debug!("TEST: shutdown done");

    // read on A
    let mut received = Vec::new();
    let mut reader_a = stream_a.reader;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut done = false;
    while !done {
        assert!(tokio::time::Instant::now() < deadline, "stream did not complete");
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), reader_a.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read error");
        if n == 0 {
            done = true;
        } else {
            received.extend_from_slice(&tmp[..n]);
        }
    }
    assert_eq!(received, payload);
}

#[test]
fn frame_layout_matches_python() {
    // Python: struct.pack(">H", (0x3fff & 1) | 0x8000 if eof) + data
    let msg = StreamDataMessage {
        stream_id: 1,
        data: b"abc".to_vec(),
        eof: true,
        compressed: false,
    };
    assert_eq!(msg.pack_bytes(), vec![0x80, 0x01, b'a', b'b', b'c']);
}

#[test]
fn mdu_bound() {
    // Stream frames must fit in a link MDU minus the stream overhead.
    assert_eq!(MAX_DATA_LEN, reticulum::packet::LINK_MDU - 8);
}

