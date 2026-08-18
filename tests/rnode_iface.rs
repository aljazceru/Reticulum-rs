//! RNode interface end-to-end against a mock RNode device (Phase 5.5):
//! detection + firmware validation + radio configuration validation, and
//! packet exchange between two RNode interfaces bridged by the mock.

#![cfg(feature = "iface-rnode")]

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::rnode::*;
use reticulum::transport::TransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CONFIG: RnodeRadioConfig = RnodeRadioConfig {
    frequency: 867_500_000,
    bandwidth: 125_000,
    txpower: 13,
    spreadingfactor: 9,
    codingrate: 5,
    st_alock: None,
    lt_alock: None,
};

/// Parse complete KISS frames from a stream of bytes.
fn parse_frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut current: Option<(u8, Vec<u8>)> = None;
    let mut escaped = false;

    for &byte in bytes {
        if byte == FEND {
            if let Some(frame) = current.take() {
                frames.push(frame);
            }
            continue;
        }

        match current.as_mut() {
            None => current = Some((byte, Vec::new())),
            Some((_, payload)) => {
                if escaped {
                    escaped = false;
                    payload.push(match byte {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => byte,
                    });
                } else if byte == FESC {
                    escaped = true;
                } else {
                    payload.push(byte);
                }
            }
        }
    }

    if let Some(frame) = current.take() {
        frames.push(frame);
    }

    frames
}

/// A mock RNode device over TCP: responds to detect/config and bridges
/// data frames between all connected hosts.
async fn mock_rnode(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

    let (bridge_tx, _bridge_rx) = tokio::sync::broadcast::channel::<Vec<u8>>(64);

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };

        let bridge_tx = bridge_tx.clone();
        let mut bridge_rx = bridge_tx.subscribe();

        let (mut reader, writer) = socket.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        // Broadcaster: forward received data frames to all hosts.
        let tx_task = {
            let bridge_tx = bridge_tx.clone();
            let writer = writer.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let mut carry = Vec::new();

                loop {
                    let Ok(n) = reader.read(&mut buffer).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }

                    carry.extend_from_slice(&buffer[..n]);

                    let (complete, rest) = split_complete_frames(&carry);
                    carry = rest;

                    let mut writer = writer.lock().await;
                    for (command, payload) in complete {
                        match command {
                            CMD_DETECT if payload.first() == Some(&DETECT_REQ) => {
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_DETECT, &[DETECT_RESP]))
                                    .await;
                            }
                            CMD_FW_VERSION => {
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_FW_VERSION, &[1, 60]))
                                    .await;
                            }
                            CMD_PLATFORM => {
                                let _ = writer.write_all(&kiss_frame(CMD_PLATFORM, &[0x40])).await;
                            }
                            CMD_MCU => {
                                let _ = writer.write_all(&kiss_frame(CMD_MCU, &[0x30])).await;
                            }
                            CMD_DATA => {
                                // bridge data to all hosts
                                let _ = bridge_tx.send(kiss_frame(CMD_DATA, &payload));
                            }
                            CMD_RADIO_STATE => {
                                // echo the radio state back
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_RADIO_STATE, &payload))
                                    .await;
                            }
                            // Configuration echoes: respond with the same
                            // command and payload so validation passes.
                            CMD_FREQUENCY | CMD_BANDWIDTH | CMD_TXPOWER | CMD_SF | CMD_CR => {
                                let _ = writer.write_all(&kiss_frame(command, &payload)).await;
                            }
                            _ => {}
                        }
                    }
                }
            })
        };

        // Receiver: forward bridged data frames to this host.
        let rx_task = {
            let writer = writer.clone();
            tokio::spawn(async move {
                loop {
                    match bridge_rx.recv().await {
                        Ok(frame) => {
                            if writer.lock().await.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        };

        let _ = (tx_task, rx_task);
    }
}

/// Split a byte stream into complete frames and the trailing remainder.
fn split_complete_frames(bytes: &[u8]) -> (Vec<(u8, Vec<u8>)>, Vec<u8>) {
    let frames = parse_frames(bytes);

    let mut rest = Vec::new();
    if let Some(last_fend) = bytes.iter().rposition(|&b| b == FEND) {
        // bytes after the last FEND are the incomplete remainder
        if last_fend + 1 < bytes.len() {
            rest.extend_from_slice(&bytes[last_fend + 1..]);
        }
    }

    (frames, rest)
}

#[tokio::test]
async fn rnode_detect_validate_and_exchange() {
    const PORT: u16 = 4982;

    tokio::spawn(mock_rnode(PORT));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let a = Arc::new(TransportConfig::new("rnode-a", &identity_a, false).build());
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let b = Arc::new(TransportConfig::new("rnode-b", &identity_b, false).build());

    let iface_a = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeInterface::tcp(format!("127.0.0.1:{PORT}"), CONFIG).with_manager(a.iface_manager()),
            RnodeInterface::spawn,
        )
    };

    let iface_b = {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeInterface::tcp(format!("127.0.0.1:{PORT}"), CONFIG).with_manager(b.iface_manager()),
            RnodeInterface::spawn,
        )
    };

    // Both interfaces must come online (detection + validation passed).
    let online = async {
        for _ in 0..400 {
            let stats_a = a.interface_stats().await;
            let stats_b = b.interface_stats().await;
            let a_up = stats_a.iter().any(|s| s.address == iface_a && s.online);
            let b_up = stats_b.iter().any(|s| s.address == iface_b && s.online);
            if a_up && b_up {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "both rnode interfaces must validate and come online");

    // B announces: A must learn the path through the bridged mock radio.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("rnode", "test"),
    );
    let dest_hash = destination.desc.address_hash;
    b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let learned = async {
        for _ in 0..400 {
            if a.has_path(&dest_hash).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(learned, "announce must flow through the rnode bridge");
}

#[tokio::test]
async fn rnode_parser_and_framing() {
    // Detection request matches the Python byte layout.
    let detect = detect_request();
    let frames = parse_frames(&detect);
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0], (CMD_DETECT, vec![DETECT_REQ]));
    assert_eq!(frames[1], (CMD_FW_VERSION, vec![0x00]));
    assert_eq!(frames[2], (CMD_PLATFORM, vec![0x00]));
    assert_eq!(frames[3], (CMD_MCU, vec![0x00]));

    // Config frames carry big-endian values.
    let config = RnodeRadioConfig {
        frequency: 0x11223344,
        bandwidth: 125_000,
        txpower: 13,
        spreadingfactor: 9,
        codingrate: 5,
        st_alock: Some(18.5),
        lt_alock: None,
    };
    let frames = config.configuration_frames(RADIO_STATE_ON);
    let parsed = parse_frames(&frames.concat());
    assert_eq!(parsed[0], (CMD_FREQUENCY, vec![0x11, 0x22, 0x33, 0x44]));
    assert_eq!(parsed[5], (CMD_ST_ALOCK, vec![0x07, 0x3A])); // 18.5% * 100 = 1850
    assert_eq!(parsed.last().unwrap(), &(CMD_RADIO_STATE, vec![RADIO_STATE_ON]));

    // Escaping round trips.
    let payload = vec![FEND, FESC, 0x00, 0xFF, TFEND, TFESC];
    let frame = kiss_frame(CMD_DATA, &payload);
    let parsed = parse_frames(&frame);
    assert_eq!(parsed, vec![(CMD_DATA, payload)]);

    // Parser: events from a device stream.
    let mut events = Vec::new();
    let mut parser = RnodeParser::new(false);
    let mut stream = Vec::new();
    stream.extend_from_slice(&kiss_frame(CMD_DETECT, &[DETECT_RESP]));
    stream.extend_from_slice(&kiss_frame(CMD_FW_VERSION, &[1, 61]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_RSSI, &[100]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_SNR, &[0xFC]));
    parser.feed(&stream, |event| events.push(event));

    assert!(matches!(events[0], RnodeEvent::Detect));
    assert!(matches!(
        events[1],
        RnodeEvent::FirmwareVersion { major: 1, minor: 61 }
    ));
    match &events[2] {
        RnodeEvent::Status(status) => assert_eq!(status.rssi, Some(100 - RSSI_OFFSET)),
        _ => panic!("expected rssi status"),
    }
    match &events[3] {
        RnodeEvent::Status(status) => assert_eq!(status.snr, Some(-1.0)),
        _ => panic!("expected snr status"),
    }

    // Firmware gate: 1.51 must be rejected, 1.52 accepted.
    let base = RnodeEchoState {
        frequency: Some(0x11223344),
        bandwidth: Some(125_000),
        txpower: Some(13),
        spreadingfactor: Some(9),
        codingrate: Some(5),
        radio_state: Some(RADIO_STATE_ON),
        ..RnodeEchoState::default()
    };
    assert!(config.validate(&base).is_ok());

    // Frequency tolerance: ±100 Hz like Python's validation.
    let mut echo = base.clone();
    echo.frequency = Some(0x11223344 + 100);
    assert!(config.validate(&echo).is_ok());
    echo.frequency = Some(0x11223344 + 101);
    assert!(config.validate(&echo).is_err());

    echo.radio_state = Some(RADIO_STATE_OFF);
    assert!(config.validate(&echo).is_err());

    // Multi framing: SEL_INT prefix + vport data commands.
    let vport = RnodeVport {
        index: 1,
        config: CONFIG,
    };
    let frames = vport.configuration_frames(RADIO_STATE_ON);
    assert!(frames[0].starts_with(&[FEND, CMD_SEL_INT, 1, FEND, FEND]));

    let mut multi_events = Vec::new();
    let mut multi_parser = RnodeParser::new(true);
    multi_parser.feed(&kiss_frame(CMD_INT_DATA[1], b"vport data"), |event| {
        multi_events.push(event)
    });
    match &multi_events[0] {
        RnodeEvent::Data { vport, data } => {
            assert_eq!(*vport, Some(1));
            assert_eq!(data, b"vport data");
        }
        _ => panic!("expected vport data event"),
    }
}
