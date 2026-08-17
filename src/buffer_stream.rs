//! Buffer streams over channels, a port of Python `RNS.Buffer`.
//!
//! `StreamDataMessage` frames carry `(stream_id | flags, data)` in the
//! channel envelope with the system-reserved message type `SMT_STREAM_DATA`.
//! `BufferReader`/`BufferWriter` expose `AsyncRead`/`AsyncWrite` stream
//! semantics over a reliable channel, byte-compatible with Python readers
//! and writers.

use alloc::vec::Vec;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::broadcast;

use crate::channel::{Channel, Message};
use crate::error::RnsError;

/// System-reserved channel message type for stream data
/// (Python `SystemMessageTypes.SMT_STREAM_DATA`).
pub const SMT_STREAM_DATA: u16 = 0xff00;

/// Maximum stream id value (2 bytes minus 2 flag bits).
pub const STREAM_ID_MAX: u16 = 0x3fff;

/// 2 bytes stream header + 6 bytes channel envelope
/// (Python `StreamDataMessage.OVERHEAD`).
pub const OVERHEAD: usize = 2 + 6;

/// Maximum data length of one stream frame.
pub const MAX_DATA_LEN: usize = crate::packet::LINK_MDU - OVERHEAD;

/// Maximum raw chunk length before compression attempts
/// (Python `RawChannelWriter.MAX_CHUNK_LEN`).
pub const MAX_CHUNK_LEN: usize = 1024 * 16;

const COMPRESSION_TRIES: usize = 4;
const DUPLEX_BUFFER: usize = 64 * 1024;

/// A stream data frame as carried over the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDataMessage {
    pub stream_id: u16,
    pub data: Vec<u8>,
    pub eof: bool,
    pub compressed: bool,
}

impl StreamDataMessage {
    /// Pack into the 2-byte-header + payload layout
    /// (Python `StreamDataMessage.pack`):
    /// `header = (stream_id & 0x3fff) | eof<<15 | compressed<<14`.
    pub fn pack_bytes(&self) -> Vec<u8> {
        let mut header = self.stream_id & STREAM_ID_MAX;
        if self.eof {
            header |= 0x8000;
        }
        if self.compressed {
            header |= 0x4000;
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Unpack from the 2-byte-header + payload layout, decompressing when
    /// the compressed flag is set (bounded like Python).
    pub fn unpack_bytes(raw: &[u8]) -> Result<Self, RnsError> {
        if raw.len() < 2 {
            return Err(RnsError::PacketError);
        }
        let header = u16::from_be_bytes([raw[0], raw[1]]);
        let eof = header & 0x8000 != 0;
        let compressed = header & 0x4000 != 0;
        let stream_id = header & STREAM_ID_MAX;
        let mut data = raw[2..].to_vec();

        if compressed && !data.is_empty() {
            data = crate::resource::decompress(&data, MAX_CHUNK_LEN)?;
        }

        Ok(Self { stream_id, data, eof, compressed })
    }
}

impl Message for StreamDataMessage {
    fn unpack(packed: &[u8], _message_type: u16) -> Result<Self, RnsError> {
        Self::unpack_bytes(packed)
    }

    fn pack(&self) -> Vec<u8> {
        self.pack_bytes()
    }

    fn message_type(&self) -> u16 {
        SMT_STREAM_DATA
    }
}

/// The receiving end of a buffer stream
/// (Python `RawChannelReader` + `Buffer.create_reader`).
pub struct BufferReader {
    stream_id: u16,
    duplex: ReadHalf<DuplexStream>,
}

impl BufferReader {
    pub(crate) fn new(
        stream_id: u16,
        mut incoming: broadcast::Receiver<StreamDataMessage>,
    ) -> Self {
        // The user reads from `client`; the pump writes received frames
        // into the other end (`peer`) so they flow to the user.
        let (client, mut peer) = tokio::io::duplex(DUPLEX_BUFFER);
        let (duplex, _) = tokio::io::split(client);

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            loop {
                match incoming.recv().await {
                    Ok(message) => {
                        log::debug!(
                            "buffer_stream: reader got frame stream_id={} eof={} {} bytes",
                            message.stream_id,
                            message.eof,
                            message.data.len()
                        );
                        if message.stream_id != stream_id {
                            continue;
                        }
                        let eof = message.eof;
                        if !message.data.is_empty() {
                            let mut data = message.data;
                            while !data.is_empty() {
                                let take = data.len().min(4096);
                                let slice: Vec<u8> = data.drain(..take).collect();
                                if peer.write_all(&slice).await.is_err() {
                                    return;
                                }
                            }
                        }
                        if eof {
                            // half-close the pump so the reader sees EOF
                            let _ = peer.shutdown().await;
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("buffer_stream: reader lagged, {n} frames lost");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        let _ = peer.shutdown().await;
                        return;
                    }
                }
            }
        });

        Self { stream_id, duplex }
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

impl AsyncRead for BufferReader {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::pin::Pin::new(&mut self.get_mut().duplex).poll_read(cx, buf)
    }
}

/// The sending end of a buffer stream
/// (Python `RawChannelWriter` + `Buffer.create_writer`).
pub struct BufferWriter {
    stream_id: u16,
    duplex: WriteHalf<DuplexStream>,
}

impl BufferWriter {
    pub(crate) fn new(stream_id: u16, channel: Channel<StreamDataMessage>) -> Self {
        // The user writes into `client`; the pump reads what was written
        // from the other end (`peer`) and frames it onto the channel.
        let (client, mut peer) = tokio::io::duplex(DUPLEX_BUFFER);
        let (_, duplex) = tokio::io::split(client);

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut channel = channel;

            // Wait for the channel to become ready before the first frame.
            let ready_deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(30);
            while !channel.is_ready().await {
                if tokio::time::Instant::now() > ready_deadline {
                    log::debug!("buffer_stream: channel never became ready");
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }

            let mut chunk = Vec::with_capacity(MAX_CHUNK_LEN);
            let mut tmp = [0u8; MAX_CHUNK_LEN];
            loop {
                chunk.clear();
                let n = match peer.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return,
                };
                chunk.extend_from_slice(&tmp[..n]);

                // Send the chunk in as many frames as needed, retrying while
                // the channel window is full (LinkNotReady), waiting for each
                // frame's delivery receipt before continuing (backpressure).
                let mut offset = 0usize;
                while offset < chunk.len() {
                    let deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(120);
                    loop {
                        match write_frame(&mut channel, stream_id, &chunk[offset..], false)
                            .await
                        {
                            Ok(processed) => {
                                offset += processed;
                                break;
                            }
                            Err(RnsError::LinkNotReady) | Err(RnsError::ChannelError) => {
                                if tokio::time::Instant::now() > deadline {
                                    log::debug!(
                                        "buffer_stream: channel window never opened"
                                    );
                                    return;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(20))
                                    .await;
                            }
                            Err(err) => {
                                log::debug!("buffer_stream: write_frame failed: {err:?}");
                                return;
                            }
                        }
                    }
                    if let Some(mut receipt_rx) = pending_receipt(&mut channel).await {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            receipt_rx.recv(),
                        )
                        .await;
                    }
                }
            }

            // Reader closed: send EOF.
            let _ = write_frame(&mut channel, stream_id, &[], true).await;
        });

        Self { stream_id, duplex }
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

impl AsyncWrite for BufferWriter {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<Result<usize, std::io::Error>> {
        core::pin::Pin::new(&mut self.get_mut().duplex).poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), std::io::Error>> {
        core::pin::Pin::new(&mut self.get_mut().duplex).poll_flush(cx)
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), std::io::Error>> {
        core::pin::Pin::new(&mut self.get_mut().duplex).poll_shutdown(cx)
    }
}

/// Frame and send one chunk, mirroring the Python compression heuristic:
/// try progressively smaller prefixes, send the first that compresses below
/// both `MAX_DATA_LEN` and its own size; otherwise send up to `MAX_DATA_LEN`
/// uncompressed. Returns the number of bytes consumed.
async fn write_frame(
    channel: &mut Channel<StreamDataMessage>,
    stream_id: u16,
    data: &[u8],
    eof: bool,
) -> Result<usize, RnsError> {
    if eof {
        let message = StreamDataMessage {
            stream_id,
            data: Vec::new(),
            eof: true,
            compressed: false,
        };
        channel.send(&message).await?;
        return Ok(0);
    }

    let mut chunk: &[u8] = data;
    if chunk.len() > MAX_CHUNK_LEN {
        chunk = &chunk[..MAX_CHUNK_LEN];
    }

    let mut compressed_frame: Option<(Vec<u8>, usize)> = None;
    let mut comp_try = 1usize;
    while chunk.len() > 32 && comp_try < COMPRESSION_TRIES {
        let segment_length = chunk.len() / comp_try;
        let (compressed, _) =
            crate::resource::maybe_compress(&chunk[..segment_length], true, usize::MAX);
        if compressed.len() < MAX_DATA_LEN && compressed.len() < segment_length {
            compressed_frame = Some((compressed, segment_length));
            break;
        }
        comp_try += 1;
    }

    let (payload, processed, compressed) = match compressed_frame {
        Some((compressed, segment_length)) => (compressed, segment_length, true),
        None => {
            let take = chunk.len().min(MAX_DATA_LEN);
            (chunk[..take].to_vec(), take, false)
        }
    };

    let message = StreamDataMessage {
        stream_id,
        data: payload,
        eof: false,
        compressed,
    };
    channel.send(&message).await?;
    log::debug!(
        "buffer_stream: frame of {processed} bytes queued (compressed={compressed})"
    );
    Ok(processed)
}

/// Get a delivery-receipt receiver from the channel if one is available
/// for the most recent message (backpressure for stream pumps).
async fn pending_receipt(
    channel: &mut Channel<StreamDataMessage>,
) -> Option<tokio::sync::broadcast::Receiver<bool>> {
    channel.last_receipt().await
}

/// A bidirectional buffer stream pair
/// (Python `Buffer.create_bidirectional_buffer`).
pub struct BufferStream {
    pub reader: BufferReader,
    pub writer: BufferWriter,
}

/// Create a reader/writer pair bound to one channel.
///
/// `receive_stream_id` is the local stream id the peer writes to;
/// `send_stream_id` is the remote stream id frames are addressed to.
pub fn create_bidirectional_buffer(
    channel: &Channel<StreamDataMessage>,
    incoming: broadcast::Receiver<StreamDataMessage>,
    receive_stream_id: u16,
    send_stream_id: u16,
) -> BufferStream {
    BufferStream {
        reader: BufferReader::new(receive_stream_id, incoming),
        writer: BufferWriter::new(send_stream_id, channel.clone_for_stream()),
    }
}

/// Create a reader (Python `Buffer.create_reader`).
pub fn create_reader(
    stream_id: u16,
    incoming: broadcast::Receiver<StreamDataMessage>,
) -> BufferReader {
    BufferReader::new(stream_id, incoming)
}

/// Create a writer (Python `Buffer.create_writer`).
pub fn create_writer(
    stream_id: u16,
    channel: Channel<StreamDataMessage>,
) -> BufferWriter {
    BufferWriter::new(stream_id, channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_pack_unpack() {
        let msg = StreamDataMessage {
            stream_id: 0x1234,
            data: b"hello stream".to_vec(),
            eof: false,
            compressed: false,
        };
        let packed = msg.pack_bytes();
        assert_eq!(&packed[..2], &[0x12, 0x34]);
        assert_eq!(&packed[2..], b"hello stream");
        let unpacked = StreamDataMessage::unpack_bytes(&packed).unwrap();
        assert_eq!(unpacked, msg);

        let msg = StreamDataMessage {
            stream_id: 0x0001,
            data: vec![],
            eof: true,
            compressed: false,
        };
        let packed = msg.pack_bytes();
        assert_eq!(&packed[..2], &[0x80, 0x01]);
        assert!(StreamDataMessage::unpack_bytes(&packed).unwrap().eof);

        let msg = StreamDataMessage {
            stream_id: 0x0002,
            data: vec![],
            eof: false,
            compressed: true,
        };
        let packed = msg.pack_bytes();
        assert_eq!(&packed[..2], &[0x40, 0x02]);
        assert!(StreamDataMessage::unpack_bytes(&packed).unwrap().compressed);
    }

    #[test]
    fn compressed_roundtrip() {
        let data = vec![0xAB; 5000];
        let (compressed, did) =
            crate::resource::maybe_compress(&data, true, usize::MAX);
        assert!(did);
        let msg = StreamDataMessage {
            stream_id: 7,
            data: compressed,
            eof: false,
            compressed: true,
        };
        let unpacked = StreamDataMessage::unpack_bytes(&msg.pack_bytes()).unwrap();
        assert_eq!(unpacked.data, data);
        assert!(unpacked.compressed);
    }

    #[test]
    fn message_type_is_system_reserved() {
        let msg = StreamDataMessage {
            stream_id: 1,
            data: vec![],
            eof: false,
            compressed: false,
        };
        assert_eq!(msg.message_type(), SMT_STREAM_DATA);
        assert!(msg.message_type() >= 0xff00);
    }
}
