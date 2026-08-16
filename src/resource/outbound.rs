//! Outbound (sender) side of a resource transfer.

use alloc::vec::Vec;

use rand_core::OsRng;
use sha2::Digest;

use crate::destination::link::{Link, LinkId};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::packet::{Packet, PacketContext, PacketType};

use super::advertisement::{
    ResourceAdvertisement, COLLISION_GUARD_SIZE, HASHMAP_MAX_LEN,
};
use super::{
    map_hash, maybe_compress, unix_time, ResourceStatus, ResourceTx, MAX_ADV_RETRIES,
    MAX_EFFICIENT_SIZE, MAX_RETRIES, MAPHASH_LEN, RANDOM_HASH_SIZE, RESPONSE_MAX_GRACE_TIME,
    SDU, SENDER_GRACE_TIME, WINDOW_MAX,
};

pub use super::ResourceOptions;

/// A prepared resource awaiting advertisement, or an active sender.
pub struct OutgoingResource {
    pub link_id: LinkId,
    pub status: ResourceStatus,
    pub hash: Hash,
    pub truncated_hash: AddressHash,
    pub expected_proof: Hash,
    pub original_hash: Hash,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Transfer size: length of the encrypted stream.
    pub size: usize,
    /// Uncompressed data size (metadata + data).
    pub total_size: usize,
    pub compressed: bool,
    pub encrypted: bool,
    pub split: bool,
    pub has_metadata: bool,
    pub metadata_size: usize,
    pub segment_index: usize,
    pub total_segments: usize,
    pub request_id: Option<AddressHash>,
    pub is_response: bool,
    pub sdu: usize,

    /// Pre-built part packets with per-part map hashes.
    pub parts: Vec<Packet>,
    pub part_hashes: Vec<[u8; MAPHASH_LEN]>,
    pub part_sent: Vec<bool>,
    pub hashmap: Vec<u8>,
    pub sent_parts: usize,

    pub receiver_min_consecutive_height: usize,
    pub req_hashlist: Vec<Hash>,

    pub rtt: Option<f64>,
    pub adv_sent: Option<f64>,
    pub last_activity: f64,
    pub last_part_sent: f64,
    pub retries_left: usize,
    pub max_retries: usize,
    pub timeout: f64,
    pub timeout_factor: f64,
    pub sender_grace_time: f64,

    /// Full original stream (metadata + data) kept for segmentation.
    pub original_stream: Option<Vec<u8>>,
    /// Prepared next segment (already compressed/split), advertised when
    /// the current segment completes.
    pub next_segment: Option<Box<OutgoingResource>>,
    pub advertise_next: bool,
}

impl OutgoingResource {
    /// Create an outbound resource for `data` (metadata prepended when
    /// given), splitting, compressing, encrypting and hashing exactly like
    /// Python `RNS.Resource.__init__`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data: Vec<u8>,
        link: &Link,
        opts: ResourceOptions,
    ) -> Result<Self, RnsError> {
        let mut metadata_blob = Vec::new();
        let mut has_metadata = false;
        let mut metadata_size = 0usize;

        if let Some(metadata) = &opts.metadata {
            let packed = metadata; // callers pass pre-packed msgpack bytes
            if packed.len() > super::METADATA_MAX_SIZE {
                return Err(RnsError::ResourceMsg("resource metadata size exceeded"));
            }
            // 3-byte big-endian size prefix + payload
            let len = packed.len() as u32;
            metadata_blob.extend_from_slice(&len.to_be_bytes()[1..]);
            metadata_blob.extend_from_slice(packed);
            metadata_size = metadata_blob.len();
            has_metadata = true;
        }

        // Build the full stream: metadata + data
        let mut stream = Vec::with_capacity(metadata_size + data.len());
        stream.extend_from_slice(&metadata_blob);
        stream.extend_from_slice(&data);
        let total_size = stream.len();

        // Segmentation: segment k covers stream[(k-1)*MAX .. k*MAX] where the
        // first segment additionally begins with the metadata blob
        // (Python `Resource.__init__` seek arithmetic).
        let total_segments = if total_size <= MAX_EFFICIENT_SIZE {
            1
        } else {
            (total_size - 1) / MAX_EFFICIENT_SIZE + 1
        };
        let segment_index = 1;
        let start = 0;
        let end = core::cmp::min(MAX_EFFICIENT_SIZE, total_size);
        let segment_range = start..end;

        Self::new_segment(
            stream,
            segment_range,
            total_size,
            total_segments,
            segment_index,
            None,
            link,
            opts,
            has_metadata,
            metadata_size,
        )
    }

    /// Build one segment of a (possibly multi-segment) resource. `stream`
    /// is the complete original data; `range` selects this segment's bytes.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_segment(
        stream: Vec<u8>,
        range: core::ops::Range<usize>,
        total_size: usize,
        total_segments: usize,
        segment_index: usize,
        original_hash: Option<Hash>,
        link: &Link,
        opts: ResourceOptions,
        has_metadata: bool,
        metadata_size: usize,
    ) -> Result<Self, RnsError> {
        let segment_data = stream[range.clone()].to_vec();
        let split = total_segments > 1;

        // Compress (only beneficial compression is used)
        let (prepared, compressed) =
            maybe_compress(&segment_data, opts.auto_compress, super::AUTO_COMPRESS_MAX_SIZE);

        // Random hash prefix + payload
        let random_hash = Hash::new_from_rand(OsRng);
        let mut plaintext: Vec<u8> = Vec::with_capacity(RANDOM_HASH_SIZE + prepared.len());
        plaintext.extend_from_slice(&random_hash.as_slice()[..RANDOM_HASH_SIZE]);
        plaintext.extend_from_slice(&prepared);

        // Encrypt the whole stream with the link token
        let sdu = if link.mtu() > 0 {
            link.sdu()
        } else {
            SDU
        };
        let mut encrypted = Vec::with_capacity(plaintext.len() + super::PART_ENCRYPT_OVERHEAD);
        let cipher_len = link.encrypt_alloc(&plaintext, &mut encrypted)?;
        encrypted.truncate(cipher_len);

        let size = encrypted.len();
        let total_parts = size.div_ceil(sdu);

        // Build parts and hashmap with collision guard
        let mut parts = Vec::with_capacity(total_parts);
        let mut part_hashes = Vec::with_capacity(total_parts);
        let part_sent = vec![false; total_parts];
        let mut hashmap = Vec::with_capacity(total_parts * MAPHASH_LEN);
        let mut collision_guard: Vec<[u8; MAPHASH_LEN]> = Vec::new();

        let mut random_hash_bytes: [u8; RANDOM_HASH_SIZE] =
            random_hash.as_slice()[..RANDOM_HASH_SIZE].try_into().unwrap();

        'hashmap: loop {
            parts.clear();
            part_hashes.clear();
            hashmap.clear();
            collision_guard.clear();

            let mut regenerated_random = None;

            for i in 0..total_parts {
                let chunk = &encrypted[i * sdu..core::cmp::min((i + 1) * sdu, size)];
                let mh = map_hash(chunk, &random_hash_bytes);
                if collision_guard.contains(&mh) {
                    // remap with a new random hash and start over
                    let new_random = Hash::new_from_rand(OsRng);
                    regenerated_random = Some(new_random);
                    break;
                }
                collision_guard.push(mh);
                if collision_guard.len() > COLLISION_GUARD_SIZE {
                    collision_guard.remove(0);
                }

                let packet = link.raw_packet(chunk, PacketType::Data, PacketContext::Resource)?;
                parts.push(packet);
                part_hashes.push(mh);
                hashmap.extend_from_slice(&mh);
            }

            match regenerated_random {
                Some(new_random) => {
                    // re-encrypt with the new random hash prefix
                    plaintext.splice(..RANDOM_HASH_SIZE, new_random.as_slice()[..RANDOM_HASH_SIZE].iter().copied());
                    encrypted.clear();
                    let cipher_len = link.encrypt_alloc(&plaintext, &mut encrypted)?;
                    encrypted.truncate(cipher_len);
                    random_hash_bytes.copy_from_slice(
                        &new_random.as_slice()[..RANDOM_HASH_SIZE],
                    );
                    continue 'hashmap;
                }
                None => break,
            }
        }

        let random_hash = random_hash_bytes;
        // Hash is computed over the full uncompressed stream + random hash
        // (Python: `Identity.full_hash(data + self.random_hash)`).
        let hash = Hash::new(
            Hash::generator()
                .chain_update(&stream)
                .chain_update(random_hash)
                .finalize()
                .into(),
        );
        let truncated_hash = AddressHash::new_from_hash(&hash);
        let expected_proof = Hash::new(
            Hash::generator()
                .chain_update(&stream)
                .chain_update(hash.as_slice())
                .finalize()
                .into(),
        );
        let original_hash = original_hash.unwrap_or(hash);

        let rtt = link.rtt().as_secs_f64();
        let timeout = opts
            .timeout
            .unwrap_or(rtt * super::TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125);

        Ok(Self {
            link_id: *link.id(),
            status: ResourceStatus::None,
            hash,
            truncated_hash,
            expected_proof,
            original_hash,
            random_hash,
            size,
            total_size,
            compressed,
            encrypted: true,
            split,
            has_metadata,
            metadata_size,
            segment_index,
            total_segments,
            request_id: opts.request_id,
            is_response: opts.is_response,
            sdu,
            parts,
            part_hashes,
            part_sent,
            hashmap,
            sent_parts: 0,
            receiver_min_consecutive_height: 0,
            req_hashlist: Vec::new(),
            rtt: None,
            adv_sent: None,
            last_activity: unix_time(),
            last_part_sent: 0.0,
            retries_left: MAX_ADV_RETRIES,
            max_retries: MAX_RETRIES,
            timeout,
            timeout_factor: super::TRAFFIC_TIMEOUT_FACTOR,
            sender_grace_time: SENDER_GRACE_TIME,
            original_stream: Some(stream),
            next_segment: None,
            advertise_next: false,
        })
    }

    /// Byte range of segment `segment_index` (1-based) within the full
    /// original `stream` of length `total_size`.
    pub fn segment_range(
        total_size: usize,
        metadata_size: usize,
        segment_index: usize,
    ) -> core::ops::Range<usize> {
        if total_size <= MAX_EFFICIENT_SIZE {
            return 0..total_size;
        }
        let _ = metadata_size;
        let start = (segment_index - 1) * MAX_EFFICIENT_SIZE;
        let end = core::cmp::min(segment_index * MAX_EFFICIENT_SIZE, total_size);
        start..end
    }

    pub fn advertisement(&self) -> ResourceAdvertisement {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= super::advertisement::FLAG_ENCRYPTED;
        }
        if self.compressed {
            flags |= super::advertisement::FLAG_COMPRESSED;
        }
        if self.split {
            flags |= super::advertisement::FLAG_SPLIT;
        }
        if self.has_metadata {
            flags |= super::advertisement::FLAG_HAS_METADATA;
        }
        if self.request_id.is_some() {
            if self.is_response {
                flags |= super::advertisement::FLAG_IS_RESPONSE;
            } else {
                flags |= super::advertisement::FLAG_IS_REQUEST;
            }
        }

        // First HASHMAP_MAX_LEN map hashes go into the advertisement
        let entries = core::cmp::min(HASHMAP_MAX_LEN, self.part_hashes.len());
        let mut hashmap = Vec::with_capacity(entries * MAPHASH_LEN);
        for mh in &self.part_hashes[..entries] {
            hashmap.extend_from_slice(mh);
        }

        ResourceAdvertisement {
            transfer_size: self.size,
            data_size: self.total_size,
            parts: self.parts.len(),
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.original_hash,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            request_id: self.request_id,
            flags,
            hashmap,
        }
    }

    /// Send (or queue) the advertisement packet. Mirrors Python `advertise`.
    pub fn advertise(&mut self, link: &Link, tx: &mut ResourceTx) -> Result<(), RnsError> {
        let packed = self.advertisement().pack();
        let packet = link.context_packet(&packed, PacketContext::ResourceAdvertisement)?;
        self.status = ResourceStatus::Advertised;
        let now = unix_time();
        self.adv_sent = Some(now);
        self.last_activity = now;
        self.rtt = None;
        self.retries_left = MAX_ADV_RETRIES;
        tx.push(packet);
        Ok(())
    }

    /// Handle an incoming RESOURCE_REQ packet plaintext. Mirrors Python
    /// `Resource.request`.
    pub fn request(&mut self, link: &Link, request_data: &[u8], tx: &mut ResourceTx) {
        let now = unix_time();
        if let Some(adv_sent) = self.adv_sent {
            if self.rtt.is_none() {
                self.rtt = Some(now - adv_sent);
            }
        }

        if self.status != ResourceStatus::Transferring {
            self.status = ResourceStatus::Transferring;
        }

        self.retries_left = self.max_retries;

        let wants_more_hashmap = request_data.first() == Some(&super::HASHMAP_IS_EXHAUSTED);
        let pad = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };

        if request_data.len() < pad + 32 {
            log::debug!("resource: malformed part request, ignoring");
            return;
        }

        let requested_hashes = &request_data[pad + 32..];
        let mut map_hashes: Vec<[u8; MAPHASH_LEN]> = Vec::new();
        for chunk in requested_hashes.chunks_exact(MAPHASH_LEN) {
            map_hashes.push(chunk.try_into().unwrap());
        }

        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            self.receiver_min_consecutive_height + COLLISION_GUARD_SIZE,
            self.parts.len(),
        );

        for i in search_start..search_end {
            if map_hashes.contains(&self.part_hashes[i]) {
                let packet = self.parts[i];
                if !self.part_sent[i] {
                    self.part_sent[i] = true;
                    self.sent_parts += 1;
                }
                tx.push(packet);
                self.last_activity = now;
                self.last_part_sent = now;
            }
        }

        if wants_more_hashmap {
            let last_map_hash: [u8; MAPHASH_LEN] =
                request_data[1..1 + MAPHASH_LEN].try_into().unwrap();

            let mut part_index = self.receiver_min_consecutive_height;
            'search: for i in search_start..search_end {
                part_index += 1;
                if self.part_hashes[i] == last_map_hash {
                    break 'search;
                }
            }

            self.receiver_min_consecutive_height =
                part_index.saturating_sub(1 + WINDOW_MAX);

            if !part_index.is_multiple_of(HASHMAP_MAX_LEN) {
                log::error!("resource: sequencing error in hashmap update, cancelling");
                self.status = ResourceStatus::Failed;
                return;
            }
            let segment = part_index / HASHMAP_MAX_LEN;

            let hashmap_start = segment * HASHMAP_MAX_LEN;
            let hashmap_end = core::cmp::min((segment + 1) * HASHMAP_MAX_LEN, self.parts.len());

            let mut hashmap = Vec::new();
            for i in hashmap_start..hashmap_end {
                hashmap.extend_from_slice(&self.part_hashes[i]);
            }

            if hashmap.is_empty() {
                log::error!("resource: hashmap update error, cancelling");
                self.status = ResourceStatus::Failed;
                return;
            }

            let mut hmu = self.hash.as_slice().to_vec();
            let mut packed = Vec::with_capacity(8 + hashmap.len());
            rmp::encode::write_array_len(&mut packed, 2).unwrap();
            rmp::encode::write_uint(&mut packed, segment as u64).unwrap();
            rmp::encode::write_bin(&mut packed, &hashmap).unwrap();
            hmu.extend_from_slice(&packed);

            if let Ok(packet) = link.context_packet(&hmu, PacketContext::ResourceHashUpdate) {
                tx.push(packet);
                self.last_activity = now;
            }
        }

        if self.sent_parts == self.parts.len() {
            self.status = ResourceStatus::AwaitingProof;
            self.retries_left = 3;
        }
    }

    /// Validate a RESOURCE_PRF proof payload (`hash + proof_hash`).
    pub fn validate_proof(&mut self, proof_data: &[u8]) -> bool {
        if proof_data.len() == 64 {
            let proof_hash = &proof_data[32..];
            if proof_hash == self.expected_proof.as_slice() {
                self.status = ResourceStatus::Complete;
                return true;
            }
        }
        false
    }

    /// Build a cancel packet (initiator cancel).
    pub fn cancel_packet(&mut self, link: &Link, tx: &mut ResourceTx) {
        if let Ok(packet) =
            link.context_packet(self.hash.as_slice(), PacketContext::ResourceInitiatorCancel)
        {
            tx.push(packet);
        }
        self.status = ResourceStatus::Failed;
    }

    /// Watchdog state machine for the sender side. Returns packets to send
    /// and whether the resource should be removed.
    pub fn check(&mut self, link: &Link, tx: &mut ResourceTx) -> bool {
        let now = unix_time();
        match self.status {
            ResourceStatus::Advertised => {
                let adv_sent = self.adv_sent.unwrap_or(now);
                if now > adv_sent + self.timeout + super::PROCESSING_GRACE {
                    if self.retries_left == 0 {
                        log::debug!("resource: transfer timeout after advertisement");
                        self.status = ResourceStatus::Failed;
                        return true;
                    }
                    self.retries_left -= 1;
                    let _ = self.advertise(link, tx);
                }
                false
            }
            ResourceStatus::Transferring => {
                let rtt = self.rtt.unwrap_or_else(|| link.rtt().as_secs_f64());
                let max_extra_wait: f64 = (0..super::MAX_RETRIES)
                    .map(|r| (r + 1) as f64 * super::PER_RETRY_DELAY)
                    .sum();
                let max_wait = rtt * self.timeout_factor * self.max_retries as f64
                    + self.sender_grace_time
                    + max_extra_wait;
                if now > self.last_activity + max_wait {
                    log::debug!("resource: timed out waiting for part requests");
                    self.status = ResourceStatus::Failed;
                    return true;
                }
                false
            }
            ResourceStatus::AwaitingProof => {
                self.timeout_factor = super::PROOF_TIMEOUT_FACTOR;
                let rtt = self.rtt.unwrap_or_else(|| link.rtt().as_secs_f64());
                if now > self.last_part_sent + (rtt * self.timeout_factor + self.sender_grace_time)
                {
                    if self.retries_left == 0 {
                        log::debug!("resource: timed out waiting for proof");
                        self.status = ResourceStatus::Failed;
                        return true;
                    }
                    self.retries_left -= 1;
                    // Python queries the network cache here; we simply retry
                    self.last_part_sent = now;
                }
                false
            }
            _ => false,
        }
    }

    /// Transfer progress (0.0 - 1.0), including segmentation weighting.
    pub fn progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }
        if !self.split {
            return (self.sent_parts as f64 / self.parts.len() as f64).min(1.0);
        }
        let max_parts_per_segment =
            (MAX_EFFICIENT_SIZE as f64 / self.sdu as f64).ceil() as usize;
        let processed_segments = self.segment_index - 1;
        let current_segment_parts = self.parts.len();
        let factor = if current_segment_parts < max_parts_per_segment {
            max_parts_per_segment as f64 / current_segment_parts as f64
        } else {
            1.0
        };
        let processed = processed_segments as f64 * max_parts_per_segment as f64
            + self.sent_parts as f64 * factor;
        let total = self.total_segments as f64 * max_parts_per_segment as f64;
        (processed / total).min(1.0)
    }
}
