pub mod link;
pub mod link_map;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use rand_core::CryptoRngCore;
use x25519_dalek::PublicKey;

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use crate::{
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        generate_ratchet, ratchet_public_from_private, EmptyIdentity, HashIdentity, Identity,
        PrivateIdentity, RATCHET_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    },
    packet::{
        self, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
        PacketDataBuffer, PacketType, PropagationType,
    },
    time::unix_time_as_secs,
};
use sha2::Digest;

//***************************************************************************//

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

//***************************************************************************//

pub trait Type {
    fn destination_type() -> DestinationType;
}

pub struct Single;
pub struct Plain;
pub struct Group;

impl Type for Single {
    fn destination_type() -> DestinationType {
        DestinationType::Single
    }
}

impl Type for Plain {
    fn destination_type() -> DestinationType {
        DestinationType::Plain
    }
}

impl Type for Group {
    fn destination_type() -> DestinationType {
        DestinationType::Group
    }
}

pub const NAME_HASH_LENGTH: usize = 10;
pub const RAND_HASH_LENGTH: usize = 10;
pub const MIN_ANNOUNCE_DATA_LENGTH: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + SIGNATURE_LENGTH;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DestinationName {
    pub hash: Hash,
}

impl DestinationName {
    pub fn new(app_name: &str, aspects: &str) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(app_name.as_bytes())
                .chain_update(".".as_bytes())
                .chain_update(aspects.as_bytes())
                .finalize()
                .into(),
        );

        Self { hash }
    }

    pub fn new_from_hash_slice(hash_slice: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash[..hash_slice.len()].copy_from_slice(hash_slice);

        Self {
            hash: Hash::new(hash),
        }
    }

    /// The destination address hash for this name and an announcing
    /// identity (Python `Destination.hash_from_name_and_identity`).
    pub fn address_hash_for<I: crate::identity::HashIdentity>(
        &self,
        identity: &I,
    ) -> AddressHash {
        create_address_hash(identity, self)
    }

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
    }

    /// Whether this name and `other` denote the same destination name,
    /// ignoring the address hash (compares the name hash).
    pub fn desc_hash_matches(&self, other: &DestinationName) -> bool {
        self.as_name_hash_slice() == other.as_name_hash_slice()
    }
}

#[derive(Copy, Clone)]
pub struct DestinationDesc {
    pub identity: Identity,
    pub address_hash: AddressHash,
    pub name: DestinationName,
}

impl fmt::Display for DestinationDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_hash)?;

        Ok(())
    }
}

/// Parsed contents of a validated announce packet.
#[derive(Clone, Debug)]
pub struct AnnounceData<'a> {
    /// Announce app data. Mirrors the Python `Identity.validate_announce`
    /// quirk: `None` when a ratchet-less announce carries no app data, and
    /// an empty slice for ratchet announces without app data.
    pub app_data: Option<&'a [u8]>,
    /// Public ratchet key carried by the announce (`None` when the announce
    /// does not include one, Python `Identity.RATCHETSIZE // 8` bytes when
    /// it does).
    pub ratchet: Option<[u8; RATCHET_KEY_LENGTH]>,
}

pub type DestinationAnnounce = Packet;

impl DestinationAnnounce {
    /// Validate an announce packet (Python `Identity.validate_announce`).
    ///
    /// Verifies the signature over
    /// `destination_hash || public_key || name_hash || random_hash || ratchet || app_data`,
    /// and that the announced destination hash actually belongs to the
    /// announced name hash and identity.
    pub fn validate(packet: &Packet) -> Result<(SingleOutputDestination, AnnounceData<'_>), RnsError> {
        if packet.header.packet_type != PacketType::Announce {
            return Err(RnsError::PacketError);
        }

        let announce_data = packet.data.as_slice();

        let minimum = if packet.header.context_flag {
            MIN_ANNOUNCE_DATA_LENGTH + RATCHET_KEY_LENGTH
        } else {
            MIN_ANNOUNCE_DATA_LENGTH
        };

        if announce_data.len() < minimum {
            return Err(RnsError::OutOfMemory);
        }

        let mut offset = 0usize;

        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;

            VerifyingKey::from_bytes(&key_data).map_err(|_| RnsError::CryptoError)?
        };

        let identity = Identity::new(public_key, verifying_key);

        let name_hash = &announce_data[offset..(offset + NAME_HASH_LENGTH)];
        offset += NAME_HASH_LENGTH;
        let rand_hash = &announce_data[offset..(offset + RAND_HASH_LENGTH)];
        offset += RAND_HASH_LENGTH;

        // If the packet context flag is set, this announce contains a
        // ratchet key between the random hash and the signature.
        let ratchet = if packet.header.context_flag {
            let mut ratchet = [0u8; RATCHET_KEY_LENGTH];
            ratchet.copy_from_slice(&announce_data[offset..(offset + RATCHET_KEY_LENGTH)]);
            offset += RATCHET_KEY_LENGTH;
            Some(ratchet)
        } else {
            None
        };

        let signature = &announce_data[offset..(offset + SIGNATURE_LENGTH)];
        offset += SIGNATURE_LENGTH;

        // Python `Identity.validate_announce`: app data is present when the
        // announce is longer than `keysize+name_hash_len+10+sig_len`.
        let app_data = if announce_data.len() > MIN_ANNOUNCE_DATA_LENGTH {
            Some(&announce_data[offset..])
        } else {
            None
        };

        let destination = &packet.destination;

        // Keeping signed data on stack is only option for now.
        // Verification function doesn't support prehashed message.
        let mut signed_data = PacketDataBuffer::new();
        signed_data
            .chain_write(destination.as_slice())?
            .chain_write(public_key.as_bytes())?
            .chain_write(verifying_key.as_bytes())?
            .chain_write(name_hash)?
            .chain_write(rand_hash)?;

        if let Some(ratchet) = &ratchet {
            signed_data.chain_write(ratchet)?;
        }

        let signed_data = match app_data {
            Some(app_data) => signed_data.chain_write(app_data)?.finalize(),
            None => signed_data.finalize(),
        };

        let signature = Signature::from_slice(signature).map_err(|_| RnsError::CryptoError)?;

        identity.verify(signed_data.as_slice(), &signature)?;

        // The announced destination hash must belong to the announced name
        // hash and identity (Python rejects hash collisions here).
        let hash_material = PacketDataBuffer::new()
            .chain_write(name_hash)?
            .chain_write(identity.address_hash.as_slice())?
            .finalize();

        let expected_hash = Hash::new_from_slice(hash_material.as_slice());

        if AddressHash::new_from_hash(&expected_hash) != *destination {
            return Err(RnsError::IncorrectHash);
        }

        Ok((
            SingleOutputDestination::new(identity, DestinationName::new_from_hash_slice(name_hash)),
            AnnounceData { app_data, ratchet },
        ))
    }
}

pub struct Destination<I: HashIdentity, D: Direction, T: Type> {
    pub direction: PhantomData<D>,
    pub r#type: PhantomData<T>,
    pub identity: I,
    /// Packet proof strategy for link data addressed to this destination
    /// (only meaningful for SINGLE IN destinations).
    pub proof_strategy: ProofStrategy,
    /// Whether this destination accepts incoming link requests
    /// (Python `Destination.accepts_links`).
    pub accepts_links: bool,
    /// Retained *private* ratchet keys, newest first. `None` while ratchets
    /// are disabled (Python `Destination.ratchets`).
    pub ratchets: Option<Vec<[u8; RATCHET_KEY_LENGTH]>>,
    /// Unix timestamp of the last ratchet rotation
    /// (Python `Destination.latest_ratchet_time`).
    pub latest_ratchet_time: u64,
    /// Minimum interval between ratchet rotations in seconds
    /// (Python `Destination.ratchet_interval`).
    pub ratchet_interval: u64,
    /// Number of ratchet keys to retain
    /// (Python `Destination.retained_ratchets`).
    pub retained_ratchets: usize,
    pub desc: DestinationDesc,
}

impl<I: HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::destination_type()
    }
}

/// Encrypt `text` for a SINGLE destination (Python `Destination.encrypt`).
///
/// When the destination's identity has a known ratchet for this destination
/// (supplied by the caller, Python `RNS.Identity.get_ratchet(self.hash)`),
/// the ephemeral key exchange is performed against the ratchet key.
pub fn encrypt_single<'a, R: CryptoRngCore + Copy>(
    identity: &Identity,
    text: &[u8],
    ratchet: Option<&PublicKey>,
    rng: R,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], RnsError> {
    identity.encrypt(rng, text, ratchet, out_buf)
}

pub enum DestinationHandleStatus {
    None,
    LinkProof,
}

/// Proof strategies for link data packets
/// (Python `Destination.PROVE_NONE/PROVE_APP/PROVE_ALL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofStrategy {
    /// Never prove packets.
    #[default]
    None,
    /// Prove packets that carry application data (proof requested via
    /// callback in Python; approximated here by proving non-empty data).
    App,
    /// Prove all packets.
    All,
}

/// Number of ratchet keys a destination retains by default
/// (Python `Destination.RATCHET_COUNT`).
pub const RATCHET_COUNT: usize = 512;

/// Minimum interval between ratchet rotations in seconds
/// (Python `Destination.RATCHET_INTERVAL`).
pub const RATCHET_INTERVAL_SECS: u64 = 30 * 60;

impl Destination<PrivateIdentity, Input, Single> {
    /// Set the packet proof strategy
    /// (Python `Destination.set_proof_strategy`).
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    pub fn proof_strategy(&self) -> ProofStrategy {
        self.proof_strategy
    }

    /// Enable ratchets on this destination (Python `Destination.enable_ratchets`).
    ///
    /// `ratchets` are the retained *private* ratchet keys (newest first,
    /// typically loaded from the destination's ratchet file by the
    /// `reticulum` storage module). Passing an empty list starts a fresh
    /// ratchet chain, exactly like a missing ratchet file in Python.
    pub fn enable_ratchets(&mut self, ratchets: Vec<[u8; RATCHET_KEY_LENGTH]>) {
        self.ratchets = Some(ratchets);
        self.latest_ratchet_time = 0;
    }

    /// Disable ratchets on this destination again.
    pub fn disable_ratchets(&mut self) {
        self.ratchets = None;
    }

    pub fn ratchets_enabled(&self) -> bool {
        self.ratchets.is_some()
    }

    /// The retained private ratchet keys, newest first.
    pub fn ratchets(&self) -> Option<&[[u8; RATCHET_KEY_LENGTH]]> {
        self.ratchets.as_deref()
    }

    /// Private ratchet keys as a mutable slice (storage (re)load).
    pub fn ratchets_mut(&mut self) -> Option<&mut Vec<[u8; RATCHET_KEY_LENGTH]>> {
        self.ratchets.as_mut()
    }

    /// Set the minimum interval in seconds between ratchet key rotations
    /// (Python `Destination.set_ratchet_interval`).
    pub fn set_ratchet_interval(&mut self, interval: u64) {
        if interval > 0 {
            self.ratchet_interval = interval;
        }
    }

    /// Set the number of retained ratchet keys
    /// (Python `Destination.set_retained_ratchets`).
    pub fn set_retained_ratchets(&mut self, count: usize) {
        if count > 0 {
            self.retained_ratchets = count;
            self.clean_ratchets();
        }
    }

    /// Drop all but the newest `retained_ratchets` keys
    /// (Python `Destination._clean_ratchets`).
    pub fn clean_ratchets(&mut self) {
        if let Some(ratchets) = &mut self.ratchets
            && ratchets.len() > self.retained_ratchets
        {
            ratchets.truncate(RATCHET_COUNT.min(self.retained_ratchets));
        }
    }

    /// Generate a fresh ratchet key at the front of the list if the
    /// rotation interval has elapsed (Python `Destination.rotate_ratchets`).
    /// Returns the new ratchet key when one was generated.
    pub fn rotate_ratchets<R: CryptoRngCore + Copy>(&mut self, rng: R, now_secs: u64) -> Option<[u8; RATCHET_KEY_LENGTH]> {
        let ratchets = self.ratchets.as_mut()?;
        if now_secs > self.latest_ratchet_time + self.ratchet_interval {
            let new_ratchet = generate_ratchet(rng);
            ratchets.insert(0, new_ratchet);
            self.latest_ratchet_time = now_secs;
            self.clean_ratchets();
            Some(new_ratchet)
        } else {
            None
        }
    }

    /// Decrypt a SINGLE-destination data packet (Python `Destination.decrypt`):
    /// try the retained ratchet keys first, then the static identity key.
    pub fn decrypt<'a>(
        &self,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let ratchets = self.ratchets.as_deref().unwrap_or(&[]);
        self.identity.decrypt(data, ratchets, out_buf)
    }

    /// Control whether this destination accepts incoming link requests
    /// (Python `Destination.set_accepts_links` / `accepts_links`).
    pub fn set_accepts_links(&mut self, accepts: bool) {
        self.accepts_links = accepts;
    }

    pub fn accepts_links(&self) -> bool {
        self.accepts_links
    }

    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        let pub_identity = *identity.as_identity();

        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            desc: DestinationDesc {
                identity: pub_identity,
                name,
                address_hash,
            },
        }
    }

    /// Build an announce packet (Python `Destination.announce`).
    ///
    /// When ratchets are enabled the newest ratchet public key is included
    /// between the random hash and the signature, and the packet context
    /// flag is set to signal its presence.
    pub fn announce<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        self.announce_at(rng, app_data, unix_time_as_secs())
    }

    /// Deterministic-time variant of [`Destination::announce`].
    pub fn announce_at<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
        now_secs: u64,
    ) -> Result<Packet, RnsError> {
        // Python `Destination.announce`: rotate ratchets (respecting the
        // rotation interval) and announce the newest public key.
        let ratchet = self
            .rotate_ratchets_if_due(rng, now_secs)
            .map(|(public, _private)| public);

        let mut packet_data = PacketDataBuffer::new();

        let rand_hash = Hash::new_from_rand(rng);
        let timestamp = now_secs.to_be_bytes();
        let rand_hash = [&rand_hash.as_slice()[..RAND_HASH_LENGTH / 2], &timestamp[3..]].concat();

        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash);

        if let Some(ratchet) = &ratchet {
            packet_data.chain_safe_write(ratchet);
        }

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let signature = self.identity.sign(packet_data.as_slice());

        packet_data.reset();

        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash);

        if let Some(ratchet) = &ratchet {
            packet_data.chain_safe_write(ratchet);
        }

        packet_data.chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        // Python `Destination.announce`: `context_flag = FLAG_SET` when the
        // announce carries a ratchet.
        let header = Header {
            ifac_flag: IfacFlag::Open,
            context_flag: ratchet.is_some(),
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops: 0,
        };

        Ok(Packet {
            header,
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    /// Rotate ratchets when the rotation interval has elapsed, returning the
    /// public (and private) key of the ratchet that an announce should
    /// carry. Mirrors Python `Destination.announce` calling
    /// `rotate_ratchets` then using `self.ratchets[0]`.
    fn rotate_ratchets_if_due<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        now_secs: u64,
    ) -> Option<([u8; RATCHET_KEY_LENGTH], [u8; RATCHET_KEY_LENGTH])> {
        let ratchets = self.ratchets.as_ref()?;

        let rotate = ratchets.is_empty()
            || now_secs > self.latest_ratchet_time + self.ratchet_interval;

        if rotate {
            let new_ratchet = generate_ratchet(rng);
            if let Some(ratchets) = self.ratchets.as_mut() {
                ratchets.insert(0, new_ratchet);
            }
            self.latest_ratchet_time = now_secs;
            self.clean_ratchets();
        }

        let private = *self.ratchets.as_ref()?.first()?;
        let public = ratchet_public_from_private(&private);
        Some((public, private))
    }

    pub fn path_response<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut announce = self.announce(rng, app_data)?;
        announce.context = PacketContext::PathResponse;

        Ok(announce)
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> DestinationHandleStatus {
        if self.desc.address_hash != packet.destination {
            return DestinationHandleStatus::None;
        }

        if packet.header.packet_type == PacketType::LinkRequest {
            // TODO: check prove strategy
            return DestinationHandleStatus::LinkProof;
        }

        DestinationHandleStatus::None
    }

    pub fn sign_key(&self) -> &SigningKey {
        self.identity.sign_key()
    }
}

impl Destination<Identity, Output, Single> {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            desc: DestinationDesc {
                identity,
                name,
                address_hash,
            },
        }
    }
}

impl<D: Direction> Destination<EmptyIdentity, D, Plain> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
        }
    }
}

/// GROUP destinations are parsed and addressed exactly like PLAIN ones:
/// name-hash addressing without an identity. The Python reference ships
/// GROUP symmetric crypto as a placeholder (`Destination.prv` /
/// `load_private_key`), so no crypto is invented here — packets to GROUP
/// destinations are sent unencrypted, mirroring the current Python state
/// for destinations that never load a symmetric key.
impl<D: Direction> Destination<EmptyIdentity, D, Group> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
        }
    }
}

fn create_address_hash<I: HashIdentity>(identity: &I, name: &DestinationName) -> AddressHash {
    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity.as_address_hash_slice())
            .finalize()
            .into(),
    ))
}

pub type SingleInputDestination = Destination<PrivateIdentity, Input, Single>;
pub type SingleOutputDestination = Destination<Identity, Output, Single>;
pub type PlainInputDestination = Destination<EmptyIdentity, Input, Plain>;
pub type PlainOutputDestination = Destination<EmptyIdentity, Output, Plain>;
pub type GroupInputDestination = Destination<EmptyIdentity, Input, Group>;
pub type GroupOutputDestination = Destination<EmptyIdentity, Output, Group>;

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand_core::OsRng;

    use crate::buffer::OutputBuffer;
    use crate::hash::Hash;
    use crate::identity::PrivateIdentity;
    use crate::serde::Serialize;

    use std::println;

    use super::DestinationAnnounce;
    use super::DestinationName;
    use super::{ProofStrategy, SingleInputDestination};

    #[test]
    fn proof_strategy_defaults_to_none_and_can_be_overridden() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination = SingleInputDestination::new(
            identity,
            DestinationName::new("test", "proof.default"),
        );

        assert_eq!(destination.proof_strategy(), ProofStrategy::None);
        destination.set_proof_strategy(ProofStrategy::All);
        assert_eq!(destination.proof_strategy(), ProofStrategy::All);
    }

    #[test]
    fn create_announce() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        let mut single_in_destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "in"));

        let announce_packet = single_in_destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        println!("Announce packet {}", announce_packet);
    }

    #[test]
    fn create_path_request_hash() {
        let name = DestinationName::new("rnstransport", "path.request");

        println!("PathRequest Name Hash {}", name.hash);
        println!(
            "PathRequest Destination Hash {}",
            Hash::new_from_slice(name.as_name_hash_slice())
        );
    }

    #[test]
    fn compare_announce() {
        let priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let sign_priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let priv_identity = PrivateIdentity::new(priv_key.into(), sign_priv_key.into());

        println!("identity hash {}", priv_identity.as_identity().address_hash);

        let mut destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        println!("destination name hash {}", destination.desc.name.hash);
        println!("destination hash {}", destination.desc.address_hash);

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let _ = announce.serialize(&mut buffer).expect("correct data");

        println!("ANNOUNCE {}", buffer);
    }

    #[test]
    fn check_announce() {
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);

        let mut destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        DestinationAnnounce::validate(&announce).expect("valid announce");
    }
}
