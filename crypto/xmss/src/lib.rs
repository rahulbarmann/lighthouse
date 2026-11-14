//! Provides leanXMSS signatures and their aggregation into STARK proofs, as specified by the
//! [`pq` feature](https://github.com/ethereum/consensus-specs/tree/pq/specs/_features/pq) of the
//! consensus specs.
//!
//! This crate should not perform direct cryptographic operations, instead it does these via
//! [leanVM](https://github.com/leanEthereum/leanVM).

mod stark;

pub use stark::{
    AggregateStatement, AttestationProof, LOG_INV_RATE, merge_proofs, prove_aggregates,
    verify_aggregates,
};

use leanvm::lean_xmss::{self, LeafIndex, LeanXmssPublicKey, LeanXmssSecretKey, LeanXmssSignature};

pub type Hash256 = fixed_bytes::Hash256;

/// The byte-length of a leanXMSS public key.
pub const PUBLIC_KEY_BYTES_LEN: usize = lean_xmss::PUB_KEY_SIZE;
/// The byte-length of a leanXMSS signature.
pub const SIGNATURE_BYTES_LEN: usize = lean_xmss::SIG_SIZE;
/// The byte-length of a leanXMSS secret key, which is its seed.
pub const SECRET_KEY_BYTES_LEN: usize = lean_xmss::SEED_LEN;

#[derive(Debug)]
pub enum Error {
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The leaf index is larger than the lifetime of a key.
    LeafIndexOutOfRange(u64),
    /// A signature was made at a different leaf index than its statement.
    LeafIndexMismatch { expected: u64, got: u64 },
    /// A statement has a different number of signatures than public keys.
    SignatureCountMismatch {
        statement: usize,
        expected: usize,
        got: usize,
    },
    /// There is a different number of signature lists than statements.
    StatementCountMismatch { expected: usize, got: usize },
    /// An error was raised from leanVM whilst signing.
    SignError(lean_xmss::LeanXmssSignError),
    /// An error was raised from leanVM whilst proving.
    AggregationError(leanvm::AggregationError),
    /// A proof could not be decoded.
    InvalidProof(leanvm::AggregateVerifyError),
}

/// Starts the leanVM thread pool and compiles its programs, which the first proof would otherwise
/// pay for.
pub fn setup() {
    leanvm::setup();
}

fn to_leaf_index(leaf_index: u64) -> Result<LeafIndex, Error> {
    LeafIndex::try_from(leaf_index).map_err(|_| Error::LeafIndexOutOfRange(leaf_index))
}

/// A leanXMSS public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(LeanXmssPublicKey);

impl PublicKey {
    /// Serialize `self` as bytes.
    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }

    /// Deserialize `self` from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.try_into().map_err(|_| Error::InvalidByteLength {
            got: bytes.len(),
            expected: PUBLIC_KEY_BYTES_LEN,
        })?;
        Ok(Self(LeanXmssPublicKey::from_bytes(bytes)))
    }
}

/// A leanXMSS signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature(LeanXmssSignature);

impl Signature {
    /// Serialize `self` as bytes.
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0.to_bytes()
    }

    /// Deserialize `self` from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.try_into().map_err(|_| Error::InvalidByteLength {
            got: bytes.len(),
            expected: SIGNATURE_BYTES_LEN,
        })?;
        Ok(Self(LeanXmssSignature::from_bytes(bytes)))
    }

    /// Returns the leaf index that `self` was made at.
    pub fn leaf_index(&self) -> u64 {
        u64::from(self.0.leaf_index())
    }

    /// Returns `true` if `self` is a signature across `msg` by `pubkey` at `leaf_index`.
    pub fn verify(&self, pubkey: &PublicKey, leaf_index: u64, msg: Hash256) -> bool {
        self.leaf_index() == leaf_index && lean_xmss::verify(&pubkey.0, &msg.0, &self.0).is_ok()
    }
}

/// A leanXMSS secret key.
///
/// ## Notes
///
/// XMSS is stateful: signing two different messages at the same leaf index breaks the key. It is
/// up to the caller to never reuse a leaf index.
pub struct SecretKey(LeanXmssSecretKey);

impl SecretKey {
    /// Instantiate `Self` from some secure source of entropy.
    pub fn random() -> Self {
        Self(lean_xmss::key_gen().0)
    }

    /// Instantiate `Self` from `seed`, which is all of its secret material.
    pub fn from_seed(seed: [u8; SECRET_KEY_BYTES_LEN]) -> Self {
        Self(lean_xmss::key_gen_from_seed(seed).0)
    }

    /// Returns the public key that corresponds to self.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Builds the bottom tree that `leaf_index` is in, so the first `sign` in it is fast.
    pub fn prepare(&self, leaf_index: u64) -> Result<(), Error> {
        self.0
            .prepare(to_leaf_index(leaf_index)?)
            .map_err(Error::SignError)
    }

    /// Signs `msg` at `leaf_index`.
    pub fn sign(&self, leaf_index: u64, msg: Hash256) -> Result<Signature, Error> {
        lean_xmss::sign(&self.0, &msg.0, to_leaf_index(leaf_index)?)
            .map(Signature)
            .map_err(Error::SignError)
    }

    /// Serialize `self` as bytes.
    ///
    /// ## Note
    ///
    /// The bytes that are returned are the unencrypted secret key. This is sensitive cryptographic
    /// material.
    pub fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }

    /// Deserialize `self` from bytes, which regenerates the key as `from_seed` does.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let seed = bytes.try_into().map_err(|_| Error::InvalidByteLength {
            got: bytes.len(),
            expected: SECRET_KEY_BYTES_LEN,
        })?;
        Ok(Self::from_seed(seed))
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    pub(crate) fn test_keys() -> &'static [SecretKey] {
        static KEYS: OnceLock<Vec<SecretKey>> = OnceLock::new();
        KEYS.get_or_init(|| (1..=3).map(|i| SecretKey::from_seed([i; 32])).collect())
    }

    fn msg(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    #[test]
    fn sign_and_verify() {
        let key = &test_keys()[0];
        let signature = key.sign(7, msg(1)).unwrap();
        assert_eq!(signature.leaf_index(), 7);
        assert!(signature.verify(&key.public_key(), 7, msg(1)));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key = &test_keys()[0];
        let signature = key.sign(8, msg(1)).unwrap();
        assert!(!signature.verify(&key.public_key(), 8, msg(2)));
    }

    #[test]
    fn verify_rejects_wrong_leaf_index() {
        let key = &test_keys()[0];
        let signature = key.sign(9, msg(1)).unwrap();
        assert!(!signature.verify(&key.public_key(), 10, msg(1)));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let keys = test_keys();
        let signature = keys[0].sign(11, msg(1)).unwrap();
        assert!(!signature.verify(&keys[1].public_key(), 11, msg(1)));
    }

    #[test]
    fn sign_rejects_leaf_index_out_of_range() {
        let leaf_index = u64::from(LeafIndex::MAX) + 1;
        assert!(matches!(
            test_keys()[0].sign(leaf_index, msg(1)),
            Err(Error::LeafIndexOutOfRange(index)) if index == leaf_index
        ));
    }

    #[test]
    fn serialization_round_trips() {
        let key = &test_keys()[0];
        let pubkey = key.public_key();
        assert_eq!(PublicKey::deserialize(&pubkey.serialize()).unwrap(), pubkey);

        let signature = key.sign(12, msg(1)).unwrap();
        let bytes = signature.serialize();
        assert_eq!(Signature::deserialize(&bytes).unwrap(), signature);
        // The leaf index comes first.
        assert_eq!(bytes[..4], 12u32.to_le_bytes());

        let restored = SecretKey::deserialize(&key.serialize()).unwrap();
        assert_eq!(restored.public_key(), pubkey);
    }

    #[test]
    fn deserialize_rejects_wrong_length() {
        assert!(matches!(
            PublicKey::deserialize(&[0; PUBLIC_KEY_BYTES_LEN - 1]),
            Err(Error::InvalidByteLength { .. })
        ));
        assert!(matches!(
            Signature::deserialize(&[0; SIGNATURE_BYTES_LEN + 1]),
            Err(Error::InvalidByteLength { .. })
        ));
        assert!(matches!(
            SecretKey::deserialize(&[]),
            Err(Error::InvalidByteLength { .. })
        ));
    }
}
