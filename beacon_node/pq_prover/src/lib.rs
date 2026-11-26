//! Aggregation of XMSS signatures into one proof, behind a backend trait.
//!
//! The PQ consensus-specs feature (`specs/_features/pq`) replaces BLS aggregation with a proof
//! that many XMSS signatures exist: `stark.ProveAggregates`, `stark.MergeProofs` and
//! `stark.VerifyAggregates`. [`ProverBackend`] is those three functions. Two backends exist:
//!
//! - [`ReferenceBackend`]: the spec's stand-in, where a proof is the signatures themselves.
//!   Usable in debug builds and CI.
//! - [`InProcessBackend`] (`leanvm` feature): proofs from leanVM's prover, in this process.
//!
//! # The leanVM revision
//!
//! Everything from leanVM is pinned to ONE commit, [`LEANVM_REV`]: the `lean_xmss` scheme
//! behind the `xmss` crate, the claims encoding and the prover. A proof only verifies with a
//! verifier built from a compatible revision, and nothing on the wire detects a mismatch, so
//! all nodes of a network must agree on the commit.
//!
//! # CPU tiers
//!
//! leanVM's prover picks its fastest kernels for the CPU at run time, but only from tiers built
//! with leanVM's `scripts/tier-rustc` as `RUSTC_WRAPPER`. Without it, a build only has the base
//! tier and proving is slower than the CPU allows; leanVM then warns on stderr on the first
//! proof. See `scripts/leanvm-tier-rustc`.
//!
//! # Blocking
//!
//! Every method blocks the calling thread: a proof takes seconds, a verification
//! milliseconds. Never call them from an async task; use `spawn_blocking` or a beacon
//! processor worker.
//!
//! # Leaf indices
//!
//! A leanVM claim is `(pubkey, message)`. The leaf a signature was made at is not part of what
//! a proof attests (leanEthereum/leanVM#787), so [`InProcessBackend::verify`] cannot enforce
//! [`Statement::leaf_index`]: it shows each key signed the message at *some* leaf.
//! [`InProcessBackend::prove`] does refuse signatures made at another leaf, since it sees them.
//! [`ReferenceBackend`] checks the leaf on every verification, as the spec does.

mod claims;
#[cfg(feature = "leanvm")]
mod in_process;
mod reference;

pub use claims::{statements_to_claims, statements_to_claims_bytes};
#[cfg(feature = "leanvm")]
pub use in_process::{InProcessBackend, InProcessConfig, MAX_CHILDREN_PER_AGGREGATE, merge_plan};
pub use leanvm_claims::AggregateClaims;
pub use reference::ReferenceBackend;
pub use xmss::{XMSS_MESSAGE_BYTES_LEN, XMSS_SIGNATURE_BYTES_LEN, XmssPublicKey, XmssSignature};

/// The leanVM commit every leanVM dependency of the workspace is pinned to.
pub const LEANVM_REV: &str = env!("LIGHTHOUSE_LEANVM_REVISION");

/// The spec's `XMSSAggregateStatement`: every one of `pubkeys` signed `message` at
/// `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub pubkeys: Vec<XmssPublicKey>,
    pub leaf_index: u64,
    pub message: [u8; XMSS_MESSAGE_BYTES_LEN],
}

/// An aggregation proof (the content of the spec's `AttestationProof`). Opaque: its bytes
/// only mean something to the backend that made it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

impl Proof {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proof({} bytes)", self.0.len())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The caller's statements and signatures do not line up.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A signature handed to `prove` was made at another leaf than its statement's.
    #[error(
        "signature {signature} of statement {statement} is at leaf {found}, expected {expected}"
    )]
    LeafIndexMismatch {
        statement: usize,
        signature: usize,
        expected: u64,
        found: u64,
    },
    /// A signature handed to `prove` does not verify (reference backend).
    #[error("signature {signature} of statement {statement} is invalid")]
    InvalidSignature { statement: usize, signature: usize },
    /// leanVM's prover cannot be used, e.g. it already runs with another thread count.
    #[error("prover unavailable: {0}")]
    ProverUnavailable(String),
    /// A rate out of range, too many children, nothing to prove.
    #[error("prover rejected the request as invalid input: {0}")]
    ProverInvalidInput(String),
    /// A signature does not verify.
    #[error("prover found an invalid signature")]
    ProverInvalidSignature,
    /// A child proof is invalid.
    #[error("prover found an invalid child proof")]
    ProverInvalidChild,
    /// Proving failed, e.g. the request is too large for one proof.
    #[error("prover failed to prove")]
    ProverFailed,
    /// The prover proved something other than what was asked.
    #[error("prover returned a proof of {found} claims, expected {expected} other claims")]
    ProverClaimsMismatch { expected: usize, found: usize },
}

/// Proves, merges and verifies aggregates of XMSS signatures (the spec's `stark` module).
///
/// All methods are synchronous and may take seconds: call them from `spawn_blocking` or a
/// beacon processor worker, never directly from an async task.
pub trait ProverBackend: Send + Sync {
    /// A short name for logs and metrics.
    fn name(&self) -> &'static str;

    /// The spec's `ProveAggregates`: a proof that, for each statement and each of its public
    /// keys, a signature of the statement's message at the statement's leaf exists.
    ///
    /// `signatures` holds one group per statement, in order, and within a group one
    /// signature per public key, in the order of `Statement::pubkeys`.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Proof, Error>;

    /// The spec's `MergeProofs`: one proof of the concatenation, in order, of the children's
    /// statement lists. Each child is the statements it proves and its proof.
    ///
    /// Children are assumed valid: verify untrusted ones first.
    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error>;

    /// Merge one scheduled batch into the exact claims in the final packed statements.
    fn merge_for_statements(
        &self,
        children: &[(Vec<Statement>, Proof)],
        output: &[Statement],
        max_proof_bytes: usize,
    ) -> Result<Proof, Error> {
        check_packed_claims(children, output)?;
        let proof = self.merge(children)?;
        if proof.len() > max_proof_bytes {
            return Err(Error::InvalidInput(
                "packed proof exceeds its byte bound".into(),
            ));
        }
        Ok(proof)
    }

    /// The spec's `VerifyAggregates`. `Ok(false)` is an invalid proof; `Err` means the
    /// backend could not decide.
    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error>;
}

fn statement_witnesses(
    statements: &[Statement],
) -> impl Iterator<Item = (XmssPublicKey, [u8; 32], u64)> + '_ {
    statements.iter().flat_map(|statement| {
        statement
            .pubkeys
            .iter()
            .map(|key| (*key, statement.message, statement.leaf_index))
    })
}

fn check_packed_claims(
    children: &[(Vec<Statement>, Proof)],
    output: &[Statement],
) -> Result<(), Error> {
    use std::collections::BTreeSet;
    if children.is_empty()
        || children.len() > 16
        || children.iter().any(|(statements, proof)| {
            proof.is_empty() || statement_witnesses(statements).next().is_none()
        })
    {
        return Err(Error::InvalidInput("invalid packed proof batch".into()));
    }
    let provided: BTreeSet<_> = children
        .iter()
        .flat_map(|(statements, _)| statement_witnesses(statements))
        .collect();
    if provided != statement_witnesses(output).collect() {
        return Err(Error::InvalidInput(
            "packed statements differ from the child claims".into(),
        ));
    }
    Ok(())
}

/// Checks that `signatures` has one group per statement and one signature per public key,
/// each made at its statement's leaf.
fn check_shape(statements: &[Statement], signatures: &[Vec<XmssSignature>]) -> Result<(), Error> {
    if statements.len() != signatures.len() {
        return Err(Error::InvalidInput(format!(
            "{} statements but {} signature groups",
            statements.len(),
            signatures.len()
        )));
    }
    for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
        if statement.pubkeys.len() != group.len() {
            return Err(Error::InvalidInput(format!(
                "statement {statement_index} has {} public keys but {} signatures",
                statement.pubkeys.len(),
                group.len()
            )));
        }
        for (signature_index, signature) in group.iter().enumerate() {
            let found = u64::from(signature.leaf_index());
            if found != statement.leaf_index {
                return Err(Error::LeafIndexMismatch {
                    statement: statement_index,
                    signature: signature_index,
                    expected: statement.leaf_index,
                    found,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_are_object_safe() {
        let backend: Box<dyn ProverBackend> = Box::new(ReferenceBackend);
        assert_eq!(backend.name(), "reference");
    }
}
