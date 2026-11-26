//! Proofs from leanVM's prover, run in this process (`lean_vm::aggregate`).
use crate::claims::statements_to_claims;
use crate::{Error, Proof, ProverBackend, Statement, check_shape};
use lean_vm::{AggregateClaims, AggregateError, AggregateProof, OutputClaims};
use lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use std::sync::OnceLock;
use xmss::XmssSignature;

/// The most children one aggregate takes.
pub const MAX_CHILDREN_PER_AGGREGATE: usize = lean_vm::MAX_RECURSIONS;

/// The thread count leanVM's prover pool was started with. leanVM panics if `setup` is called
/// again with another count.
static PROVER_THREADS: OnceLock<usize> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InProcessConfig {
    /// `log_inv_rate` of the proofs made, 1 to 4: a higher rate gives smaller proofs that take
    /// longer to make. A proof verifies whatever rate it was made at.
    pub log_inv_rate: u8,
    /// Threads in leanVM's prover pool, 0 for one per core. The pool is shared by the whole
    /// process and started once.
    pub threads: usize,
}

impl InProcessConfig {
    pub const DEFAULT_LOG_INV_RATE: u8 = 2;
}

impl Default for InProcessConfig {
    fn default() -> Self {
        Self {
            log_inv_rate: Self::DEFAULT_LOG_INV_RATE,
            threads: 0,
        }
    }
}

/// Proves and verifies with leanVM in this process.
///
/// Proof bytes are leanVM's proof alone. The claims it proves are not stored with it: the
/// verifier rebuilds them from the statements ([`statements_to_claims`]). The empty proof
/// stands for "nothing to prove" (leanVM refuses to prove zero claims) and verifies only
/// against statements with no public keys.
///
/// leanVM proves one aggregate at a time, so concurrent `prove` and `merge` calls wait for
/// each other. `verify` does not wait for them.
///
/// Leaf indices: `verify` cannot check [`Statement::leaf_index`] (see the crate docs).
#[derive(Debug)]
pub struct InProcessBackend {
    config: InProcessConfig,
}

impl InProcessBackend {
    /// Starts leanVM's prover pool and builds its aggregation program, which takes a few
    /// seconds the first time.
    pub fn new(config: InProcessConfig) -> Result<Self, Error> {
        let threads = *PROVER_THREADS.get_or_init(|| {
            lean_vm::setup(config.threads);
            config.threads
        });
        if threads != config.threads {
            return Err(Error::ProverUnavailable(format!(
                "leanVM already runs with {threads} threads, not {}",
                config.threads
            )));
        }
        Ok(Self { config })
    }

    pub fn config(&self) -> &InProcessConfig {
        &self.config
    }

    /// One aggregate. Checks leanVM proved exactly `expected`.
    fn aggregate(
        &self,
        children: &[(AggregateClaims, AggregateProof)],
        raw_signatures: Vec<(LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature)>,
        expected: &AggregateClaims,
    ) -> Result<AggregateProof, Error> {
        let (claims, proof) = lean_vm::aggregate(
            children,
            raw_signatures,
            Vec::new(),
            None,
            OutputClaims::All,
            usize::from(self.config.log_inv_rate),
        )?;
        if claims != *expected {
            return Err(Error::ProverClaimsMismatch {
                expected: expected.num_signature_claims(),
                found: claims.num_signature_claims(),
            });
        }
        Ok(proof)
    }
}

impl ProverBackend for InProcessBackend {
    fn name(&self) -> &'static str {
        "in-process"
    }

    /// One aggregate with every signature. Signatures made at another leaf than their
    /// statement's are refused here, since a proof would hide them.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Proof, Error> {
        check_shape(statements, signatures)?;
        let expected = statements_to_claims(statements);
        if expected.lean_xmss.is_empty() {
            return Ok(Proof::default());
        }
        let raw_signatures = statements
            .iter()
            .zip(signatures)
            .flat_map(|(statement, group)| {
                statement
                    .pubkeys
                    .iter()
                    .zip(group)
                    .map(|(pubkey, signature)| {
                        (
                            LeanXmssPublicKey::from_bytes(pubkey.as_bytes()),
                            statement.message,
                            LeanXmssSignature::from_bytes(signature.as_bytes()),
                        )
                    })
            })
            .collect();
        self.aggregate(&[], raw_signatures, &expected)
            .map(|proof| Proof::from_bytes(proof.to_bytes()))
    }

    /// Folds the children [`MAX_CHILDREN_PER_AGGREGATE`] at a time, round after round, until
    /// one proof remains ([`merge_plan`] gives the cost). Children that prove nothing are
    /// skipped, and a single child is returned as it is, without proving.
    ///
    /// leanVM does not verify children: an invalid one fails the merge
    /// ([`Error::ProverInvalidChild`] or [`Error::ProverFailed`]).
    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error> {
        let mut level: Vec<(AggregateClaims, AggregateProof)> = Vec::with_capacity(children.len());
        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = statements_to_claims(statements);
            match (claims.lean_xmss.is_empty(), proof.is_empty()) {
                (true, true) => {}
                (false, false) => {
                    let proof = AggregateProof::from_bytes(proof.as_bytes()).ok_or_else(|| {
                        Error::InvalidInput(format!("child {index} proof does not decode"))
                    })?;
                    level.push((claims, proof));
                }
                (true, false) => {
                    return Err(Error::InvalidInput(format!(
                        "child {index} has a proof but no claims"
                    )));
                }
                (false, true) => {
                    return Err(Error::InvalidInput(format!(
                        "child {index} has claims but an empty proof"
                    )));
                }
            }
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_CHILDREN_PER_AGGREGATE));
            for chunk in level.chunks(MAX_CHILDREN_PER_AGGREGATE) {
                if let [only] = chunk {
                    next.push(only.clone());
                    continue;
                }
                let expected = union(chunk);
                let proof = self.aggregate(chunk, Vec::new(), &expected)?;
                next.push((expected, proof));
            }
            level = next;
        }
        Ok(level
            .pop()
            .map(|(_, proof)| Proof::from_bytes(proof.to_bytes()))
            .unwrap_or_default())
    }

    /// Does not check the statements' leaf indices.
    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error> {
        let claims = statements_to_claims(statements);
        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }
        Ok(AggregateProof::from_bytes(proof.as_bytes()).is_some_and(|proof| proof.verify(&claims)))
    }
}

/// What merging `children` non-empty proofs costs: `(rounds, proofs made)`. Proofs within a
/// round are made one after another, since leanVM proves one aggregate at a time.
pub fn merge_plan(children: usize) -> (usize, usize) {
    let (mut remaining, mut rounds, mut proofs) = (children, 0usize, 0usize);
    while remaining > 1 {
        let full_chunks = remaining / MAX_CHILDREN_PER_AGGREGATE;
        let leftover = remaining % MAX_CHILDREN_PER_AGGREGATE;
        // A leftover of one is carried to the next round as it is.
        proofs = proofs
            .saturating_add(full_chunks)
            .saturating_add(usize::from(leftover > 1));
        remaining = full_chunks.saturating_add(usize::from(leftover > 0));
        rounds = rounds.saturating_add(1);
    }
    (rounds, proofs)
}

/// The claims a proof of all of `children` attests: their union, strictly sorted.
fn union(children: &[(AggregateClaims, AggregateProof)]) -> AggregateClaims {
    let mut lean_xmss: Vec<_> = children
        .iter()
        .flat_map(|(claims, _)| claims.lean_xmss.iter().copied())
        .collect();
    lean_xmss.sort_unstable();
    lean_xmss.dedup();
    AggregateClaims {
        lean_xmss,
        lean_sphincs: Vec::new(),
        da_commitment: None,
    }
}

impl From<AggregateError> for Error {
    fn from(error: AggregateError) -> Self {
        match error {
            AggregateError::InvalidInput(why) => Error::ProverInvalidInput(why.to_string()),
            AggregateError::InvalidSignature => Error::ProverInvalidSignature,
            AggregateError::InvalidChild => Error::ProverInvalidChild,
            AggregateError::ProvingFailed => Error::ProverFailed,
        }
    }
}

#[cfg(test)]
mod tests;
