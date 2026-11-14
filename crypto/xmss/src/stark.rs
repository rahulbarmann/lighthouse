use crate::{Error, Hash256, PublicKey, Signature};
use leanvm::{EthereumClaims, EthereumProof};
use parking_lot::Mutex;

/// The `log_inv_rate` that proofs are made at. A higher `log_inv_rate` makes a smaller proof and a
/// slower prover. The spec does not fix one yet.
pub const LOG_INV_RATE: usize = 1;

/// leanVM must not prove more than one aggregate at a time.
static AGGREGATE_LOCK: Mutex<()> = Mutex::new(());

/// The public keys that signed `message` at `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateStatement {
    pub pubkeys: Vec<PublicKey>,
    pub leaf_index: u64,
    pub message: Hash256,
}

/// A STARK proof of the leanXMSS signatures of some statements.
///
/// A proof of no signatures is empty, as in the spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestationProof(Vec<u8>);

impl AttestationProof {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Returns the `(pubkey, message)` claims of `statements`, sorted and without duplicates.
///
/// A leanVM proof does not prove the leaf index of a signature, so there is no claim for it.
fn claims_of<'a>(statements: impl IntoIterator<Item = &'a AggregateStatement>) -> EthereumClaims {
    let mut xmss: Vec<_> = statements
        .into_iter()
        .flat_map(|statement| {
            statement
                .pubkeys
                .iter()
                .map(|pubkey| (pubkey.0, statement.message.0))
        })
        .collect();
    xmss.sort();
    xmss.dedup();
    EthereumClaims {
        xmss,
        lean_sphincs: vec![],
        da_commitment: None,
    }
}

/// Proves `signatures`, which hold the signatures of each statement in the order of its public
/// keys.
///
/// The signatures are not verified first. An invalid one fails to prove.
pub fn prove_aggregates(
    statements: &[AggregateStatement],
    signatures: &[Vec<Signature>],
) -> Result<AttestationProof, Error> {
    if statements.len() != signatures.len() {
        return Err(Error::StatementCountMismatch {
            expected: statements.len(),
            got: signatures.len(),
        });
    }

    let mut signed = vec![];
    for (index, (statement, signatures)) in statements.iter().zip(signatures).enumerate() {
        if statement.pubkeys.len() != signatures.len() {
            return Err(Error::SignatureCountMismatch {
                statement: index,
                expected: statement.pubkeys.len(),
                got: signatures.len(),
            });
        }
        for (pubkey, signature) in statement.pubkeys.iter().zip(signatures) {
            // The proof does not prove the leaf index, so it is checked here.
            if signature.leaf_index() != statement.leaf_index {
                return Err(Error::LeafIndexMismatch {
                    expected: statement.leaf_index,
                    got: signature.leaf_index(),
                });
            }
            signed.push((pubkey.0, statement.message.0, signature.0.clone()));
        }
    }

    if signed.is_empty() {
        return Ok(AttestationProof::default());
    }
    let _lock = AGGREGATE_LOCK.lock();
    let proof = leanvm::aggregate(&[], signed, vec![], &[], None, LOG_INV_RATE)
        .map_err(Error::AggregationError)?;
    Ok(AttestationProof(proof.proof_bytes()))
}

/// Merges `proofs` into one proof of all of their statements.
///
/// Unlike `stark.MergeProofs` in the spec, it takes the statements of each proof, since leanVM
/// needs them to decode it. The proofs are not verified first, and a single non-empty proof is
/// returned as it is.
pub fn merge_proofs(
    proofs: &[(&[AggregateStatement], &AttestationProof)],
) -> Result<AttestationProof, Error> {
    let mut children = proofs
        .iter()
        .filter(|(_, proof)| !proof.is_empty())
        .map(|(statements, proof)| {
            EthereumProof::from_proof_bytes(proof.as_bytes(), claims_of(statements.iter()))
                .map_err(Error::InvalidProof)
        })
        .collect::<Result<Vec<_>, _>>()?;

    match children.len() {
        0 => Ok(AttestationProof::default()),
        1 => Ok(AttestationProof(children.remove(0).proof_bytes())),
        _ => {
            let _lock = AGGREGATE_LOCK.lock();
            let proof = leanvm::aggregate(&children, vec![], vec![], &[], None, LOG_INV_RATE)
                .map_err(Error::AggregationError)?;
            Ok(AttestationProof(proof.proof_bytes()))
        }
    }
}

/// Returns `true` if `proof` proves a signature by each public key of each statement.
///
/// ## Notes
///
/// Unlike `stark.VerifyAggregates` in the spec, this does not check the leaf indices of
/// `statements`, since a leanVM proof does not prove them.
pub fn verify_aggregates(statements: &[AggregateStatement], proof: &AttestationProof) -> bool {
    let claims = claims_of(statements);
    if claims.xmss.is_empty() {
        return proof.is_empty();
    }
    EthereumProof::from_proof_bytes(proof.as_bytes(), claims)
        .and_then(|proof| proof.verify())
        .is_ok()
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::tests::test_keys;

    fn msg(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    /// Returns a statement that the first `count` test keys signed `message` at `leaf_index`, and
    /// their signatures.
    fn signed_statement(
        count: usize,
        leaf_index: u64,
        message: Hash256,
    ) -> (AggregateStatement, Vec<Signature>) {
        let keys = &test_keys()[..count];
        let statement = AggregateStatement {
            pubkeys: keys.iter().map(|key| key.public_key()).collect(),
            leaf_index,
            message,
        };
        let signatures = keys
            .iter()
            .map(|key| key.sign(leaf_index, message).unwrap())
            .collect();
        (statement, signatures)
    }

    #[test]
    fn prove_and_verify_aggregates() {
        crate::setup();
        let (first, first_signatures) = signed_statement(3, 100, msg(1));
        let (second, second_signatures) = signed_statement(2, 101, msg(2));
        let statements = vec![first, second];
        let proof = prove_aggregates(&statements, &[first_signatures, second_signatures]).unwrap();
        assert!(verify_aggregates(&statements, &proof));

        let mut wrong_message = statements.clone();
        wrong_message[1].message = msg(3);
        assert!(!verify_aggregates(&wrong_message, &proof));

        let mut fewer_keys = statements.clone();
        fewer_keys[0].pubkeys.pop();
        assert!(!verify_aggregates(&fewer_keys, &proof));

        assert!(!verify_aggregates(&[], &proof));
    }

    #[test]
    fn merge_proofs_proves_all_statements() {
        crate::setup();
        let (first, first_signatures) = signed_statement(2, 200, msg(4));
        let (second, second_signatures) = signed_statement(3, 201, msg(5));
        let first = vec![first];
        let second = vec![second];
        let first_proof = prove_aggregates(&first, &[first_signatures]).unwrap();
        let second_proof = prove_aggregates(&second, &[second_signatures]).unwrap();

        let merged = merge_proofs(&[(&first, &first_proof), (&second, &second_proof)]).unwrap();
        let all: Vec<_> = first.iter().chain(&second).cloned().collect();
        assert!(verify_aggregates(&all, &merged));
        assert!(!verify_aggregates(&first, &merged));

        // An empty proof adds nothing.
        let empty = AttestationProof::default();
        let merged = merge_proofs(&[(&[], &empty), (&first, &first_proof)]).unwrap();
        assert_eq!(merged, first_proof);
    }

    #[test]
    fn empty_statements_have_an_empty_proof() {
        let proof = prove_aggregates(&[], &[]).unwrap();
        assert!(proof.is_empty());
        assert!(verify_aggregates(&[], &proof));
        assert!(merge_proofs(&[(&[], &proof)]).unwrap().is_empty());
        assert!(!verify_aggregates(
            &[],
            &AttestationProof::from_bytes(vec![0])
        ));
    }

    #[test]
    fn prove_aggregates_rejects_wrong_leaf_index() {
        let (mut statement, signatures) = signed_statement(2, 300, msg(6));
        statement.leaf_index = 301;
        assert!(matches!(
            prove_aggregates(&[statement], &[signatures]),
            Err(Error::LeafIndexMismatch {
                expected: 301,
                got: 300
            })
        ));
    }

    #[test]
    fn prove_aggregates_rejects_signature_count_mismatch() {
        let (statement, mut signatures) = signed_statement(2, 400, msg(7));
        signatures.pop();
        assert!(matches!(
            prove_aggregates(&[statement], &[signatures]),
            Err(Error::SignatureCountMismatch {
                statement: 0,
                expected: 2,
                got: 1
            })
        ));
    }
}
