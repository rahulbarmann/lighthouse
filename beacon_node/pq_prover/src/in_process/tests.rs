//! The in-process backend, and in release builds with real crypto, leanVM's actual prover.

use super::*;
use xmss::{XMSS_SIGNATURE_BYTES_LEN, XmssPublicKey};

fn backend() -> InProcessBackend {
    InProcessBackend::new(InProcessConfig::default()).unwrap()
}

fn pubkey(index: usize) -> XmssPublicKey {
    let mut bytes = [0x40; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    XmssPublicKey::from(bytes)
}

fn statement(keys: std::ops::Range<usize>, message: u8) -> Statement {
    Statement {
        pubkeys: keys.map(pubkey).collect(),
        leaf_index: 40_000,
        message: [message; 32],
    }
}

#[test]
fn empty_proof_proves_only_nothing() {
    let backend = backend();
    let no_keys = Statement {
        pubkeys: vec![],
        leaf_index: 1,
        message: [1; 32],
    };
    let empty = backend.prove(&[], &[]).unwrap();
    assert!(empty.is_empty());
    assert!(
        backend
            .prove(std::slice::from_ref(&no_keys), &[vec![]])
            .unwrap()
            .is_empty()
    );
    assert!(backend.merge(&[]).unwrap().is_empty());
    assert!(
        backend
            .merge(&[(vec![], Proof::default())])
            .unwrap()
            .is_empty()
    );
    assert!(backend.verify(&[], &empty).unwrap());
    assert!(backend.verify(&[no_keys], &empty).unwrap());
    assert!(!backend.verify(&[statement(0..1, 1)], &empty).unwrap());
    assert!(!backend.verify(&[], &Proof::from_bytes(vec![1])).unwrap());
}

#[test]
fn undecodable_proofs_are_rejected() {
    let backend = backend();
    let statements = [statement(0..2, 1)];
    let garbage = Proof::from_bytes(vec![7; 64]);
    assert!(!backend.verify(&statements, &garbage).unwrap());
    assert!(matches!(
        backend.merge(&[
            (statements.to_vec(), garbage.clone()),
            (vec![statement(2..3, 1)], garbage),
        ]),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn leaf_mismatch_is_refused_before_proving() {
    let backend = backend();
    let mut bytes = [0; XMSS_SIGNATURE_BYTES_LEN];
    bytes[..4].copy_from_slice(&7u32.to_le_bytes());
    let signature = XmssSignature::from(bytes);
    assert!(matches!(
        backend.prove(&[statement(0..1, 1)], &[vec![signature]]),
        Err(Error::LeafIndexMismatch { .. })
    ));
}

#[test]
fn another_thread_count_is_an_error() {
    let _ = backend();
    let config = InProcessConfig {
        threads: 3,
        ..InProcessConfig::default()
    };
    assert!(matches!(
        InProcessBackend::new(config),
        Err(Error::ProverUnavailable(_))
    ));
}

#[test]
fn merge_plan_counts_rounds_and_proofs() {
    assert_eq!(merge_plan(0), (0, 0));
    assert_eq!(merge_plan(1), (0, 0));
    assert_eq!(merge_plan(2), (1, 1));
    assert_eq!(merge_plan(16), (1, 1));
    assert_eq!(merge_plan(17), (2, 2));
    assert_eq!(merge_plan(32), (2, 3));
    assert_eq!(merge_plan(64), (2, 5));
    assert_eq!(merge_plan(256), (2, 17));
    assert_eq!(merge_plan(257), (3, 18));
}

#[cfg(all(not(debug_assertions), not(feature = "fake_crypto")))]
#[test]
fn prove_merge_verify_round_trip() {
    use xmss::XmssSecretKey;

    let backend = backend();
    let leaf = (1u32 << 15) + 5;
    let keys: Vec<XmssSecretKey> = (1..=3u8)
        .map(|i| XmssSecretKey::from_seed(&[i; 32]))
        .collect();
    let signed = |keys: &[XmssSecretKey], message: [u8; 32], leaf| {
        let statement = Statement {
            pubkeys: keys.iter().map(XmssSecretKey::public_key).collect(),
            leaf_index: u64::from(leaf),
            message,
        };
        let signatures: Vec<XmssSignature> = keys
            .iter()
            .map(|key| key.sign(&message, leaf).unwrap())
            .collect();
        (statement, signatures)
    };
    let (first, first_signatures) = signed(&keys[..2], [1; 32], leaf);
    let (second, second_signatures) = signed(&keys[1..], [2; 32], leaf + 1);
    let left_statements = vec![first];
    let right_statements = vec![second];
    let left = backend
        .prove(&left_statements, std::slice::from_ref(&first_signatures))
        .unwrap();
    let right = backend
        .prove(&right_statements, &[second_signatures])
        .unwrap();
    assert!(backend.verify(&left_statements, &left).unwrap());
    assert!(backend.verify(&right_statements, &right).unwrap());

    // Tampered proof, other statements.
    let mut tampered = left.as_bytes().to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(
        !backend
            .verify(&left_statements, &Proof::from_bytes(tampered))
            .unwrap()
    );
    assert!(!backend.verify(&right_statements, &left).unwrap());
    let mut other_message = left_statements.clone();
    other_message[0].message = [3; 32];
    assert!(!backend.verify(&other_message, &left).unwrap());

    // Merged, in either statement order.
    let merged = backend
        .merge(&[
            (left_statements.clone(), left.clone()),
            (right_statements.clone(), right),
        ])
        .unwrap();
    let all_statements = [left_statements.clone(), right_statements.clone()].concat();
    let reordered = [right_statements, left_statements.clone()].concat();
    assert!(backend.verify(&all_statements, &merged).unwrap());
    assert!(backend.verify(&reordered, &merged).unwrap());
    assert!(!backend.verify(&left_statements, &merged).unwrap());

    // Extend a saved proof with a child sharing one identical signer/claim.
    let (overlap, overlap_signatures) = signed(&keys[1..], [1; 32], leaf);
    let overlap = vec![overlap];
    let overlap_proof = backend
        .prove(&overlap, std::slice::from_ref(&overlap_signatures))
        .unwrap();
    let output = vec![Statement {
        pubkeys: vec![
            keys[2].public_key(),
            keys[0].public_key(),
            keys[1].public_key(),
        ],
        ..left_statements[0].clone()
    }];
    let inputs = vec![(left_statements.clone(), left), (overlap, overlap_proof)];
    let union = backend
        .merge_for_statements(&inputs, &output, 1 << 20)
        .unwrap();
    assert!(backend.verify(&output, &union).unwrap());
    assert!(!backend.verify(&left_statements, &union).unwrap());
    assert!(
        backend
            .merge_for_statements(&inputs, &left_statements, 1 << 20)
            .is_err()
    );

    // An invalid signature is leanVM's to find.
    let swapped = vec![first_signatures[1].clone(), first_signatures[0].clone()];
    assert!(matches!(
        backend.prove(&left_statements, &[swapped]),
        Err(Error::ProverInvalidSignature | Error::ProverFailed)
    ));
}
