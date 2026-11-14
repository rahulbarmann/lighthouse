use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use xmss::{
    AggregateStatement, Hash256, SecretKey, merge_proofs, prove_aggregates, verify_aggregates,
};

/// The numbers of signatures that the aggregation benchmarks prove.
const SIGNER_COUNTS: [usize; 2] = [16, 128];

fn keys(count: usize) -> Vec<SecretKey> {
    (0..count)
        .map(|i| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            SecretKey::from_seed(seed)
        })
        .collect()
}

pub fn bench_signatures(c: &mut Criterion) {
    let msg = Hash256::repeat_byte(1);
    let key = SecretKey::from_seed([1; 32]);
    let pubkey = key.public_key();
    key.prepare(0).unwrap();
    let signature = key.sign(0, msg).unwrap();

    let mut group = c.benchmark_group("xmss");
    group.sample_size(10);
    group.bench_function("key generation", |b| {
        b.iter(|| SecretKey::from_seed([2; 32]))
    });
    let mut leaf_index = 0;
    group.bench_function("sign in a prepared bottom tree", |b| {
        b.iter(|| {
            leaf_index += 1;
            key.sign(leaf_index, msg).unwrap()
        })
    });
    group.bench_function("verify", |b| {
        b.iter(|| assert!(signature.verify(&pubkey, 0, msg)))
    });
    group.finish();
}

pub fn bench_aggregation(c: &mut Criterion) {
    xmss::setup();
    let msg = Hash256::repeat_byte(1);
    let leaf_index = 0;

    let mut group = c.benchmark_group("stark");
    group.sample_size(10);
    for count in SIGNER_COUNTS {
        let keys = keys(count);
        let statements = vec![AggregateStatement {
            pubkeys: keys.iter().map(|key| key.public_key()).collect(),
            leaf_index,
            message: msg,
        }];
        let signatures = vec![
            keys.iter()
                .map(|key| key.sign(leaf_index, msg).unwrap())
                .collect::<Vec<_>>(),
        ];
        let proof = prove_aggregates(&statements, &signatures).unwrap();
        println!(
            "proof of {count} signatures: {} bytes",
            proof.as_bytes().len()
        );

        group.bench_with_input(BenchmarkId::new("prove", count), &count, |b, _| {
            b.iter(|| prove_aggregates(&statements, &signatures).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("verify", count), &count, |b, _| {
            b.iter(|| assert!(verify_aggregates(&statements, &proof)))
        });

        // Merge two proofs of the same size over different messages.
        let other_statements = vec![AggregateStatement {
            leaf_index: leaf_index + 1,
            message: Hash256::repeat_byte(2),
            ..statements[0].clone()
        }];
        let other_signatures = vec![
            keys.iter()
                .map(|key| {
                    key.sign(leaf_index + 1, other_statements[0].message)
                        .unwrap()
                })
                .collect::<Vec<_>>(),
        ];
        let other_proof = prove_aggregates(&other_statements, &other_signatures).unwrap();
        group.bench_with_input(
            BenchmarkId::new("merge two proofs", count),
            &count,
            |b, _| {
                b.iter(|| {
                    merge_proofs(&[(&statements, &proof), (&other_statements, &other_proof)])
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_signatures, bench_aggregation);
criterion_main!(benches);
