# xmss

This crate provides leanXMSS signatures and their aggregation into STARK proofs, as specified by
the [`pq` feature](https://github.com/ethereum/consensus-specs/tree/pq/specs/_features/pq) of the
consensus specs, using [leanVM](https://github.com/leanEthereum/leanVM).

## Running the Tests

Run the tests (in this directory) with:

```
$ cargo test --release
```

The benchmarks can be run with:

```
$ cargo bench
```
