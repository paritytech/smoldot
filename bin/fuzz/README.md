# Fuzzing

These fuzzing targets can be used in conjunction with [`cargo fuzz`](https://github.com/rust-fuzz/cargo-fuzz).

Setup:

```bash
cargo install --force cargo-fuzz
rustup install nightly
```

In order to start fuzzing:

```bash
cargo +nightly fuzz run --fuzz-dir ./bin/fuzz <bin>
```

Where `<bin>` is one of the files in the `fuzz_targets` directory.
