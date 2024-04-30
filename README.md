# Rust Cryptographic Hash Functions.

This is a simple, no-dependency library which implements the bunch of crypotographic hash
functions. At the moment this includes:
 - SHA-1
 - SHA-2
   - SHA-256
   - SHA-384
   - SHA-512
   - SHA-512/256
 - RIPEMD-160
 - SipHash-2-4
 - HMAC-x (where x is any of the hash functions above).

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.

## Contributions

Contributions are welcome, including additional hash function implementations.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

### Running Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.
