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

## Relation to `bitcoin_hashes`

This crate was extracted out of [bitcoin_hashes](https://crates.io/crates/bitcoin_hashes). As shown
in the initial commit:

```
commit 05a2955470864919172b66feb7b70ebb81d5ec51
Author: Tobin C. Harding <me@tobin.cc>
Date:   Mon Apr 29 04:52:27 2024 +1000

    Import hashes from rust-bitcoin

    Copy the `hashes` directory directly from
    `github.com/rust-bitcoin/rust-bitcoin/hashes` at the tip of the 0.32.0
    tagged release: commit `a3f766715eabf008e0d7f2bfdf2ce7a86e9d2f9b`.

    No other changes.
```

In the manifest the original author was left as is and no additional authors were added made because
I mealy took the code and removed stuff.

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
