// SPDX-License-Identifier: CC0-1.0

//! Rust Cryptographic Hash Functions.
//!
//! This is a simple, no-dependency library which implements the bunch of crypotographic hash
//! functions. At the moment this includes:
//! - SHA-1
//! - SHA-2
//!   - SHA256
//!   - SHA384
//!   - SHA512
//!   - SHA512_256
//! - RIPEMD-160
//! - SipHash
//! - HMAC-x (where x is any of the hash functions above).
//!
//! ## Commonly used operations
//!
//! Hashing a single byte slice or a string:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//!
//! let bytes = [0u8; 5];
//! let hash_of_bytes = sha256::Hash::hash(&bytes);
//! let hash_of_string = sha256::Hash::hash("some string".as_bytes());
//! ```
//!
//!
//! Hashing content from a reader:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = sha256::HashEngine::default();
//! std::io::copy(&mut reader, &mut engine)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```
//!
//!
//! Hashing content by [`std::io::Write`] on HashEngine:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//! use std::io::Write;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = sha256::HashEngine::default();
//! engine.write_all(part1)?;
//! engine.write_all(part2)?;
//! engine.write_all(part3)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(hashes_fuzz, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(feature = "serde")]
/// A generic serialization/deserialization framework.
pub extern crate serde;

#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
#[cfg(bench)]
extern crate test;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

#[doc(hidden)]
pub mod _export {
    /// A re-export of core::*
    pub mod _core {
        pub use core::*;
    }
}

#[cfg(feature = "schemars")]
extern crate schemars;

mod internal_macros;
#[macro_use]
mod util;
#[macro_use]
pub mod serde_macros;
pub mod cmp;
pub mod hmac;
#[cfg(feature = "bitcoin-io")]
mod impls;
pub mod ripemd160;
pub mod sha1;
pub mod sha256;
pub mod sha256t;
pub mod sha384;
pub mod sha512;
pub mod sha512_256;
pub mod siphash24;

use core::fmt;

pub use hmac::{Hmac, HmacEngine};

/// A hashing engine which bytes can be serialized into.
pub trait HashEngine<const N: usize>: Clone + Default {
    /// Byte array representing the internal state of the hash engine.
    type Midstate;

    /// Length of the hash's internal block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Creates a new hash engine.
    fn new() -> Self { Default::default() }

    /// Add data to the hash engine.
    fn input(&mut self, data: &[u8]);

    /// Return the number of bytes already n_bytes_hashed(inputted).
    fn n_bytes_hashed(&self) -> usize;

    /// Returns the final digest from the current state of the hash engine.
    fn finalize(self) -> [u8; N];

    /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
    ///
    /// # Returns
    ///
    /// The digest created by hashing `bytes` with engine's hashing algorithm.
    fn hash(bytes: &[u8]) -> [u8; N] {
        let mut engine = Self::new();
        engine.input(bytes);
        engine.finalize()
    }

    /// Hashes all the byte slices retrieved from the iterator together.
    fn hash_byte_chunks<B, I>(byte_slices: I) -> [u8; N]
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = B>,
    {
        let mut engine = Self::new();
        for slice in byte_slices {
            engine.input(slice.as_ref());
        }
        engine.finalize()
    }

    /// Outputs the midstate of the hash engine. This function should not be
    /// used directly unless you really know what you're doing.
    fn midstate(&self) -> Self::Midstate;

    /// Create a new [`HashEngine`] from a [`Midstate`].
    ///
    /// Only use this function if you know what you are doing.
    fn from_midstate(midstate: Self::Midstate, length: usize) -> Self;
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError {
    expected: usize,
    got: usize,
}

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize { self.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.got }
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.got, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}
