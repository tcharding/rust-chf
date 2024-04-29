// SPDX-License-Identifier: CC0-1.0

// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! Hash-based Message Authentication Code (HMAC).
//!

use core::borrow::Borrow;
use core::{borrow, fmt, str};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::HashEngine;

/// A hash computed from a RFC 2104 HMAC. Parameterized by the underlying hash function.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hmac<const N: usize>([u8; N]);

impl<const N: usize> Hmac<N> {
    /// Length of the hash, in bytes.
    pub const LEN: usize = N;

    /// Returns the length of the hash, in bytes.
    // FIXME: function vs const ?
    pub const fn len() -> usize { N }

    /// Returns a hash engine that is ready to be used for the data.
    pub fn engine<E: HashEngine<N>>() -> E { E::new() }

    /// Creates a `Hash` from an `engine`.
    ///
    /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
    pub fn from_engine<E: HashEngine<N>>(engine: E) -> Self {
        let digest = engine.finalize();
        Self(digest)
    }

    /// Zero cost conversion between a fixed length byte array shared reference and
    /// a shared reference to this Hash type.
    pub fn from_bytes_ref(bytes: &[u8; N]) -> &Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
        unsafe { &*(bytes as *const _ as *const Self) }
    }

    /// Zero cost conversion between a fixed length byte array exclusive reference and
    /// an exclusive reference to this Hash type.
    pub fn from_bytes_mut(bytes: &mut [u8; N]) -> &mut Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; N]
        unsafe { &mut *(bytes as *mut _ as *mut Self) }
    }

    /// Copies a byte slice into a hash object.
    pub fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
        if sl.len() != N {
            Err(crate::FromSliceError{expected: N, got: sl.len()})
        } else {
            let mut ret = [0; N];
            ret.copy_from_slice(sl);
            Ok(Self::from_byte_array(ret))
        }
    }

    /// Constructs a hash from the underlying byte array.
    pub fn from_byte_array(bytes: [u8; N]) -> Self { Self(bytes) }

    /// Returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; N] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub fn as_byte_array(&self) -> &[u8; N] { &self.0 }

    /// Returns an all zero hash.
    ///
    /// An all zeros hash is a made up construct because there is not a known input that can
    /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
    /// block's previous blockhash and the coinbase transaction's outpoint txid.
    pub fn all_zeros() -> Self { Self([0x00; N]) }
}

#[cfg(feature = "schemars")]
impl<T: HashEngine + schemars::JsonSchema> schemars::JsonSchema for Hmac<T> {
    fn is_referenceable() -> bool { <T as schemars::JsonSchema>::is_referenceable() }

    fn schema_name() -> std::string::String { <T as schemars::JsonSchema>::schema_name() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <T as schemars::JsonSchema>::json_schema(gen)
    }
}

impl<const N: usize> str::FromStr for Hmac<N> {
    type Err = hex::HexToArrayError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::{FromHex};

        let bytes = <[u8; N]>::from_hex(s)?;
        Ok(Self::from_byte_array(bytes))
    }
}

impl<const N: usize> fmt::Display for Hmac<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl<const N: usize> fmt::Debug for Hmac<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:#}", self) }
}

impl<const N: usize> fmt::LowerHex for Hmac<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: I can't get the macro to work with N?
        // hex::fmt_hex_exact!(f, N, self.0.iter(), hex::Case::Lower)
        hex::display::fmt_hex_exact_fn::<std::slice::Iter<'_, u8>, N>(f, self.0.iter(), hex::Case::Lower)
    }
}

impl<const N: usize> fmt::UpperHex for Hmac<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: I can't get the macro to work with N?
        // hex::fmt_hex_exact!(f, N, self.0.iter(), hex::Case::Lower)
        hex::display::fmt_hex_exact_fn::<std::slice::Iter<'_, u8>, N>(f, self.0.iter(), hex::Case::Upper)
    }
}
 
/// Pair of underlying hash midstates which represent the current state of an `HmacEngine`.
pub struct HmacMidState<E: HashEngine<N>, const N: usize> {
    /// Midstate of the inner hash engine
    pub inner: E::Midstate,
    /// Midstate of the outer hash engine
    pub outer: E::Midstate,
}

/// Pair of underlying hash engines, used for the inner and outer hash of HMAC.
#[derive(Clone)]
pub struct HmacEngine<E: HashEngine<N>, const N: usize> {
    iengine: E,
    oengine: E,
}

impl<E: HashEngine<N>, const N: usize> Default for HmacEngine<E, N> {
    fn default() -> Self { HmacEngine::new(&[]) }
}

impl<E: HashEngine<N>, const N: usize> HmacEngine<E, N> {
    /// Constructs a new keyed HMAC from `key`.
    ///
    /// We only support underlying hashes whose block sizes are ≤ 128 bytes.
    ///
    /// # Panics
    ///
    /// Larger hashes will result in a panic.
    pub fn new(key: &[u8]) -> HmacEngine<E, N> {
        debug_assert!(E::BLOCK_SIZE <= 128);

        let mut ipad = [0x36u8; 128];
        let mut opad = [0x5cu8; 128];
        let mut ret = HmacEngine { iengine: E::default(), oengine: E::default() };

        if key.len() > E::BLOCK_SIZE {
            let hash = <E as HashEngine<N>>::hash(key);
            for (b_i, b_h) in ipad.iter_mut().zip(&<[u8; N] as Borrow<[u8; N]>>::borrow(&hash)[..]) {
                *b_i ^= *b_h;
            }
            for (b_o, b_h) in opad.iter_mut().zip(&<[u8; N] as Borrow<[u8; N]>>::borrow(&hash)[..]) {
                *b_o ^= *b_h;
            }
        } else {
            for (b_i, b_h) in ipad.iter_mut().zip(key) {
                *b_i ^= *b_h;
            }
            for (b_o, b_h) in opad.iter_mut().zip(key) {
                *b_o ^= *b_h;
            }
        };

        ret.iengine.input(&ipad[..E::BLOCK_SIZE]);
        ret.oengine.input(&opad[..E::BLOCK_SIZE]);
        ret
    }
}

impl<E: HashEngine<N>, const N: usize> HashEngine<N> for HmacEngine<E, N> {
    type Midstate = HmacMidstate<E, N>;
    const BLOCK_SIZE: usize = E::BLOCK_SIZE;

    #[inline]
    fn input(&mut self, data: &[u8]) { self.iengine.input(data) }

    #[inline]
    fn n_bytes_hashed(&self) -> usize { self.iengine.n_bytes_hashed() }

    #[inline]
    fn finalize(mut self) -> [u8; N] {
        let ihash = self.iengine.finalize();
        self.oengine.input(&<[u8; N] as Borrow<[u8; N]>>::borrow(&ihash)[..]);
        self.oengine.finalize()
    }

    #[inline]
    fn midstate(&self) -> Self::Midstate {
        HmacMidstate { inner: self.iengine.midstate(), outer: self.oengine.midstate() }
    }

    #[inline]
    fn from_midstate(midstate: HmacMidstate<E, N>, length: usize) -> Self {
        HmacEngine {
            iengine: E::from_midstate(midstate.inner, length),
            oengine: E::from_midstate(midstate.outer, length),
        }
    }
}

/// Pair of underlying hash engine midstates which represent the current state of an `HmacEngine`.
// TODO: Use derives?
//#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct HmacMidstate<E: HashEngine<N>, const N: usize> {
    /// Midstate of the inner hash engine.
    pub inner: E::Midstate,
    /// Midstate of the outer hash engine.
    pub outer: E::Midstate,
}

impl<const N: usize> borrow::Borrow<[u8]> for Hmac<N> {
    fn borrow(&self) -> &[u8] { &self.0 }
}

#[cfg(feature = "serde")]
impl<E: HashEngine<N> + Serialize, const N: usize> Serialize for Hmac<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de, E: HashEngine<N> + Deserialize<'de>, const N: usize> Deserialize<'de> for Hmac<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Hmac<E>, D::Error> {
        let bytes = Deserialize::deserialize(d)?;
        Ok(Hmac(bytes))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use super::*;
        use crate::sha256;

        #[derive(Clone)]
        struct Test {
            key: Vec<u8>,
            input: Vec<u8>,
            output: Vec<u8>,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Test vectors copied from libsecp256k1
            // Sadly the RFC2104 test vectors all use MD5 as their underlying hash function,
            // which of course this library does not support.
            Test {
                key: vec![ 0x0b; 20],
                input: vec![0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65],
                output: vec![
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                    0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ],
            },
            Test {
                key: vec![ 0x4a, 0x65, 0x66, 0x65 ],
                input: vec![
                    0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
                    0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
                    0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
                    0x69, 0x6e, 0x67, 0x3f,
                ],
                output: vec![
                    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                    0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                    0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
                ],
            },
            Test {
                key: vec![ 0xaa; 20 ],
                input: vec![ 0xdd; 50 ],
                output: vec![
                    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
                    0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
                    0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
                    0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
                ],
            },
            Test {
                key: vec![
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19
                ],
                input: vec![ 0xcd; 50 ],
                output: vec![
                    0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
                    0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
                    0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
                    0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
                ],
            },
            Test {
                key: vec! [ 0xaa; 131 ],
                input: vec![
                    0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69,
                    0x6e, 0x67, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65,
                    0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
                    0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a,
                    0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20,
                    0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
                    0x20, 0x46, 0x69, 0x72, 0x73, 0x74,
                ],
                output: vec![
                    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
                    0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
                    0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
                    0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
                ],
            },
            Test {
                key: vec! [ 0xaa; 131 ],
                input: vec![
                    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
                    0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75,
                    0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c,
                    0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68,
                    0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
                    0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65,
                    0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20,
                    0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74,
                    0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63,
                    0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64,
                    0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65,
                    0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65,
                    0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65,
                    0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20,
                    0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
                    0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65,
                    0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
                    0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c,
                    0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
                ],
                output: vec![
                    0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
                    0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
                    0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
                    0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
                ],
            },
        ];

        for test in tests {
            let mut engine = HmacEngine::<sha256::HashEngine, 32>::new(&test.key);
            engine.input(&test.input);
            let hash = engine.finalize();
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(hash, test.output.as_slice());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn hmac_sha512_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        use crate::{sha512, Hash, Hmac};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 64] = [
            0x8b, 0x41, 0xe1, 0xb7, 0x8a, 0xd1, 0x15, 0x21,
            0x11, 0x3c, 0x52, 0xff, 0x18, 0x2a, 0x1b, 0x8e,
            0x0a, 0x19, 0x57, 0x54, 0xaa, 0x52, 0x7f, 0xcd,
            0x00, 0xa4, 0x11, 0x62, 0x0b, 0x46, 0xf2, 0x0f,
            0xff, 0xfb, 0x80, 0x88, 0xcc, 0xf8, 0x54, 0x97,
            0x12, 0x1a, 0xd4, 0x49, 0x9e, 0x08, 0x45, 0xb8,
            0x76, 0xf6, 0xdd, 0x66, 0x40, 0x08, 0x8a, 0x2f,
            0x0b, 0x2d, 0x8a, 0x60, 0x0b, 0xdf, 0x4c, 0x0c,
        ];

        let hash = Hmac::<sha512::Hash>::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(
            &hash.readable(),
            &[Token::Str(
                "8b41e1b78ad11521113c52ff182a1b8e0a195754aa527fcd00a411620b46f20f\
                 fffb8088ccf85497121ad4499e0845b876f6dd6640088a2f0b2d8a600bdf4c0c",
            )],
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha256, Hash, HashEngine, Hmac};

    #[bench]
    pub fn hmac_sha256_10(bh: &mut Bencher) {
        let mut engine = Hmac::<sha256::Hash>::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn hmac_sha256_1k(bh: &mut Bencher) {
        let mut engine = Hmac::<sha256::Hash>::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn hmac_sha256_64k(bh: &mut Bencher) {
        let mut engine = Hmac::<sha256::Hash>::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
