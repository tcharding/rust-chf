// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).

use core::cmp;
use core::marker::PhantomData;

use crate::{sha256, HashEngine as _};

type HashEngine = sha256::HashEngine;

/// Trait representing a tag that can be used as a context for SHA256t hashes.
pub trait Tag {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> sha256::HashEngine;
}

/// Output of the SHA256t hash function.
#[repr(transparent)]
pub struct Hash<T: Tag>([u8; 32], PhantomData<T>);

impl<T: Tag> Hash<T> {
    /// Length of the hash, in bytes.
    pub const LEN: usize = 32;

    /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
    ///
    /// # Returns
    ///
    /// The digest created by hashing `bytes` with engine's hashing algorithm.
    #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
    pub fn hash(bytes: &[u8]) -> Self {
        let mut engine = Self::engine();
        engine.input(bytes);
        Self(engine.finalize(), PhantomData)
    }

    /// Returns a hash engine that is ready to be used for data.
    pub fn engine() -> HashEngine { <T as Tag>::engine() }

    /// Creates a `Hash` from an `engine`.
    ///
    /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
    pub fn from_engine(engine: HashEngine) -> Self {
        let digest = engine.finalize();
        Self(digest, PhantomData)
    }

    /// Zero cost conversion between a fixed length byte array shared reference and
    /// a shared reference to this Hash type.
    pub fn from_bytes_ref(bytes: &[u8; 32]) -> &Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
        unsafe { &*(bytes as *const _ as *const Self) }
    }

    /// Zero cost conversion between a fixed length byte array exclusive reference and
    /// an exclusive reference to this Hash type.
    pub fn from_bytes_mut(bytes: &mut [u8; 32]) -> &mut Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
        unsafe { &mut *(bytes as *mut _ as *mut Self) }
    }

    /// Copies a byte slice into a hash object.
    pub fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
        if sl.len() != 32 {
            Err(crate::FromSliceError { expected: 32, got: sl.len() })
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Self::from_byte_array(ret))
        }
    }

    /// Constructs a hash from the underlying byte array.
    pub fn from_byte_array(bytes: [u8; 32]) -> Self { Self(bytes, PhantomData) }

    /// Returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub fn as_byte_array(&self) -> &[u8; 32] { &self.0 }

    /// Returns an all zero hash.
    ///
    /// An all zeros hash is a made up construct because there is not a known input that can
    /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
    /// block's previous blockhash and the coinbase transaction's outpoint txid.
    pub fn all_zeros() -> Self { Self([0x00; 32], PhantomData) }
}

#[cfg(feature = "schemars")]
impl<T: Tag> schemars::JsonSchema for Hash<T> {
    fn schema_name() -> String { "Hash".to_owned() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
        schema.string = Some(Box::new(schemars::schema::StringValidation {
            max_length: Some(32 * 2),
            min_length: Some(32 * 2),
            pattern: Some("[0-9a-fA-F]+".to_owned()),
        }));
        schema.into()
    }
}

impl<T: Tag> Copy for Hash<T> {}
impl<T: Tag> Clone for Hash<T> {
    fn clone(&self) -> Self { *self }
}
impl<T: Tag> PartialEq for Hash<T> {
    fn eq(&self, other: &Hash<T>) -> bool { self.0 == other.0 }
}
impl<T: Tag> Eq for Hash<T> {}
impl<T: Tag> Default for Hash<T> {
    fn default() -> Self { Hash([0; 32], PhantomData) }
}
impl<T: Tag> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Hash<T>) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}
impl<T: Tag> Ord for Hash<T> {
    fn cmp(&self, other: &Hash<T>) -> cmp::Ordering { cmp::Ord::cmp(&self.0, &other.0) }
}
impl<T: Tag> core::hash::Hash for Hash<T> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) { self.0.hash(h) }
}

crate::internal_macros::hash_trait_impls!(256, T: Tag);

#[cfg(test)]
mod tests {
    use crate::{sha256, sha256t};

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    // The digest created by sha256 hashing `&[0]` starting with `TEST_MIDSTATE`.
    #[cfg(feature = "alloc")]
    const HASH_ZERO: &str = "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829";

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    pub struct TestHashTag;

    impl sha256t::Tag for TestHashTag {
        fn engine() -> sha256::HashEngine {
            // The TapRoot TapLeaf midstate.
            let midstate = sha256::Midstate::from_byte_array(TEST_MIDSTATE);
            sha256::HashEngine::from_midstate(midstate, 64)
        }
    }

    // We support manually implementing `Tag` and creating a tagged hash from it.
    #[cfg(feature = "alloc")]
    pub type TestHash = sha256t::Hash<TestHashTag>;

    #[test]
    #[cfg(feature = "alloc")]
    fn manually_created_sha256t_hash_type() {
        assert_eq!(TestHash::hash(&[0]).to_string(), HASH_ZERO);
    }
}
