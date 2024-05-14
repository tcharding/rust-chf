// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

/// Adds `AsRef` implementation to a given type `$ty`.
macro_rules! as_ref_impl(
    ($ty:ident) => (
        $crate::internal_macros::as_ref_impl!($ty, );
    );
    ($ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*>  {
            fn as_ref(&self) -> &[u8] { &self[..] }
        }
    )
);
pub(crate) use as_ref_impl;

/// Adds an implementation of the `HashEngine::input` method.
macro_rules! engine_input_impl(
    ($n:literal) => (
        #[cfg(not(hashes_fuzz))]
        fn input(&mut self, mut inp: &[u8]) {
            while !inp.is_empty() {
                let buf_idx = self.length % <Self as crate::HashEngine>::BLOCK_SIZE;
                let rem_len = <Self as crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = $crate::_export::_core::cmp::min(rem_len, inp.len());

                self.buffer[buf_idx..buf_idx + write_len]
                    .copy_from_slice(&inp[..write_len]);
                self.length += write_len;
                if self.length % <Self as crate::HashEngine>::BLOCK_SIZE == 0 {
                    self.process_block();
                }
                inp = &inp[write_len..];
            }
        }

        #[cfg(hashes_fuzz)]
        fn input(&mut self, inp: &[u8]) {
            for c in inp {
                self.buffer[0] ^= *c;
            }
            self.length += inp.len();
        }
    )
);
pub(crate) use engine_input_impl;

macro_rules! arr_newtype_fmt_impl {
    ($ty:ident, $bytes:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter(), $crate::hex::Case::Lower)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter(), $crate::hex::Case::Upper)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{:#}", self)
            }
        }
    }
}
pub(crate) use arr_newtype_fmt_impl;

/// Adds trait impls to the type called `Hash` in the current scope.
///
/// Implpements various conversion traits as well as the [`crate::Hash`] trait.
/// Arguments:
///
/// * `$bits` - number of bits this hash type has
/// * `$reverse` - `bool`  - `true` if the hash type should be displayed backwards, `false`
///    otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s)
///
/// Restrictions on usage:
///
/// * There must be a free-standing `fn from_engine(HashEngine) -> Hash` in the scope
/// * `fn internal_new([u8; $bits / 8]) -> Self` must exist on `Hash`
/// * `fn internal_engine() -> HashEngine` must exist on `Hash`
///
/// `from_engine` obviously implements the finalization algorithm.
/// `internal_new` is required so that types with more than one field are constructible.
/// `internal_engine` is required to initialize the engine for given hash type.
macro_rules! hash_trait_impls {
    ($bits:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for Hash<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::hex::FromHex;

                let bytes = <[u8; $bits / 8]>::from_hex(s)?;
                Ok(Self::from_byte_array(bytes))
            }
        }

        $crate::internal_macros::arr_newtype_fmt_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
        serde_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
        $crate::internal_macros::as_ref_impl!(Hash $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8; $bits / 8]> for Hash<$($gen),*> {
            fn as_ref(&self) -> &[u8; $bits / 8] { &self.0 }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]> $(, $gen: $gent)*> $crate::_export::_core::ops::Index<I> for Hash<$($gen),*> {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}
pub(crate) use hash_trait_impls;

/// Creates a type called `Hash` and implements standard interface for it.
///
/// The created type will have all standard derives, `Hash` impl and implementation of
/// `internal_engine` returning default. The created type has a single field.
///
/// Arguments:
///
/// * `$bits` - the number of bits of the hash type
/// * `$reverse` - `true` if the hash should be displayed backwards, `false` otherwise
/// * `$doc` - doc string to put on the type
/// * `$schemars` - a literal that goes into `schema_with`.
///
/// The `from_engine` free-standing function is still required with this macro. See the doc of
/// [`hash_trait_impls`].
macro_rules! hash_type {
    ($bits:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct Hash([u8; $bits / 8]);

        impl Hash {
            /// Length of the hash, in bytes.
            pub const LEN: usize = $bits / 8;

            /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
            ///
            /// # Returns
            ///
            /// The digest created by hashing `bytes` with engine's hashing algorithm.
            #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
            pub fn hash(bytes: &[u8]) -> Self {
                let mut engine = Self::engine();
                engine.input(bytes);
                Self(engine.finalize())
            }

            /// Returns a hash engine that is ready to be used for data.
            pub fn engine() -> HashEngine { HashEngine::new() }

            /// Creates a `Hash` from an `engine`.
            ///
            /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
            pub fn from_engine(engine: HashEngine) -> Self {
                let digest = engine.finalize();
                Self(digest)
            }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this Hash type.
            pub fn from_bytes_ref(bytes: &[u8; $bits / 8]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this Hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; $bits / 8]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bits / 8]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
                if sl.len() != $bits / 8 {
                    Err(crate::FromSliceError { expected: $bits / 8, got: sl.len() })
                } else {
                    let mut ret = [0; $bits / 8];
                    ret.copy_from_slice(sl);
                    Ok(Self::from_byte_array(ret))
                }
            }

            /// Constructs a hash from the underlying byte array.
            pub fn from_byte_array(bytes: [u8; $bits / 8]) -> Self { Self(bytes) }

            /// Returns the underlying byte array.
            pub fn to_byte_array(self) -> [u8; $bits / 8] { self.0 }

            /// Returns a reference to the underlying byte array.
            pub fn as_byte_array(&self) -> &[u8; $bits / 8] { &self.0 }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can
            /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
            /// block's previous blockhash and the coinbase transaction's outpoint txid.
            pub fn all_zeros() -> Self { Self([0x00; $bits / 8]) }
        }

        #[cfg(feature = "schemars")]
        impl schemars::JsonSchema for Hash {
            fn schema_name() -> String { "Hash".to_owned() }

            fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                let len = $bits / 8;
                let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
                schema.string = Some(Box::new(schemars::schema::StringValidation {
                    max_length: Some(len * 2),
                    min_length: Some(len * 2),
                    pattern: Some("[0-9a-fA-F]+".to_owned()),
                }));
                schema.into()
            }
        }

        crate::internal_macros::hash_trait_impls!($bits);
    };
}
pub(crate) use hash_type;
