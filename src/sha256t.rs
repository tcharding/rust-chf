// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).
//!

/// Defines a new hash type and a pre-tagged hash engine.
#[macro_export]
macro_rules! sha256t_hash_newtype {
    (
        $(#[$($engine_attrs:tt)*])* $engine_vis:vis struct $engine:ident(_) = $constructor:tt($($tag_value:tt)+);
        $(#[$($hash_attrs:tt)*])* $hash_vis:vis struct $hash:ident(_);
    ) => {

        $crate::sha256t_hash_newtype_struct! {
            #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            $engine_vis struct $hash($crate::sha256::Hash);

            $({ $($hash_attrs)* })*
        }

        #[allow(unused)] // Macro user may not need everything here.
        impl $hash {
            /// Length of the hash, in bytes.
            pub const LEN: usize = 32;

            /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
            ///
            /// # Returns
            ///
            /// The digest created by hashing `bytes` with engine's hashing algorithm.
            pub fn hash(bytes: &[u8]) -> Self {
                use $crate::HashEngine as _;
                let mut engine = Self::engine();
                engine.input(bytes);
                Self($crate::sha256::Hash::from_engine(engine.0))
            }

            /// Returns a hash engine that is ready to be used for data.
            pub fn engine() -> $engine {
                use $crate::HashEngine as _;
                $engine::new()
            }

            /// Creates a `Hash` from an `engine`.
            ///
            /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
            pub fn from_engine(engine: $engine) -> Self {
                let inner = $crate::sha256::Hash::from_engine(engine.0);
                Self(inner)
            }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this Hash type.
            // TODO: Check this is right? 
            pub fn from_bytes_ref(bytes: &[u8; 32]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this Hash type.
            // TODO: Check this is right? 
            pub fn from_bytes_mut(bytes: &mut [u8; 32]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
                if sl.len() != 32 {
                    Err(crate::FromSliceError{expected: 32, got: sl.len()})
                } else {
                    let mut ret = [0; 32];
                    ret.copy_from_slice(sl);
                    Ok(Self::from_byte_array(ret))
                }
            }

            /// Constructs a hash from the underlying byte array.
            pub fn from_byte_array(bytes: [u8; 32]) -> Self {
                Self($crate::sha256::Hash::from_byte_array(bytes))
            }

            /// Returns the underlying byte array.
            pub fn to_byte_array(self) -> [u8; 32] { self.0.to_byte_array() }

            /// Returns a reference to the underlying byte array.
            pub fn as_byte_array(&self) -> &[u8; 32] { self.0.as_byte_array() }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can
            /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
            /// block's previous blockhash and the coinbase transaction's outpoint txid.
            pub fn all_zeros() -> Self {
                let inner = $crate::sha256::Hash::all_zeros();
                Self(inner)
            }
        }

        #[cfg(feature = "schemars")] // FIXME: This requires "alloc" as well.
        impl schemars::JsonSchema for Hash {
            fn schema_name() -> String { stringify!($hash).to_owned() } 

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

        impl $crate::_export::_core::fmt::LowerHex for $hash {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl $crate::_export::_core::fmt::UpperHex for $hash {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl $crate::_export::_core::fmt::Display for $hash {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl $crate::_export::_core::fmt::Debug for $hash {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{:#}", self.0)
            }
        }

        $crate::sha256t_hash_newtype_struct! {
            #[derive(Clone)]
            $engine_vis struct $engine($crate::sha256::HashEngine);

            $({ $($engine_attrs)* })*
        }

        impl Default for  $engine {
            fn default() -> $engine {
                const MIDSTATE: ($crate::sha256::Midstate, usize) = $crate::sha256t_hash_newtype_tag_constructor!($constructor, $($tag_value)+);
                #[allow(unused)]
                const _LENGTH_CHECK: () = [(); 1][MIDSTATE.1 % 64];
                let inner = $crate::sha256::HashEngine::from_midstate(MIDSTATE.0, MIDSTATE.1);
                $engine(inner)
            }
        }

        impl crate::HashEngine<32> for $engine {
            type Midstate = $crate::sha256::Midstate;
            const BLOCK_SIZE: usize = $crate::sha256::BLOCK_SIZE;

            #[inline]
            fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }

            #[inline]
            fn input(&mut self, data: &[u8]) { self.0.input(data) }

            #[inline]
            fn finalize(self) -> [u8; 32] { self.0.finalize() }

            #[inline]
            fn midstate(&self) -> $crate::sha256::Midstate { self.0.midstate() }

            #[inline]
            fn from_midstate(midstate: $crate::sha256::Midstate, length: usize) -> Self {
                let inner = $crate::sha256::HashEngine::from_midstate(midstate, length);
                Self(inner)
            }
        }

    }
}

// Generates the struct only (no impls)
//
// This is a separate macro to make it more readable and have a separate interface that allows for
// two groups of type attributes: processed and not-yet-processed ones (think about it like
// computation via recursion). The macro recursively matches unprocessed attributes, popping them
// one at a time and either ignoring them (`hash_newtype`) or appending them to the list of
// processed attributes to be added to the struct.
//
// Once the list of not-yet-processed attributes is empty the struct is generated with processed
// attributes added.
#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_struct {
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($inner:path);) => {
        $(#[$other_attrs])*
        $type_vis struct $newtype($inner);
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($inner:path); { hash_newtype($($ignore:tt)*) } $($type_attrs:tt)*) => {
        $crate::sha256t_hash_newtype_struct! {
            $(#[$other_attrs])*
            $type_vis struct $newtype($field_vis $inner);

            $($type_attrs)*
        }
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($inner:path); { $other_attr:meta } $($type_attrs:tt)*) => {
        $crate::sha256t_hash_newtype_struct! {
            $(#[$other_attrs])*
            #[$other_attr]
            $type_vis struct $newtype($inner);

            $($type_attrs)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_tag_constructor {
    (hash_str, $value:expr) => {
        ($crate::sha256::Midstate::hash_tag($value.as_bytes()), 64)
    };
    (hash_bytes, $value:expr) => {
        ($crate::sha256::Midstate::hash_tag($value), 64)
    };
    (raw, $bytes:expr, $len:expr) => {
        ($crate::sha256::Midstate::from_byte_array($bytes), $len)
    };
}

#[cfg(test)]
mod tests {
    sha256t_hash_newtype! {
        /// Engine to compute SHA256 hash function pre-tagged with "example".
        struct ExampleHashEngine(_) = hash_str("example");

        /// Output of the tagged SHA256 hash function.
        struct ExampleHash(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn example_sha256t() {
        assert_eq!(
            ExampleHash::hash(&[0]).to_string(),
            "25e4ca9ac768deb76e4ccbf71f9042e2d81b64a09ced1c0ff6e80690ac72ecb2",
        );
    }

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    sha256t_hash_newtype! {
        /// Engine to compute SHA256 hash function pre-tagged with "example".
        struct TestHashEngine(_) = raw(TEST_MIDSTATE, 64);

        /// Output of the tagged SHA256 hash function.
        struct TestHash(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_sha256t() {
        assert_eq!(
            TestHash::hash(&[0]).to_string(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829",
        );
    }
}
