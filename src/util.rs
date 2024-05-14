// SPDX-License-Identifier: CC0-1.0

/// Adds `AsRef` implementation to a given type `$ty`.
#[macro_export]
macro_rules! as_ref_impl(
    ($ty:ident) => (
        $crate::as_ref_impl!($ty, );
    );
    ($ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*>  {
            fn as_ref(&self) -> &[u8] {
                &self[..]
            }
        }
    )
);

macro_rules! engine_input_impl(
    ($n:literal) => (
        #[cfg(not(hashes_fuzz))]
        fn input(&mut self, mut inp: &[u8]) {
            while !inp.is_empty() {
                let buf_idx = self.length % <Self as crate::HashEngine>::BLOCK_SIZE;
                let rem_len = <Self as crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = cmp::min(rem_len, inp.len());

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
