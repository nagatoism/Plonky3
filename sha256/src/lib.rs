//! The sha256 hash function from bitcoin.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use p3_symmetric::CryptographicHasher;
use bitcoin::hashes::{sha256::HashEngine, HashEngine as Hasher};
use bitcoin_hashes::Hash;
/// The Sha256 hash function.
#[derive(Clone)]
struct Sha256;

impl CryptographicHasher<u8, [u8; 32]> for Sha256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let input = input.into_iter().collect::<Vec<_>>();
        self.hash_iter_slices([input.as_slice()])
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = HashEngine::default();
        for chunk in input.into_iter() {
            bitcoin::hashes::HashEngine::input(&mut hasher, &chunk);
        }
        hasher.midstate().to_byte_array()
      
    }
    
    fn hash_slice(&self, input: &[u8]) -> [u8; 32] {
        self.hash_iter_slices(core::iter::once(input))
    }
    
    fn hash_item(&self, input: u8) -> [u8; 32] {
        self.hash_slice(&[input])
    }
}
