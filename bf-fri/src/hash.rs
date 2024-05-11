use core::array;
use core::marker::PhantomData;

use alloc::vec::Vec;
use bf_scripts::{BaseCanCommit, BfBaseField};
use bitcoin::{TapNodeHash,hashes::Hash as Bitcoin_HASH};
use p3_commit::{DirectMmcs, Mmcs};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Dimensions, Matrix};
use p3_util::log2_strict_usize;
use bf_scripts::BabyBear;
use p3_symmetric::Hash as HASH;


#[derive(Clone, Copy)]
pub struct NodeHash<F, W, const DIGEST_ELEMS: usize>{
    pub tap_node_hash: TapNodeHash,
    _marker: PhantomData<(F,W)>,
}   
impl<F, W:Default, const DIGEST_ELEMS: usize> From<TapNodeHash> for NodeHash<F,W,DIGEST_ELEMS> {
    fn from(tap_node_hash: TapNodeHash) -> Self {
        Self{
            tap_node_hash,
            _marker:PhantomData,
        }
    }
}

impl<F, W, const DIGEST_ELEMS: usize> Into<TapNodeHash> for NodeHash<F,W,DIGEST_ELEMS> {
    fn into(self) -> TapNodeHash {
        self.tap_node_hash
    }
}


impl<F, W:AbstractField + PrimeField32, const DIGEST_ELEMS: usize> NodeHash<F,W,DIGEST_ELEMS> {
    fn bytes_len(&self) -> usize{
        self.tap_node_hash.as_byte_array().len()
    }

    fn to_u32_vec(&self) ->Vec<u32> {
        let hash_byte = self.tap_node_hash.as_byte_array();
        let mut u32s = Vec::new();
        for chunk in hash_byte.chunks(4){
            let new_u32 = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            u32s.push(new_u32);
        }
        u32s
    }

    fn to_u32_array(&self) -> [u32;DIGEST_ELEMS] {
        let hash_byte = self.tap_node_hash.as_byte_array();
        assert_eq!(self.bytes_len()/4 , DIGEST_ELEMS);

        let mut u32s = [0;DIGEST_ELEMS];
        let mut index = 0;

        for chunk in hash_byte.chunks(4){
            let new_u32 = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            u32s[index] = new_u32;
            index+=1;
        }
        u32s
    }

    fn from_u32_array(array: [u32;DIGEST_ELEMS]) -> Self {
        let mut bytes = Vec::new();
        for u32 in array.iter(){
            bytes.extend_from_slice(&u32.to_be_bytes());
        }
        let hash = TapNodeHash::from_slice(&bytes).unwrap();
        Self{
            tap_node_hash: hash,
            _marker: PhantomData,
        }
    }

    fn from_u32_vec(u32s: Vec<u32>) -> Self {
        let mut bytes = Vec::new();
        for u32 in u32s {
            bytes.extend_from_slice(&u32.to_be_bytes());
        }
        let hash = TapNodeHash::from_slice(&bytes).unwrap();
        Self{
            tap_node_hash: hash,
            _marker: PhantomData,
        }
    }

    fn to_w_array(&self) -> [W;DIGEST_ELEMS] {
        let u32_array: [u32; DIGEST_ELEMS] = self.to_u32_array();
        let mut w_array: [W; DIGEST_ELEMS] =array::from_fn(|v|W::zero()); // 需要W类型实现Default trait

        for (i, elem) in u32_array.iter().enumerate() {
            w_array[i] = W::from_canonical_u32(*elem);
        }

        w_array
    }

    pub fn to_hash(&self) -> HASH<F,W,DIGEST_ELEMS> {
        HASH::from(self.to_w_array())
    }

    pub fn from_hash(h: HASH<F,W,DIGEST_ELEMS>) -> Self {
        let mut u32_array = [0; DIGEST_ELEMS];
        for (i, elem) in h.into_iter().enumerate() {
            u32_array[i] = elem.as_canonical_u32();
        }
        Self::from_u32_array(u32_array)
    }

}