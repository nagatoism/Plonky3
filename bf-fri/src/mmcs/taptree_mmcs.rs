use alloc::vec::Vec;
use core::marker::PhantomData;
use core::usize;

use bf_scripts::BfField;
use bitcoin::hashes::Hash as Bitcoin_HASH;
use bitcoin::TapNodeHash;
use p3_field::{u256_to_u32, u32_to_u256, PermutationField, U256, U32};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Dimensions, Matrix};
use p3_util::log2_strict_usize;

use super::bf_mmcs::BFMmcs;
use crate::error::BfError;
use crate::taptree::PolyCommitTree;
use crate::BfCommitPhaseProofStep;

pub type TreeRoot = [U32; ROOT_WIDTH];
pub const ROOT_WIDTH: usize = 8;
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TapTreeMmcs<F> {
    _marker: PhantomData<F>,
}

impl<F> TapTreeMmcs<F> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
impl<F: BfField> BFMmcs<F> for TapTreeMmcs<F> {
    type ProverData = PolyCommitTree<1>;
    type Proof = BfCommitPhaseProofStep;
    type Commitment = TreeRoot;
    type Error = BfError;

    fn open_taptree(&self, index: usize, prover_data: &PolyCommitTree<1>) -> Self::Proof {
        let opening_leaf = prover_data.get_leaf(index).unwrap().clone();
        let merkle_branch = opening_leaf.merkle_branch().clone();
        let leaf = opening_leaf.leaf().clone();
        BfCommitPhaseProofStep {
            leaf_node: leaf,
            merkle_branch: merkle_branch,
        }
    }

    fn verify_taptree(
        &self,
        proof: &Self::Proof,
        root: &Self::Commitment,
    ) -> Result<(), Self::Error> {
        let root_node = TapNodeHash::from_byte_array(u32_to_u256(root.clone()));
        let mut first_node_hash = TapNodeHash::from_node_hashes(root_node, proof.merkle_branch[0]);
        proof.merkle_branch[1..]
            .into_iter()
            .for_each(|sibling_node| {
                first_node_hash = TapNodeHash::from_node_hashes(first_node_hash, *sibling_node);
            });
        if root_node == first_node_hash {
            Ok(())
        } else {
            Err(BfError::InvalidMerkleProof)
        }
    }

    fn commit(&self, inputs: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        let log_leaves = log2_strict_usize(inputs[0].height());
        let mut tree = PolyCommitTree::<1>::new(log_leaves);

        tree.commit_rev_points(inputs[0].values.clone(), inputs[0].width);
        let root: U256 = tree.root().node_hash().as_byte_array().clone();

        (u256_to_u32(root), tree)
    }
}
