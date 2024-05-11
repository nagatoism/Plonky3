use alloc::vec::Vec;
use core::marker::PhantomData;
use core::usize;

use bf_scripts::BfBaseField;
use bitcoin::hashes::Hash as Bitcoin_HASH;
use bitcoin::TapNodeHash;
use p3_commit::{DirectMmcs, Mmcs};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Dimensions, Matrix};
use p3_util::log2_strict_usize;

use super::error::BfError;
use crate::taptree::PolyCommitTree;
use crate::BfCommitPhaseProofStep;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TapTreeMmcs<F, const DIGEST_ELEMS: usize> {
    _marker: PhantomData<F>,
}

impl<F, const DIGEST_ELEMS: usize> TapTreeMmcs<F, DIGEST_ELEMS> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
impl<F: BfBaseField, const DIGEST_ELEMS: usize> Mmcs<F> for TapTreeMmcs<F, DIGEST_ELEMS> {
    type ProverData = PolyCommitTree<1>;
    type Proof = BfCommitPhaseProofStep;
    type Commitment = [u8; 32];
    type Error = BfError;
    type Mat<'a> = RowMajorMatrixView<'a, F>;

    fn open_batch(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<1>,
    ) -> (Vec<Vec<F>>, Self::Proof) {
        unimplemented!()
    }

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
        let root_node = TapNodeHash::from_byte_array(root.clone());
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

    fn get_matrices<'a>(&'a self, prover_data: &'a Self::ProverData) -> Vec<Self::Mat<'a>> {
        unimplemented!();
    }

    fn get_max_height(&self, prover_data: &Self::ProverData) -> usize {
        unimplemented!();
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opened_values: &[Vec<F>],
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        unimplemented!();
    }
}

impl<F, const DIGEST_ELEMS: usize> DirectMmcs<F> for TapTreeMmcs<F, DIGEST_ELEMS>
where
    F: BfBaseField,
{
    fn commit(&self, inputs: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        let log_leaves = log2_strict_usize(inputs[0].height());
        let mut tree = PolyCommitTree::<1>::new(log_leaves);

        tree.commit_rev_points(inputs[0].values.clone(), inputs[0].width);
        let root = tree.root().clone();
        (root.node_hash().as_byte_array().clone(), tree)
    }
}
