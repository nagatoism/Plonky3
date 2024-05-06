use alloc::ffi::NulError;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;
use core::usize;

use bf_scripts::{BfBaseField, BfExtensionField, BfField};
use bitcoin::io::Error;
use bitcoin::taproot::{LeafNode, NodeInfo, TaprootBuilderError, TaprootMerkleBranch};
use bitcoin::{ScriptBuf, TapNodeHash};
use p3_commit::{DirectMmcs, Mmcs};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Dimensions, Matrix, MatrixRowSlices};
use p3_util::log2_strict_usize;

use super::error::BfError;
use crate::prover::{self, BF_MATRIX_WIDTH, DEFAULT_MATRIX_WIDTH};
use crate::taptree::PolyCommitTree;
use crate::BfCommitPhaseProofStep;
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TapTreeMmcs<F: BfBaseField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> {
    pub(crate) tree: PolyCommitTree<NUM_POLY, LOG_POLY_POINTS>,
    _marker: PhantomData<F>,
}

impl<F: BfBaseField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>
    TapTreeMmcs<F, NUM_POLY, LOG_POLY_POINTS>
{
    pub fn new() -> Self {
        Self {
            tree: PolyCommitTree::new(),
            _marker: PhantomData,
        }
    }
}
impl<F: BfBaseField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> Mmcs<F>
    for TapTreeMmcs<F, NUM_POLY, LOG_POLY_POINTS>
{
    type ProverData = PolyCommitTree<NUM_POLY, LOG_POLY_POINTS>;
    type Proof = BfCommitPhaseProofStep;
    type Commitment = TapNodeHash;
    type Error = BfError;
    type Mat<'a> = RowMajorMatrixView<'a, F>;

    fn open_batch(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<NUM_POLY, LOG_POLY_POINTS>,
    ) -> (Vec<Vec<F>>, Self::Proof) {
        unimplemented!()
    }

    fn open_taptree(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<NUM_POLY, LOG_POLY_POINTS>,
    ) -> Self::Proof {
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
        let mut first_node_hash = TapNodeHash::from_node_hashes(*root, proof.merkle_branch[0]);
        proof.merkle_branch[1..]
            .into_iter()
            .for_each(|sibling_node| {
                first_node_hash = TapNodeHash::from_node_hashes(first_node_hash, *sibling_node);
            });
        if root.clone() == first_node_hash {
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

impl<F: BfBaseField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> DirectMmcs<F>
    for TapTreeMmcs<F, NUM_POLY, LOG_POLY_POINTS>
{
    fn commit(&self, inputs: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].width, DEFAULT_MATRIX_WIDTH);

        let mut tree = PolyCommitTree::<NUM_POLY, LOG_POLY_POINTS>::new();

        tree.commit_rev_points(inputs[0].values.clone(), inputs[0].width);
        let root = tree.root().clone();
        (root.node_hash(), tree)
    }
}
