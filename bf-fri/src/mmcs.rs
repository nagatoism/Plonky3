
use alloc::vec::Vec;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Matrix, Dimensions};
use core::marker::PhantomData;
use core::usize;

use bf_scripts::{NativeField};
use bitcoin::taproot::{
    LeafNode, NodeInfo, TaprootBuilderError, TaprootMerkleBranch
};
use bitcoin::{ScriptBuf};
use p3_util::log2_strict_usize;
use p3_commit::{DirectMmcs, Mmcs};

use crate::prover::{self, BF_MATRIX_WIDTH};
use crate::taptree::PolyCommitTree;
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct PolyCommitTreeMmcs<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> {
    pub(crate) tree: PolyCommitTree<F,NUM_POLY,LOG_POLY_POINTS>,
    pub(crate) _phantom: PhantomData<F>,
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> Mmcs<F> for PolyCommitTreeMmcs<F,NUM_POLY,LOG_POLY_POINTS>{
    type ProverData = PolyCommitTree<F,NUM_POLY,LOG_POLY_POINTS>;
    type Commitment = NodeInfo;
    type Proof = TaprootMerkleBranch;
    type Error = TaprootBuilderError;
    type Mat<'a> = RowMajorMatrixView<'a,F>;
    type LeafType = LeafNode;

    fn open_batch(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<F,NUM_POLY,LOG_POLY_POINTS>,
    ) -> (Vec<Vec<LeafNode>>, Self::Proof) {

        let opening_leaf = prover_data.get_leaf(index).unwrap().clone();
        let merkle_branch = prover_data.get_leaf_merkle_path(index).unwrap().clone();
        let mut opening_leafs = Vec::new();
        opening_leafs.push(opening_leaf);
        let mut wrap_vec = Vec::new();
        wrap_vec.push(opening_leafs);
        (wrap_vec,merkle_branch)
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
    ) -> Result<(), Self::Error>{
        unimplemented!();
    }
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> DirectMmcs<LeafNode> for PolyCommitTreeMmcs<F,NUM_POLY,LOG_POLY_POINTS>{
    fn commit(&self, inputs: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        assert_eq!(inputs.len(), 1);
        let mut tree = PolyCommitTree::<F,NUM_POLY,LOG_POLY_POINTS>::new();

        // todo: support matrix width more than 1
        // we just consider the matrix width is one here which means that the PACK_FIELD is the same as the FIELD
        inputs.iter().for_each(|matrix| assert_eq!(matrix.width(),BF_MATRIX_WIDTH));

        tree.commit_poly(inputs[0].values.clone());
        let root = tree.root().clone();
        (root,tree)
    }
}
