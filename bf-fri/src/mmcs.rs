
use alloc::vec::Vec;
use p3_field::{AbstractField, PackedField, PackedValue, PrimeField32};
use serde::{Deserialize, Serialize};
use core::marker::PhantomData;
use core::usize;

use bf_scripts::{BaseCanCommit, BfBaseField};
use bitcoin::{TapNodeHash,hashes::Hash as Bitcoin_HASH};
use p3_commit::{DirectMmcs, Mmcs};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::{Dimensions, Matrix};
use p3_util::log2_strict_usize;
use p3_symmetric::Hash;
use bf_scripts::BabyBear;

use super::error::BfError;
use crate::hash::NodeHash;
use crate::prover::{self, BF_MATRIX_WIDTH, DEFAULT_MATRIX_WIDTH};
use crate::taptree::PolyCommitTree;
use crate::BfCommitPhaseProofStep;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TapTreeMmcs<P,PW, const DIGEST_ELEMS: usize> {
    _marker: PhantomData<(P,PW)>,
}

impl<P,PW, const DIGEST_ELEMS: usize>
    TapTreeMmcs<P,PW, DIGEST_ELEMS> where 
{
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
impl<P,PW, const DIGEST_ELEMS: usize> Mmcs<P::Scalar>
    for TapTreeMmcs<P,PW, DIGEST_ELEMS> 
where 
    P: PackedField,
    PW: PackedValue,
    PW::Value: Eq,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
    <PW as PackedValue>::Value: PrimeField32,
{
    type ProverData = PolyCommitTree<DIGEST_ELEMS>;
    type Proof = BfCommitPhaseProofStep;
    type Commitment = Hash<P::Scalar,PW::Value,DIGEST_ELEMS>;
    type Error = BfError;
    type Mat<'a> = RowMajorMatrixView<'a, P::Scalar>;

    fn open_batch(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<DIGEST_ELEMS>,
    ) -> (Vec<Vec<P::Scalar>>, Self::Proof) {
        unimplemented!()
    }

    fn open_taptree(
        &self,
        index: usize,
        prover_data: &PolyCommitTree<DIGEST_ELEMS>,
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
        let root_node = NodeHash::from_hash(root.clone());
        let mut first_node_hash = TapNodeHash::from_node_hashes(root_node.tap_node_hash, proof.merkle_branch[0]);
        proof.merkle_branch[1..]
            .into_iter()
            .for_each(|sibling_node| {
                first_node_hash = TapNodeHash::from_node_hashes(first_node_hash, *sibling_node);
            });
        if root_node.tap_node_hash == first_node_hash {
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
        opened_values: &[Vec<P::Scalar>],
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        unimplemented!();
    }
}

impl<P,PW, const DIGEST_ELEMS: usize> DirectMmcs<P::Scalar>
    for TapTreeMmcs<P,PW, DIGEST_ELEMS>
where
    P: PackedField,
    PW: PackedValue,
    PW::Value: Eq,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
    <PW as PackedValue>::Value: PrimeField32,
    P::Scalar:BfBaseField,
{
    fn commit(&self, inputs: Vec<RowMajorMatrix<P::Scalar>>) -> (Self::Commitment, Self::ProverData) {
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].width, DEFAULT_MATRIX_WIDTH);

        let log_leaves = log2_strict_usize(inputs[0].height());
        let mut tree = PolyCommitTree::<DIGEST_ELEMS>::new(log_leaves);

        tree.commit_rev_points(inputs[0].values.clone(), inputs[0].width);
        let root = tree.root().clone();
        let root_hash = NodeHash::<<P as PackedField>::Scalar, <PW as PackedValue>::Value,DIGEST_ELEMS>::from(root.node_hash());
        (root_hash.to_hash(), tree)
    }
}
