use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::usize;

use bf_scripts::{execute_script, leaf, EvaluationLeaf, NativeField, TwoPointsLeaf};
use bitcoin::taproot::LeafVersion::TapScript;
use bitcoin::taproot::{
    LeafNode, LeafNodes, NodeInfo, TapTree, TaprootBuilderError, TaprootMerkleBranch,
};
use bitcoin::ScriptBuf;
use p3_util::{log2_strict_usize, reverse_slice_index_bits};

use super::error::BfError;

const NUM_POLY: usize = 1;

pub fn combine_two_nodes(a: NodeInfo, b: NodeInfo) -> Result<NodeInfo, BfError> {
    let parent = NodeInfo::combine(a, b)?;
    Ok(parent)
}

// Todo: use &[F] to replace Vec<F>
pub fn construct_evaluation_leaf_script<const NUM_POLY: usize, F: NativeField>(
    leaf_index: usize,
    x: F,
    y_s: Vec<F>,
) -> Result<ScriptBuf, BfError> {
    let leaf_script: EvaluationLeaf<NUM_POLY, F> = EvaluationLeaf::new(leaf_index, x, y_s);
    let script = leaf_script.leaf_script();
    Ok(script)
}

trait TreeProgram {
    fn into_taptree() -> TapTree;
}
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct GlobalTree {}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct LayerTree {}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct FSTree {}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct FoldingTree<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>(
    pub BasicTree<F, NUM_POLY, LOG_POLY_POINTS>,
);

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>
    FoldingTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    fn new() -> Self {
        Self(BasicTree::new())
    }

    // fn add_leaf(&mut self,leaf: VerifyFoldingLeaf<>){
    //     self.0.add_leaf(leaf_script);
    // }
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> Deref
    for FoldingTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    type Target = BasicTree<F, NUM_POLY, LOG_POLY_POINTS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// =============== Polycommitment Tree ===============
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct PolyCommitTree<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>(
    pub BasicTree<F, NUM_POLY, LOG_POLY_POINTS>,
);

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>
    PolyCommitTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    pub fn new() -> Self {
        Self(BasicTree::new())
    }

    pub fn commit_poly(&mut self, evaluations: Vec<F>) {
        let poly_points = evaluations.len();
        let evas = Polynomials::new_eva_poly(
            evaluations,
            F::sub_group(log2_strict_usize(poly_points)),
            PolynomialType::Eva,
        );

        for i in 0..evas.values.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                evas.points[i],
                vec![evas.values[i].clone()],
            )
            .unwrap();
            self.0.add_leaf(leaf_script);
        }

        self.0.finalize();
    }

    pub fn commit_rev_points(&mut self, evaluations: Vec<F>, width: usize) {
        let poly_points = evaluations.len();
        let mut subgroup = F::sub_group(log2_strict_usize(poly_points));
        let mut leaf_indexs: Vec<usize> = (0..poly_points).into_iter().collect();
        reverse_slice_index_bits(&mut subgroup);
        reverse_slice_index_bits(&mut leaf_indexs);

        for i in (0..poly_points).into_iter().step_by(width) {
            let leaf = TwoPointsLeaf::new(
                leaf_indexs[i],
                leaf_indexs[i + 1],
                subgroup[i],
                evaluations[i],
                subgroup[i + 1],
                evaluations[i + 1],
            );
            self.0.add_leaf(leaf.commit_script());
        }

        self.0.finalize();
    }
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> Deref
    for PolyCommitTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    type Target = BasicTree<F, NUM_POLY, LOG_POLY_POINTS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> DerefMut
    for PolyCommitTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct BasicTree<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize> {
    root_node: Option<NodeInfo>,
    tree_builder: TreeBuilder<LOG_POLY_POINTS>,
    _maker: PhantomData<F>,
}

impl<F: NativeField, const NUM_POLY: usize, const LOG_POLY_POINTS: usize>
    BasicTree<F, NUM_POLY, LOG_POLY_POINTS>
{
    pub fn new() -> Self {
        Self {
            root_node: None,
            tree_builder: TreeBuilder::new(),
            _maker: PhantomData::<F>,
        }
    }

    pub fn add_leaf(&mut self, leaf_script: ScriptBuf) {
        self.tree_builder.add_leaf(leaf_script);
    }

    pub fn add_leafs(&mut self, leaf_scripts: Vec<ScriptBuf>) {
        for leaf_script in leaf_scripts {
            self.tree_builder.add_leaf(leaf_script);
        }
    }

    pub fn isfinalize(&self) -> bool {
        match self.root_node {
            Some(_) => true,
            None => false,
        }
    }

    pub fn root(&self) -> &NodeInfo {
        assert!(self.isfinalize());
        let root = self.root_node.as_ref().unwrap();
        root
    }

    pub fn finalize(&mut self) {
        self.root_node = Some(self.tree_builder.root());
    }

    pub fn leaves(&self) -> LeafNodes {
        self.isfinalize();
        let nodes = self.root_node.as_ref().unwrap().leaf_nodes();
        nodes
    }

    pub fn get_leaf_merkle_path(&self, index: usize) -> Option<&TaprootMerkleBranch> {
        if let Some(leaf) = self.leaves().nth(index) {
            Some(leaf.merkle_branch())
        } else {
            None
        }
    }

    pub fn get_leaf(&self, index: usize) -> Option<&LeafNode> {
        self.leaves().nth(index)
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TreeBuilder<const LOG_N: usize> {
    leaves: Vec<NodeInfo>,
}

impl<const LOG_N: usize> TreeBuilder<LOG_N> {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn add_leaf(&mut self, leaf_script: ScriptBuf) {
        self.leaves
            .push(NodeInfo::new_leaf_with_ver(leaf_script, TapScript));
    }

    pub fn root(&mut self) -> NodeInfo {
        assert!(self.leaves.len() as u32 == 2u32.pow(LOG_N as u32));
        for i in 0..LOG_N {
            self.build_layer((LOG_N - i) as u32);
        }
        assert!(self.leaves.len() == 1);
        self.leaves[0].clone()
    }

    fn build_layer(&mut self, depth: u32) {
        let nodes_len = self.leaves.len();
        assert!(nodes_len as u32 == 2u32.pow(depth));
        for i in (0..nodes_len).step_by(2) {
            self.leaves[i / 2] =
                NodeInfo::combine(self.leaves[i].clone(), self.leaves[i + 1].clone()).unwrap();
        }
        self.leaves.truncate(nodes_len / 2);
    }
}

#[derive(PartialEq)]
enum PolynomialType {
    Eva,
    Coeff,
}
struct Polynomials<F: NativeField> {
    values: Vec<F>,
    points: Vec<F>, // only for evaluations
    style: PolynomialType,
}

impl<F: NativeField> Polynomials<F> {
    pub fn new(values: Vec<F>, style: PolynomialType) -> Self {
        Self {
            values,
            points: Vec::new(),
            style,
        }
    }

    pub fn new_eva_poly(values: Vec<F>, points: Vec<F>, style: PolynomialType) -> Self {
        Self {
            values,
            points,
            style,
        }
    }

    fn convert_to_evals_at_subgroup(&self) -> Self {
        assert!(self.style == PolynomialType::Coeff);
        let subgroup_bits = log2_strict_usize(self.values.len());
        let subgroup = F::sub_group(subgroup_bits);
        let mut evals = Vec::new();
        for i in 0..subgroup.len() {
            let point = subgroup[i];
            let result = self
                .values
                .iter()
                .fold(F::zero(), |acc, item| acc + *item * point.exp_u64(i as u64));
            evals.push(result);
        }
        assert_eq!(subgroup.len(), evals.len());
        Self::new_eva_poly(evals, subgroup, PolynomialType::Eva)
    }

    fn values(&self) -> &Vec<F> {
        &self.values
    }

    fn points(&self) -> &Vec<F> {
        assert!(self.style == PolynomialType::Eva);
        &self.points
    }
}

mod tests {

    use alloc::vec;

    use p3_field::AbstractField;
    use p3_interpolation::interpolate_subgroup;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    #[test]
    fn test_tree_builder() {
        type F = BabyBear;
        const DEPTH: usize = 3;
        let mut coeffs1: Vec<F> = Vec::with_capacity(2u32.pow(DEPTH as u32) as usize);
        for i in 0..2u32.pow(DEPTH as u32) {
            coeffs1.push(F::from_canonical_u32(i));
        }
        let poly1 = Polynomials::new(coeffs1, PolynomialType::Coeff);
        let eva_poly1 = poly1.convert_to_evals_at_subgroup();
        let evas1 = eva_poly1.values();

        let mut tb = TreeBuilder::<DEPTH>::new();

        for i in 0..evas1.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly1.points[i],
                vec![evas1[i].clone()],
            )
            .unwrap();
            tb.add_leaf(leaf_script);
        }

        let root_node = tb.root();
        // assert!(root_node.leaf_nodes().len()==8);
    }
    #[test]
    fn test_interpolate_subgroup() {
        // x^2 + 2 x + 3
        type F = BabyBear;
        let evals = [
            6, 886605102, 1443543107, 708307799, 2, 556938009, 569722818, 1874680944,
        ]
        .map(F::from_canonical_u32);
        let evals_mat = RowMajorMatrix::new(evals.to_vec(), 1);

        let point = F::from_canonical_u32(100);
        let result = interpolate_subgroup(&evals_mat, point);
        assert_eq!(result, vec![F::from_canonical_u32(10203)]);

        let coeffs1: Vec<BabyBear> = vec![
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(4),
        ];
        let poly1 = Polynomials::new(coeffs1, PolynomialType::Coeff);
        let eva_poly1 = poly1.convert_to_evals_at_subgroup();
        let evas1 = eva_poly1.values();

        let mut field_taptree_1 = PolyCommitTree::<BabyBear, 1, 3>::new();

        for i in 0..evas1.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly1.points[i],
                vec![evas1[i].clone()],
            )
            .unwrap();
            field_taptree_1.add_leaf(leaf_script);
        }

        let coeffs2: Vec<BabyBear> = vec![
            BabyBear::from_canonical_u32(4),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(1),
        ];
        let poly2 = Polynomials::new(coeffs2, PolynomialType::Coeff);
        let eva_poly2 = poly2.convert_to_evals_at_subgroup();
        let evas2 = eva_poly2.values();
        assert!(evas2.len() == 4);

        let mut field_taptree_2 = PolyCommitTree::<BabyBear, 1, 3>::new();

        for i in 0..evas2.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly2.points[i],
                vec![evas2[i].clone()],
            )
            .unwrap();
            field_taptree_2.add_leaf(leaf_script);
        }

        let new_node = combine_two_nodes(
            field_taptree_1.root().clone(),
            field_taptree_2.root().clone(),
        )
        .unwrap();
    }
}
