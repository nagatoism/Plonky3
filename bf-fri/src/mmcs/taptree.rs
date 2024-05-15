use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::usize;

use bf_scripts::{BfField, EvaluationLeaf, PointsLeaf};
use bitcoin::taproot::LeafVersion::TapScript;
use bitcoin::taproot::{LeafNode, LeafNodes, NodeInfo, TaprootMerkleBranch};
use bitcoin::{ScriptBuf, TapNodeHash};
use p3_util::{log2_strict_usize, reverse_slice_index_bits};

use crate::error::BfError;

pub fn combine_two_nodes(a: NodeInfo, b: NodeInfo) -> Result<NodeInfo, BfError> {
    let parent = NodeInfo::combine(a, b)?;
    Ok(parent)
}

// Todo: use &[F] to replace Vec<F>
pub fn construct_evaluation_leaf_script<const NUM_POLY: usize, F: BfField>(
    leaf_index: usize,
    x: F,
    y_s: Vec<F>,
) -> Result<ScriptBuf, BfError> {
    let leaf_script: EvaluationLeaf<NUM_POLY, F> = EvaluationLeaf::new(leaf_index, x, y_s);
    let script = leaf_script.leaf_script();
    Ok(script)
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct GlobalTree {}

// =============== Polycommitment Tree ===============

#[derive(Clone, Debug)]
pub struct PolyCommitTree<F: BfField, const NUM_POLY: usize> {
    pub tree: BasicTree<NUM_POLY>,
    pub points_leafs: Vec<PointsLeaf<F>>,
}

impl<const NUM_POLY: usize, F: BfField> PolyCommitTree<F, NUM_POLY> {
    pub fn new(log_poly_points: usize) -> Self {
        Self {
            tree: BasicTree::<NUM_POLY>::new(log_poly_points),
            points_leafs: Vec::new(),
        }
    }

    pub fn commit_points(&mut self, evaluations: Vec<F>) {
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
            self.tree.add_leaf(leaf_script);
        }

        self.tree.finalize();
    }

    pub fn commit_rev_points(&mut self, evaluations: Vec<F>, width: usize) {
        let poly_points = evaluations.len();
        let mut subgroup = F::sub_group(log2_strict_usize(poly_points));
        let leaf_indexs: Vec<usize> = (0..poly_points).into_iter().collect();
        reverse_slice_index_bits(&mut subgroup);

        for i in (0..poly_points).into_iter().step_by(width) {
            let leaf = PointsLeaf::new(
                leaf_indexs[i],
                leaf_indexs[i + 1],
                subgroup[i],
                evaluations[i],
                subgroup[i + 1],
                evaluations[i + 1],
            );
            self.add_leaf(&leaf);
        }

        self.tree.finalize();
    }

    pub fn add_leaf(&mut self, leaf: &PointsLeaf<F>) {
        self.points_leafs.push(leaf.clone());
        self.tree
            .add_leaf(leaf.recover_points_euqal_to_commited_point());
    }

    pub fn get_points_leafs(&self) -> &[PointsLeaf<F>] {
        &self.points_leafs
    }

    pub fn get_points_leaf(&self, index: usize) -> &PointsLeaf<F> {
        &self.points_leafs[index]
    }
}

impl<const NUM_POLY: usize, F: BfField> Deref for PolyCommitTree<F, NUM_POLY> {
    type Target = BasicTree<NUM_POLY>;

    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

impl<const NUM_POLY: usize, F: BfField> DerefMut for PolyCommitTree<F, NUM_POLY> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tree
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct BasicTree<const NUM_POLY: usize> {
    root_node: Option<NodeInfo>,
    leaf_count: u64,
    tree_builder: Option<TreeBuilder>,
}

impl<const NUM_POLY: usize> BasicTree<NUM_POLY> {
    pub fn new(log_poly_points: usize) -> Self {
        Self {
            root_node: None,
            leaf_count: 0,
            tree_builder: Some(TreeBuilder::new(log_poly_points)),
        }
    }

    pub fn add_leaf(&mut self, leaf_script: ScriptBuf) {
        self.leaf_count += 1;
        self.mut_tree_builder().add_leaf(leaf_script);
    }

    pub fn add_leafs(&mut self, leaf_scripts: Vec<ScriptBuf>) {
        for leaf_script in leaf_scripts {
            self.mut_tree_builder().add_leaf(leaf_script);
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

    pub fn tree_builder(&self) -> &TreeBuilder {
        let builder = self.tree_builder.as_ref().unwrap();
        builder
    }

    pub fn mut_tree_builder(&mut self) -> &mut TreeBuilder {
        let builder = self.tree_builder.as_mut().unwrap();
        builder
    }

    pub fn combine_tree<const NEXT_LOG_POLY_POINTS: usize>(self, other: Self) -> Self {
        let combined_tree = combine_two_nodes(self.root().clone(), other.root().clone()).unwrap();
        Self {
            root_node: Some(combined_tree),
            leaf_count: self.leaf_count() + other.leaf_count(),
            tree_builder: None,
        }
    }

    pub fn finalize(&mut self) {
        self.root_node = Some(self.tree_builder.as_mut().unwrap().root());
        self.tree_builder = None;
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn leaves(&self) -> LeafNodes {
        assert!(self.isfinalize());
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

    pub fn verify_inclusion_by_index(&self, index: usize) -> bool {
        let leaf = self.get_leaf(index).unwrap();
        let path = self.get_leaf_merkle_path(index).unwrap();
        let mut first_node_hash = TapNodeHash::from_node_hashes(leaf.node_hash(), path[0]);
        path[1..].into_iter().for_each(|sibling_node| {
            first_node_hash = TapNodeHash::from_node_hashes(first_node_hash, *sibling_node);
        });

        first_node_hash == self.root().node_hash()
    }
}

impl<const NUM_POLY: usize> From<NodeInfo> for BasicTree<NUM_POLY> {
    fn from(value: NodeInfo) -> Self {
        Self {
            root_node: Some(value),
            leaf_count: 0,
            tree_builder: None,
        }
    }
}

pub fn verify_inclusion(root: TapNodeHash, leaf: &LeafNode) -> bool {
    let path = leaf.merkle_branch();
    let mut first_node_hash = TapNodeHash::from_node_hashes(leaf.node_hash(), path[0]);
    path[1..].into_iter().for_each(|sibling_node| {
        first_node_hash = TapNodeHash::from_node_hashes(first_node_hash, *sibling_node);
    });

    first_node_hash == root
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TreeBuilder {
    log_leaves: usize,
    leaves: Vec<NodeInfo>,
}

impl TreeBuilder {
    pub fn new(log_n: usize) -> Self {
        Self {
            log_leaves: log_n,
            leaves: Vec::new(),
        }
    }

    pub fn log_leaves(&self) -> usize {
        self.log_leaves
    }

    pub fn add_leaf(&mut self, leaf_script: ScriptBuf) {
        self.leaves
            .push(NodeInfo::new_leaf_with_ver(leaf_script, TapScript));
    }

    pub fn root(&mut self) -> NodeInfo {
        assert!(self.leaves.len() as u32 == 2u32.pow(self.log_leaves as u32));
        for i in 0..self.log_leaves {
            self.build_layer((self.log_leaves - i) as u32);
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

    pub fn root_and_leaf_order(&mut self) -> NodeInfo {
        let mut order = Vec::new();
        let nodes_len = self.leaves.len();
        for i in 0..nodes_len{
            order.push(i);
        }

        assert!(self.leaves.len() as u32 == 2u32.pow(self.log_leaves as u32));
        for i in 0..self.log_leaves {
            self.build_layer_with_order((self.log_leaves - i) as u32,&mut order);
        }
        assert!(self.leaves.len() == 1);
        self.leaves[0].clone()
    }

    fn build_layer_with_order(&mut self, depth: u32, &mut order:&mut Vec<usize>){
        let chunk_size:usize = 1 << (self.log_leaves - depth as usize);
        let left_first = false;
        let nodes_len = self.leaves.len();
        assert!(nodes_len as u32 == 2u32.pow(depth));
        for i in (0..nodes_len).step_by(2) {
            (self.leaves[i / 2],left_first) =
                NodeInfo::combine_with_order(self.leaves[i].clone(), self.leaves[i + 1].clone()).unwrap();
            if !left_first{
                let start = i * chunk_size;
                let mid = (i + 1) * chunk_size;
                let end = (i + 2) * chunk_size;

                order[start..mid].swap_with_slice(&mut order[mid..end]);
            }
        }
        self.leaves.truncate(nodes_len / 2);
    }

}

#[derive(PartialEq)]
enum PolynomialType {
    Eva,
    Coeff,
}
struct Polynomials<F: BfField> {
    values: Vec<F>,
    points: Vec<F>, // only for evaluations
    style: PolynomialType,
}

impl<F: BfField> Polynomials<F> {
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

    use bf_scripts::BabyBear;
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

        let mut tb = TreeBuilder::new(DEPTH);

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

        let mut field_taptree_1 = PolyCommitTree::<BabyBear, 1>::new(2);

        for i in 0..evas1.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly1.points[i],
                vec![evas1[i].clone()],
            )
            .unwrap();
            field_taptree_1.tree.add_leaf(leaf_script);
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

        field_taptree_1.finalize();

        (0..4).into_iter().for_each(|index| {
            let inclusion = field_taptree_1.verify_inclusion_by_index(index);
            assert_eq!(inclusion, true);
            let success = verify_inclusion(
                field_taptree_1.root().node_hash(),
                field_taptree_1.get_leaf(index).unwrap(),
            );
            assert_eq!(success, true);
        });

        let mut field_taptree_2 = PolyCommitTree::<BabyBear, 1>::new(2);

        for i in 0..evas2.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly2.points[i],
                vec![evas2[i].clone()],
            )
            .unwrap();
            field_taptree_2.tree.add_leaf(leaf_script);
        }

        field_taptree_2.finalize();
        (0..4).into_iter().for_each(|index| {
            let inclusion = field_taptree_2.verify_inclusion_by_index(index);
            assert_eq!(inclusion, true);
        });

        let combined_tree: BasicTree<1> = BasicTree::<1>::from(
            combine_two_nodes(
                field_taptree_1.root().clone(),
                field_taptree_2.root().clone(),
            )
            .unwrap(),
        );

        (0..8).into_iter().for_each(|index| {
            let inclusion = combined_tree.verify_inclusion_by_index(index);
            assert_eq!(inclusion, true);
        });

        assert_eq!(
            combined_tree.get_leaf(0).unwrap().leaf_hash(),
            field_taptree_1.get_leaf(0).unwrap().leaf_hash()
        );
    }

    #[test]
    fn test_poly_add_leaf() {
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
            BabyBear::from_canonical_u32(4),
            BabyBear::from_canonical_u32(4),
            BabyBear::from_canonical_u32(4),
            BabyBear::from_canonical_u32(4),
        ];

        let poly1 = Polynomials::new(coeffs1, PolynomialType::Coeff);
        let eva_poly1 = poly1.convert_to_evals_at_subgroup();
        let evas1 = eva_poly1.values();

        let mut poly_taptree = PolyCommitTree::<BabyBear, 1>::new(2);

        poly_taptree.commit_rev_points(evas1.clone(),2);

        (0..4).into_iter().for_each(|index| {
            let leaf = poly_taptree.get_leaf(index).unwrap();
            let script = leaf.leaf().as_script().unwrap();
            let points_leaf = poly_taptree.get_points_leaf(index);
            assert_eq!(points_leaf.recover_points_euqal_to_commited_point(),*script.0);
            let success = verify_inclusion(
                poly_taptree.root().node_hash(),
                leaf,
            );
            assert_eq!(success, true);
        });


    }
}
