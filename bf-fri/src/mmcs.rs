use alloc::vec::Vec;
use core::marker::PhantomData;

use bf_scripts::field::BabyBear;
use bf_scripts::{execute_script, leaf, EvaluationLeaf, NativeField};
use bitcoin::taproot::LeafVersion::TapScript;
use bitcoin::taproot::{NodeInfo, TapLeaf, TapTree, TaprootBuilder, TaprootBuilderError};
use bitcoin::ScriptBuf;
use p3_field::{AbstractField, PrimeField, PrimeField32, TwoAdicField};
use p3_util::log2_strict_usize;

#[derive(Debug)]
pub enum BfError {
    TaprootBuilderError(TaprootBuilderError),
    TaprootError,
    TapLeafError,
    TapTreeError,
    EvaluationLeafError,
    ExecuteScriptError,
}

impl From<TaprootBuilderError> for BfError {
    fn from(error: TaprootBuilderError) -> Self {
        BfError::TaprootBuilderError(error)
    }
}

pub fn combine_two_nodes(a: NodeInfo, b: NodeInfo) -> Result<NodeInfo, BfError> {
    let parent = NodeInfo::combine(a, b)?;
    Ok(parent)
}

#[derive(Clone)]
pub struct FieldTapTreeMMCS<const TREE_HEIGHT: u8, F: NativeField> {
    builder: TaprootBuilder,
    phantom: PhantomData<F>,
}

pub fn construct_evaluation_leaf_script<const NUM_POLY: usize, F: NativeField>(
    leaf_index: usize,
    x: F,
    y_s: Vec<F>,
) -> Result<ScriptBuf, BfError> {
    let leaf_script: EvaluationLeaf<NUM_POLY, F> = EvaluationLeaf::new(leaf_index, x, y_s);
    let script = leaf_script.leaf_script();
    Ok(script)
}

impl<const TREE_HEIGHT: u8, F: NativeField> FieldTapTreeMMCS<TREE_HEIGHT, F> {
    pub fn new() -> Self {
        Self {
            builder: TaprootBuilder::new(),
            // builder:TaprootBuilder::with_capacity(TREE_HEIGHT as usize)
            phantom: PhantomData::<F>,
        }
    }

    pub fn add_leaf(mut self, leaf_script: ScriptBuf) -> Result<Self, BfError> {
        self.builder = self.builder.add_leaf(TREE_HEIGHT, leaf_script)?;
        Ok(self)
    }

    pub fn into_node_info(self) -> NodeInfo {
        self.builder.try_into_node_info().unwrap()
    }

    pub fn into_taptree(self) -> TapTree {
        self.builder.try_into_taptree().unwrap()
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

        let mut field_taptree_1 = FieldTapTreeMMCS::<3, BabyBear>::new();

        for i in 0..evas1.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly1.points[i],
                vec![evas1[i].clone()],
            )
            .unwrap();
            field_taptree_1 = field_taptree_1.add_leaf(leaf_script).unwrap();
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

        let mut field_taptree_2 = FieldTapTreeMMCS::<3, BabyBear>::new();

        for i in 0..evas2.len() {
            let leaf_script = construct_evaluation_leaf_script::<1, F>(
                i,
                eva_poly2.points[i],
                vec![evas2[i].clone()],
            )
            .unwrap();
            field_taptree_2 = field_taptree_2.add_leaf(leaf_script).unwrap();
        }

        let new_node = combine_two_nodes(
            field_taptree_1.clone().into_node_info(),
            field_taptree_2.clone().into_node_info(),
        )
        .unwrap();
    }
}
