use core::marker::PhantomData;

use alloc::vec::Vec;
use bf_scripts::field::BabyBear;
use bf_scripts::{execute_script, leaf};
use bf_scripts::{EvaluationLeaf, NativeField};
use bitcoin::taproot::NodeInfo;
use bitcoin::{
    taproot::LeafVersion::TapScript, taproot::TapLeaf, taproot::TapTree, taproot::TaprootBuilder,
    taproot::TaprootBuilderError, ScriptBuf,
};

use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_field::{PrimeField, PrimeField32};
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

#[derive(Clone)]
pub struct FieldTapTreeMMCS<const TREE_HEIGHT: u8, F: NativeField> {
    builder: TaprootBuilder,
    phantom: PhantomData<F>,
}

impl<const TREE_HEIGHT: u8, F: NativeField> FieldTapTreeMMCS<TREE_HEIGHT, F> {
    pub fn new() -> Self {
        Self {
            builder: TaprootBuilder::new(),
            // builder:TaprootBuilder::with_capacity(TREE_HEIGHT as usize)
            phantom: PhantomData::<F>,
        }
    }

    pub fn add_leaf(self, leaf_script: ScriptBuf) -> Result<TaprootBuilder, BfError> {
        let builder = self.builder.add_leaf(TREE_HEIGHT, leaf_script)?;
        Ok(builder)
    }

    pub fn construct_evaluation_leaf_script<const NUM_POLY: usize>(
        self,
        leaf_index: usize,
        x: F,
        y_s: Vec<F>,
    ) -> Result<ScriptBuf, BfError> {
        let leaf_script: EvaluationLeaf<NUM_POLY, F> = EvaluationLeaf::new(leaf_index, x, y_s);
        let script = leaf_script.leaf_script();
        Ok(script)
    }

    pub fn into_node_info(self) -> NodeInfo {
        self.builder.try_into_node_info().unwrap()
    }

    pub fn into_taptree(self) -> TapTree {
        self.builder.try_into_taptree().unwrap()
    }

    pub fn combine_two_nodes(a: NodeInfo, b: NodeInfo) -> Result<NodeInfo, BfError> {
        let parent = NodeInfo::combine(a, b)?;
        Ok(parent)
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

    fn combine_two_taptree(a: NodeInfo, b: NodeInfo) -> Result<NodeInfo, BfError> {
        let parent = NodeInfo::combine(a, b)?;
        Ok(parent)
    }
}

mod tests {
    use super::*;

    use alloc::vec;

    use p3_field::AbstractField;
    use p3_interpolation::interpolate_subgroup;
    use p3_matrix::dense::RowMajorMatrix;

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

        let field_taptree_1 = FieldTapTreeMMCS::<1, BabyBear>::new();

        for i in 0..evas1.len() {
            let leaf_script = field_taptree_1
                .construct_evaluation_leaf_script::<1>(
                    i,
                    eva_poly1.points[i],
                    vec![evas1[i].clone()],
                )
                .unwrap();
            let result = field_taptree_1.add_leaf(leaf_script);
            assert!(result.is_ok());
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

        let field_taptree_2 = FieldTapTreeMMCS::<1, BabyBear>::new();

        for i in 0..evals.len() {
            let leaf_script = field_taptree_2
                .construct_evaluation_leaf_script::<1>(
                    i,
                    eva_poly1.points[i],
                    vec![evas2[i].clone()],
                )
                .unwrap();
            let result = field_taptree_2.add_leaf(leaf_script);
            assert!(result.is_ok());
        }
    }

    // #[test]
    // fn test_combine_taptree(){

    //     let field_taptree = FieldTapTreeMMCS::<1,BabyBear>::new();

    //     // field_taptree.
    //     // let leaf_script = EvaluationLeaf::<1,BabyBear>::new(0, BabyBear::one(), vec![BabyBear::one()]);

    //     let result = field_taptree.add_leaf(leaf_script);
    //     assert!(result.is_ok());
    // }
}
