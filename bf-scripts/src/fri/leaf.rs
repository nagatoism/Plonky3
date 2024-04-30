// the leaf script maybe include
// different field [M31, BabyBear, Babybear EXTField]
// one evaluation from one polynomial or multiple evaluations from multi-polynomials
// different bit-commitment
// how to searlize the leaf
// use which hash to hash the leaf script

use std::marker::PhantomData;
use std::usize;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::opcodes::{OP_EQUAL, OP_EQUALVERIFY, OP_SWAP};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::{define_pushable, script};

use super::bitcom::*;
use super::winternitz::*;
use super::NativeField;
use crate::{fold_degree, BabyBearU31};
define_pushable!();

pub struct VerifyFoldingLeaf<'a, const NUM_POLY: usize, F: NativeField> {
    x: F,
    beta: &'a BitCommit<F>,
    y_0_x_commitment: &'a BitCommit<F>,
    y_0_neg_x_commitment: &'a BitCommit<F>,
    y_1_x_square_commitment: &'a BitCommit<F>,
}

impl<'a, const NUM_POLY: usize, F: NativeField> VerifyFoldingLeaf<'a, NUM_POLY, F> {
    fn new(
        x: F,
        beta: &'a BitCommit<F>,
        y_0_x_commitment: &'a BitCommit<F>,
        y_0_neg_x_commitment: &'a BitCommit<F>,
        y_1_x_square_commitment: &'a BitCommit<F>,
    ) -> Self {
        VerifyFoldingLeaf {
            x,
            beta,
            y_0_x_commitment,
            y_0_neg_x_commitment,
            y_1_x_square_commitment,
        }
    }

    fn leaf_script(&self) -> Script {
        fold_degree::<BabyBearU31>(
            2,
            self.x.as_u32(),
            self.y_0_x_commitment.origin_value,
            self.y_0_neg_x_commitment.origin_value,
            self.beta.origin_value,
            self.y_1_x_square_commitment.origin_value,
        )
    }

    pub fn check_equal_script(&self) -> Script {
        script! {
            for i in 0..F::N0/2{
                {self.y_0_x_commitment.commit_u32_as_4bytes()[ F::N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }
}

pub struct TwoPointsLeaf<F: NativeField> {
    leaf_index_1: usize,
    leaf_index_2: usize,
    p1: Point<F>,
    p2: Point<F>,
}

impl<F: NativeField> TwoPointsLeaf<F> {
    pub fn new(
        leaf_index_1: usize,
        leaf_index_2: usize,
        x1: F,
        y1: F,
        x2: F,
        y2: F,
    ) -> TwoPointsLeaf<F> {
        let p1 = Point::<F>::new(x1, y1);
        let p2 = Point::<F>::new(x2, y2);
        Self {
            leaf_index_1,
            leaf_index_2,
            p1,
            p2,
        }
    }

    pub fn commit_script(&self) -> Script {
        let scripts = script! {
            {self.p1.commit_script()}
            {self.p2.commit_script()}
            OP_1
        };
        scripts
    }
}

pub struct Point<F: NativeField> {
    x: F,
    y: F,
    x_commit: BitCommit<F>,
    y_commit: BitCommit<F>,
}

impl<F: NativeField> Point<F> {
    pub fn new(x: F, y: F) -> Point<F> {
        let x_commit = BitCommit::new("b138982ce17ac813d505b5b40b665d404e9528e8".to_string(), x);
        let y_commit = BitCommit::new("b138982ce17ac813d505b5b40b665d404e9528e8".to_string(), y);
        Self {
            x: x,
            y: y,
            x_commit: x_commit,
            y_commit: y_commit,
        }
    }

    pub fn commit_script(&self) -> Script {
        let scripts = script! {
            { self.x_commit.checksig_verify_script() }
            { self.x_commit.commit_u32_as_4bytes_script() }
            { self.y_commit.checksig_verify_script() }
            { self.y_commit.commit_u32_as_4bytes_script() }
        };

        scripts
    }
}

pub struct EvaluationLeaf<const NUM_POLY: usize, F: NativeField> {
    leaf_index: usize,
    x: F,
    x_commitment: BitCommit<F>,
    neg_x_commitment: BitCommit<F>,
    evaluations: Vec<F>,
    evaluations_commitments: Vec<BitCommit<F>>,
}

impl<const NUM_POLY: usize, F: NativeField> EvaluationLeaf<NUM_POLY, F> {
    pub fn new(leaf_index: usize, x: F, evaluations: Vec<F>) -> Self {
        assert_eq!(evaluations.len(), NUM_POLY);

        let x_commitment =
            BitCommit::new("b138982ce17ac813d505b5b40b665d404e9528e8".to_string(), x);
        let neg_x_commitment = BitCommit::new(
            "b138982ce17ac813d505b5b40b665d404e9528e8".to_string(),
            F::field_mod() - x,
        );
        let mut evaluations_commitments = Vec::new();
        for i in 0..NUM_POLY {
            evaluations_commitments.push(BitCommit::new(
                "b138982ce17ac813d505b5b40b665d404e9528e9".to_string(),
                evaluations[i],
            ));
        }

        Self {
            leaf_index,
            x,
            x_commitment,
            neg_x_commitment,
            evaluations,
            evaluations_commitments,
        }
    }

    pub fn leaf_script(&self) -> Script {
        // equal to x script
        let scripts = script! {
            { self.x_commitment.checksig_verify_script() }
            { self.x_commitment.commit_u32_as_4bytes_script() }
            // todo: calculate to equal to -x
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].commit_u32_as_4bytes_script() }
            }
            OP_1
        };

        scripts
    }

    pub fn two_point_leaf_script(&self) -> Script {
        // equal to x script
        let scripts = script! {
            { self.x_commitment.checksig_verify_script() }
            { self.x_commitment.commit_u32_as_4bytes_script() }
            { self.neg_x_commitment.checksig_verify_script() }
            { self.neg_x_commitment.commit_u32_as_4bytes_script() }
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].commit_u32_as_4bytes_script() }
            }
            OP_1
        };

        scripts
    }
}

pub fn u8_to_hex_str(byte: &u8) -> String {
    format!("{:02X}", byte)
}

#[cfg(test)]
mod test {
    use p3_baby_bear::BabyBear;
    use rand::Rng;

    use super::*;
    use crate::execute_script_with_inputs;

    #[test]
    fn test_leaf_execution() {
        const num_polys: usize = 2;
        let x = BabyBear::from_u32(0x11654321);

        let leaf = EvaluationLeaf::<num_polys, BabyBear>::new(
            0,
            x,
            vec![
                BabyBear::from_u32(0x11654321),
                BabyBear::from_u32(0x11654321),
            ],
        );

        let script = leaf.leaf_script();

        let mut sigs: Vec<Vec<u8>> = Vec::new();
        for i in 0..num_polys {
            let signature = leaf.evaluations_commitments[num_polys - 1 - i].signature();
            signature.iter().for_each(|item| sigs.push(item.to_vec()));
        }
        let signature = leaf.x_commitment.signature();
        signature.iter().for_each(|item| sigs.push(item.to_vec()));

        println!("{:?}", script);

        let exec_result = execute_script_with_inputs(script, sigs);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u32_compress_to_bit_commit() {
        use crate::u32::u32_std::{u32_compress, u32_push};
    }

    #[test]
    fn test_check_x_neg_x_equal_script() {
        const num_polys: usize = 1;
        let x = BabyBear::from_u32(0x11654321);
        let neg_x = BabyBear::field_mod() - x; // 669ABCE0
        let expect_neg_x = BabyBear::from_u32(0x669ABCE0);
        assert_eq!(neg_x, expect_neg_x);
        let leaf =
            EvaluationLeaf::<num_polys, BabyBear>::new(0, x, vec![BabyBear::from_u32(0x11654321)]);

        assert_eq!(x.as_u32(), leaf.x_commitment.origin_value);
        assert_eq!(neg_x.as_u32(), leaf.neg_x_commitment.origin_value);
        println!("{}", format!("{:X}", neg_x.as_u32()));

        // check signature and verify the value
        let signature = leaf.x_commitment.signature();
        // check equal to r
        let exec_scripts = script! {
            { leaf.x_commitment.checksig_verify_script() }
            { leaf.x_commitment.check_equal_x_or_neg_x_script(&leaf.neg_x_commitment) }
            OP_1
        };
        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);

        // check equal to -r
        let signature = leaf.x_commitment.signature();
        let exec_scripts = script! {
            { leaf.x_commitment.checksig_verify_script() }
            { leaf.neg_x_commitment.check_equal_x_or_neg_x_script(&leaf.x_commitment) }
            OP_1
        };
        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);

        for _ in 0..30 {
            let mut rng = rand::thread_rng();
            let random_number: u32 = rng.gen();
            let x = random_number % BabyBear::MOD;
            let x = BabyBear::from_u32(x);
            let neg_x = BabyBear::field_mod() - x;
            let leaf = EvaluationLeaf::<num_polys, BabyBear>::new(
                0,
                x,
                vec![BabyBear::from_u32(0x11654321)],
            );

            assert_eq!(x.as_u32(), leaf.x_commitment.origin_value);
            assert_eq!(neg_x.as_u32(), leaf.neg_x_commitment.origin_value);
            // check signature and verify the value
            let signature = leaf.x_commitment.signature();
            // check equal to r
            let exec_scripts = script! {
                { leaf.x_commitment.checksig_verify_script() }
                { leaf.x_commitment.check_equal_x_or_neg_x_script(&leaf.neg_x_commitment) }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);

            // check equal to -r
            let signature = leaf.x_commitment.signature();
            let exec_scripts = script! {
                { leaf.x_commitment.checksig_verify_script() }
                { leaf.neg_x_commitment.check_equal_x_or_neg_x_script(&leaf.x_commitment) }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);

            let signature = leaf.neg_x_commitment.signature();
            let exec_scripts = script! {
                { leaf.neg_x_commitment.checksig_verify_script() }
                { leaf.x_commitment.check_equal_x_or_neg_x_script(&leaf.neg_x_commitment) }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_push_bytes() {
        let scripts1 = script! {
            0x00bc
            OP_DROP
            OP_1
        };

        let scripts2 = script! {
            0x50
            OP_DROP
            OP_1
        };

        let scripts3 = script! {
            <0x90>
            OP_DROP
            OP_1
        };

        // let script4 = Script::parse_asm("OP_PUSHDATA1 90 OP_DROP OP_PUSHNUM_1");
        let scripts4 = Script::parse_asm("OP_PUSHBYTES_1 90 OP_DROP OP_PUSHNUM_1").unwrap();
        println!("{:?}", scripts1);
        println!("{:?}", scripts2);
        println!("{:?}", scripts3);
        println!("{:?}", scripts4);
        let result = execute_script(scripts4);
        assert!(result.success);
    }
}
