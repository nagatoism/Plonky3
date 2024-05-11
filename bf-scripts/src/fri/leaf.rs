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

use super::bit_comm::*;
use super::winternitz::*;
use super::BfField;
use crate::{fold_degree, winternitz, BabyBearU31};
define_pushable!();
//Warning! The code only works for Babybear now
pub struct VerifyFoldingLeaf<'a, const NUM_POLY: usize, F: BfField> {
    x: F,
    beta: &'a BitCommitment<F>,
    y_0_x_commitment: &'a BitCommitment<F>,
    y_0_neg_x_commitment: &'a BitCommitment<F>,
    y_1_x_square_commitment: &'a BitCommitment<F>,
}

impl<'a, const NUM_POLY: usize, F: BfField> VerifyFoldingLeaf<'a, NUM_POLY, F> {
    fn new(
        x: F,
        beta: &'a BitCommitment<F>,
        y_0_x_commitment: &'a BitCommitment<F>,
        y_0_neg_x_commitment: &'a BitCommitment<F>,
        y_1_x_square_commitment: &'a BitCommitment<F>,
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
            self.x.as_u32_vec()[0],
            self.y_0_x_commitment.commitments[0].value,
            self.y_0_neg_x_commitment.commitments[0].value,
            self.beta.commitments[0].value,
            self.y_1_x_square_commitment.commitments[0].value,
        )
    }

    pub fn check_equal_script(&self) -> Script {
        script! {
            for i in 0..winternitz::N0/2{
                {self.y_0_x_commitment.commitments[0].commit_u32_as_4bytes()[ winternitz::N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }
}

pub struct EvaluationLeaf<const NUM_POLY: usize, F: BfField> {
    leaf_index: usize,
    x: F,
    x_commitment: BitCommitment<F>,
    neg_x_commitment: BitCommitment<F>,
    evaluations: Vec<F>,
    evaluations_commitments: Vec<BitCommitment<F>>,
}

impl<const NUM_POLY: usize, F: BfField> EvaluationLeaf<NUM_POLY, F> {
    pub fn new(leaf_index: usize, x: F, evaluations: Vec<F>) -> Self {
        assert_eq!(evaluations.len(), NUM_POLY);

        let x_commitment = BitCommitment::new("b138982ce17ac813d505b5b40b665d404e9528e8", x);
        let neg_x_commitment = BitCommitment::new(
            "b138982ce17ac813d505b5b40b665d404e9528e8",
            F::field_mod() - x,
        );
        let mut evaluations_commitments = Vec::new();
        for i in 0..NUM_POLY {
            evaluations_commitments.push(BitCommitment::new(
                "b138982ce17ac813d505b5b40b665d404e9528e9",
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
            { self.x_commitment.commitments[0].checksig_verify_script() }
            { self.x_commitment.commitments[0].commit_u32_as_4bytes_script() }
            // todo: calculate to equal to -x
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].commitments[0].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].commitments[0].commit_u32_as_4bytes_script() }
            }
            OP_1
        };

        scripts
    }

    pub fn two_point_leaf_script(&self) -> Script {
        // equal to x script
        let scripts = script! {
            { self.x_commitment.commitments[0].checksig_verify_script() }
            { self.x_commitment.commitments[0].commit_u32_as_4bytes_script() }
            { self.neg_x_commitment.commitments[0].checksig_verify_script() }
            { self.neg_x_commitment.commitments[0].commit_u32_as_4bytes_script() }
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].commitments[0].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].commitments[0].commit_u32_as_4bytes_script() }
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
    use crate::{execute_script_with_inputs};

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
            let signature = leaf.evaluations_commitments[num_polys - 1 - i].commitments[0].signature();
            signature.iter().for_each(|item| sigs.push(item.to_vec()));
        }
        let signature = leaf.x_commitment.commitments[0].signature();
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

        // check signature and verify the value
        let signature = leaf.x_commitment.commitments[0].signature();
        // check equal to r
        let exec_scripts = script! {
            { leaf.x_commitment.commitments[0].checksig_verify_script() }
            { leaf.x_commitment.commitments[0].check_equal_x_or_neg_x_script(&leaf.neg_x_commitment.commitments[0]) }
            OP_1
        };
        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);

        // check equal to -r
        let signature = leaf.x_commitment.commitments[0].signature();
        let exec_scripts = script! {
            { leaf.x_commitment.commitments[0].checksig_verify_script() }
            { leaf.neg_x_commitment.commitments[0].check_equal_x_or_neg_x_script(&leaf.x_commitment.commitments[0]) }
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

            // check signature and verify the value
            let signature = leaf.x_commitment.commitments[0].signature();
            // check equal to r
            let exec_scripts = script! {
                { leaf.x_commitment.commitments[0].checksig_verify_script() }
                { leaf.x_commitment.commitments[0].check_equal_x_or_neg_x_script(&leaf.neg_x_commitment.commitments[0]) }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);

            // check equal to -r
            let signature = leaf.x_commitment.commitments[0].signature();
            let exec_scripts = script! {
                { leaf.x_commitment.commitments[0].checksig_verify_script() }
                { leaf.neg_x_commitment.commitments[0].check_equal_x_or_neg_x_script(&leaf.x_commitment.commitments[0]) }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);

            let signature = leaf.neg_x_commitment.commitments[0].signature();
            let exec_scripts = script! {
                { leaf.neg_x_commitment.commitments[0].checksig_verify_script() }
                { leaf.x_commitment.commitments[0].check_equal_x_or_neg_x_script(&leaf.neg_x_commitment.commitments[0]) }
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
