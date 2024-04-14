// the leaf script maybe include
// different field [M31, BabyBear, Babybear EXTField]
// one evaluation from one polynomial or multiple evaluations from multi-polynomials
// different bit-commitment
// how to searlize the leaf
// use which hash to hash the leaf script

use std::marker::PhantomData;
use std::usize;

use super::bit_commitment::*;
use super::NativeField;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::opcodes::{OP_EQUAL, OP_EQUALVERIFY, OP_SWAP};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::{define_pushable, script};
define_pushable!();

pub struct VerifyFoldingLeaf<'a, const NUM_POLY: usize, F: NativeField> {
    x: F,
    y_0_x_commitment: &'a BitCommitment<F>,
    y_0_neg_x_commitment: &'a BitCommitment<F>,
    y_1_x_square_commitment: &'a BitCommitment<F>,
}

impl<'a, const NUM_POLY: usize, F: NativeField> VerifyFoldingLeaf<'a, NUM_POLY, F> {
    fn new(
        x: F,
        y_0_x_commitment: &'a BitCommitment<F>,
        y_0_neg_x_commitment: &'a BitCommitment<F>,
        y_1_x_square_commitment: &'a BitCommitment<F>,
    ) -> Self {
        VerifyFoldingLeaf {
            x,
            y_0_x_commitment,
            y_0_neg_x_commitment,
            y_1_x_square_commitment,
        }
    }

    // fn leaf_script(&self) -> Script{

    // }

    pub fn check_equal_script(&self) -> Script {
        script! {
            for i in 0..N0/2{
                {self.y_0_x_commitment.commit_message[ N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }
}

pub struct EvaluationLeaf<const NUM_POLY: usize, F: NativeField> {
    leaf_index: usize,
    x: F,
    x_commitment: BitCommitment<F>,
    neg_x_commitment: BitCommitment<F>,
    evaluations: Vec<F>,
    evaluations_commitments: Vec<BitCommitment<F>>,
}

impl<const NUM_POLY: usize, F: NativeField> EvaluationLeaf<NUM_POLY, F> {
    pub fn new(leaf_index: usize, x: F, evaluations: Vec<F>) -> Self {
        assert_eq!(evaluations.len(), NUM_POLY);

        let x_commitment =
            BitCommitment::new("b138982ce17ac813d505b5b40b665d404e9528e8".to_string(), x);
        let neg_x_commitment = BitCommitment::new(
            "b138982ce17ac813d505b5b40b665d404e9528e8".to_string(),
            F::field_mod() - x,
        );
        let mut evaluations_commitments = Vec::new();
        for i in 0..NUM_POLY {
            evaluations_commitments.push(BitCommitment::new(
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
            { self.x_commitment.check_equal_script() }
            // todo: calculate to equal to -x
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].check_equal_script() }
            }
            OP_1
        };

        scripts
    }
}

pub struct BitCommitment<F: NativeField> {
    origin_value: u32,
    secret_key: String,
    message: [u8; N0 as usize], // every u8 only available for 4-bits
    commit_message: [u8; N0 / 2 as usize],
    pubkey: Vec<Vec<u8>>,
    _marker: PhantomData<F>,
}

impl<F: NativeField> BitCommitment<F> {
    pub fn new(secret_key: String, origin_value: F) -> Self {
        let origin_value = origin_value.as_u32();
        let message = to_digits::<N0>(origin_value);
        let mut commit_message = [0; N0 / 2];
        for i in 0..N0 / 2 {
            let index = N0 / 2 - 1 - i;
            commit_message[i] = message[2 * index] ^ (message[2 * index + 1] << 4);
        }
        let mut pubkey = Vec::new();
        for i in 0..N {
            pubkey.push(public_key(&secret_key, i as u32));
        }
        Self {
            origin_value,
            secret_key,
            message,
            commit_message,
            pubkey,
            _marker: PhantomData,
        }
    }

    pub fn check_equal_script(&self) -> Script {
        script! {
            for i in 0..N0/2{
                {self.commit_message[ N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }

    pub fn check_equal_x_or_neg_x_script(&self, neg_x: &BitCommitment<F>) -> Script {
        script! {
            for i in 0..N0/2{
                OP_DUP
                {self.commit_message[ N0 / 2 - 1 - i]} OP_EQUAL OP_SWAP
                {neg_x.commit_message[ N0 / 2 - 1 - i]} OP_EQUAL OP_ADD
                OP_1 OP_EQUALVERIFY
            }
        }
    }

    pub fn checksig_verify_script(&self) -> Script {
        checksig_verify(self.pubkey.as_slice())
    }

    // signuture is the input of this script
    pub fn complete_script(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {self.check_equal_script()}
        }
    }

    pub fn signature_script(&self) -> Script {
        sign_script(&self.secret_key, self.message)
    }

    pub fn signature(&self) -> Vec<Vec<u8>> {
        let mut sig = sign(&self.secret_key, self.message);
        for i in 0..sig.len() {
            if sig[i].len() == 1 && sig[i][0] == 0 {
                sig[i] = vec![]
            }
        }
        sig
    }
}

pub fn u8_to_hex_str(byte: &u8) -> String {
    format!("{:02X}", byte)
}

#[cfg(test)]
mod test {
    use p3_baby_bear::BabyBear;
    use rand::Rng;

    use crate::execute_script_with_inputs;

    use super::*;

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
    fn test_bit_commitment_scripts() {
        let x_commitment = BitCommitment::new("0000".to_string(), BabyBear::from_u32(0x11654321));
        assert_eq!(x_commitment.commit_message, [0x11, 0x65, 0x43, 0x21]);
        // println!("{:?}",x_commitment.commit_message);

        let check_equal_script = x_commitment.check_equal_script();
        // println!("{:?}", check_equal_script);

        let expect_script = script! {
            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x11 OP_EQUALVERIFY
        };
        // println!("{:}",expect_script);
        assert_eq!(expect_script, check_equal_script);

        // check signature and verify the value
        let signature = x_commitment.signature();
        let exec_scripts = script! {
            { x_commitment.checksig_verify_script() }
            { x_commitment.check_equal_script() }
            OP_1
        };
        // println!("{:?}", exec_scripts);
        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);

        for _ in 0..30 {
            let mut rng = rand::thread_rng();
            let random_number: u32 = rng.gen();
            let n = random_number % BabyBear::MOD;

            let x_commitment = BitCommitment::new(
                "b138982ce17ac813d505b5b40b665d404e9528e8".to_string(),
                BabyBear::from_u32(n),
            );
            println!("{:?}", x_commitment.commit_message);

            let check_equal_script = x_commitment.check_equal_script();
            println!("{:?}", check_equal_script);

            // check signature and verify the value
            let signature = x_commitment.signature();
            let exec_scripts = script! {
                { x_commitment.checksig_verify_script() }
                { x_commitment.check_equal_script() }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);
        }

        // test bitcommitment
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
