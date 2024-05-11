use std::marker::PhantomData;
use std::ops::Deref;

use bitcoin::opcodes::{OP_EQUAL, OP_EQUALVERIFY, OP_TOALTSTACK};
use bitcoin::p2p::message;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::{define_pushable, script};
use itertools::Itertools;
use p3_baby_bear::BabyBear;

use super::winternitz::*;
use super::BfField;
use crate::bit_comm_u32::BitCommitmentU32;
use crate::{u31ext_equalverify, winternitz};
use crate::u32_std::u32_compress;

define_pushable!();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitCommitment<F:BfField> {
    pub value: F,
    pub commitments:Vec<BitCommitmentU32>
}


impl<F: BfField> BitCommitment<F> {
    pub fn new(secret_key: &str, value: F) -> Self {
        let u32_values = value.as_u32_vec();
        let commitments = u32_values.iter().map(|v|{
            let comm = BitCommitmentU32::new(secret_key, *v);
            comm
        }).collect_vec();
       
        
        Self {
            value,
            commitments
        }
    }
}

impl<F: BfField>  BitCommitment<F> {
  

    pub fn from_message_at_stack(&self) -> Script {
        // we must confirm the stack state look like below after the inputs enter to match the complete_script:
        // bit_commits[0].sig  <- top
        // bit_commits[1].sig
        //       ...
        // bit_commits[N].sig
        let u32_value =self.value.as_u32_vec();
        let script = script! {
            for i in 0..(F::U32_SIZE-1){
                {self.winternitz[i].checksig_verify(self.winternitz[i].pub_key())}
                {u32_value[i]}
                OP_TOALTSTACK
            }

            {self.winternitz[F::U32_SIZE-1].checksig_verify_self_pubkey()}
            {u32_compress()}
            {u32_value[F::U32_SIZE-1]}

            for _ in 0..F::U32_SIZE-1{
                OP_FROMALTSTACK
            }
            // The stake state looks like below:
            // EF.slice(0)  <- top
            // EF.slice(1)
            //    ...
            // EF.slice(EF::D-1)
        };
        script
    }

    pub fn from_message_at_altstack(&self) -> Script {
        // we must confirm the stack state look like below after the inputs enter to match the recover_message_at_altstack:
        // bit_commits[0].sig  <- top
        // bit_commits[1].sig
        //       ...
        // bit_commits[N].sig
        let u32_value =self.value.as_u32_vec();
        let script = script! {
            for i in 0..F::U32_SIZE{
                {self.winternitz[i].checksig_verify_self_pubkey()}
                {u32_compress()}
                {OP_TOALTSTACK}
                {u32_value[i]}
                OP_TOALTSTACK
            }

            // The altstake state looks like below:
            // EF.slice(EF::D-1)  <- top
            // EF.slice(EF::D-2)
            //    ...
            // EF.slice(1)
        };
        script
    }

    // signuture is the input of this script
    pub fn from_message_euqal_to_commit_message(&self) -> Script {
        let ms = self.commit_message.as_base_slice();
        script! {
            {self.recover_message_at_stack()}
            { ms[3].as_u32() } { ms[2].as_u32() } { ms[1].as_u32() } { ms[0].as_u32() }
            { u31ext_equalverify::<BabyBear,4>() }
        }
    }

    pub fn signature(&self) -> Vec<Vec<u8>> {
        let mut sigs = Vec::new();
        for i in (0..F::D).rev() {
            sigs.append(&mut self.bit_commits[i].signature());
        }
        sigs
    }
}


impl <F:BfField> BitCommitment<F> {
    fn recover_u32_at_stack(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {u32_compress()}
        }
    }

    fn recover_u32_at_altstack(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {u32_compress()}
            OP_TOALTSTACK
        }
    }

    // signuture is the input of this script
    fn recover_u32_euqal_to_commit_message(&self) -> Script {
        script! {
            {self.recover_u32_at_stack()}
            {self.value }
            OP_EQUALVERIFY
        }
    }

    fn signature_u32(&self) -> Vec<Vec<u8>> {
        let mut sig = self.winter.sign(&self.message);
        for i in 0..sig.len() {
            if sig[i].len() == 1 && sig[i][0] == 0 {
                sig[i] = vec![]
            }
        }
        sig
    }
}
#[cfg(test)]
mod test {
    use p3_baby_bear::BabyBear;
    use rand::Rng;

    use super::*;
    use crate::execute_script_with_inputs;

    #[test]
    fn test_bit_commit_with_compressu32() {
        let value = BabyBear::from_u32(0x11654321);
        let x_commitment = BitCommitment::new("0000", value);

        let signature = x_commitment.signature();
        // let exec_scripts = script! {
        //     { x_commitment.checksig_verify_script() }
        //     { u32_compress() }
        //     { value.as_u32() }
        //     OP_EQUAL
        // };

        let exec_scripts = script! {
            { x_commitment.recover_message_euqal_to_commit_message() }
            OP_1
        };

        // let exec_scripts = x_commitment.complete_script()

        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);
    }

    #[test]
    fn test_bit_commmit_sig_and_verify() {
        let x_commitment = BitCommitment::new("0000", BabyBear::from_u32(0x11654321));
        assert_eq!(
            x_commitment.commit_u32_as_4bytes(),
            [0x11, 0x65, 0x43, 0x21]
        );
        // println!("{:?}",x_commitment.commit_message);

        let check_equal_script = x_commitment.commit_u32_as_4bytes_script();
        // println!("{:?}", check_equal_script);

        let expect_script = script! {
            0x21 OP_EQUALVERIFY // low position
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x11 OP_EQUALVERIFY // high position
        };
        // println!("{:}",expect_script);
        assert_eq!(expect_script, check_equal_script);

        // check signature and verify the value
        let signature = x_commitment.signature();
        let exec_scripts = script! {
            { x_commitment.checksig_verify_script() }
            { x_commitment.commit_u32_as_4bytes_script() }
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
                "b138982ce17ac813d505b5b40b665d404e9528e8",
                BabyBear::from_u32(n),
            );
            println!("{:?}", x_commitment.commit_u32_as_4bytes());

            let check_equal_script = x_commitment.commit_u32_as_4bytes_script();
            println!("{:?}", check_equal_script);

            // check signature and verify the value
            let signature = x_commitment.signature();
            let exec_scripts = script! {
                { x_commitment.checksig_verify_script() }
                { x_commitment.commit_u32_as_4bytes_script() }
                OP_1
            };
            let exec_result = execute_script_with_inputs(exec_scripts, signature);
            assert!(exec_result.success);
        }
    }

    use core::ops::{Add, Mul, Neg};

    use p3_field::{AbstractExtensionField, AbstractField, PrimeField32};
    use rand::{SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        execute_script, u31ext_add, u31ext_double, u31ext_equalverify,
        BabyBear4,
    };

    type F = BabyBear;
    type EF = p3_field::extension::BinomialExtensionField<BabyBear, 4>;

    #[test]
    fn test_extension_bit_commit() {
        let mut rng = ChaCha20Rng::seed_from_u64(0u64);
        eprintln!("babybear4 add: {}", u31ext_add::<BabyBear4>().len());

        let a = rng.gen::<EF>();
        let b = rng.gen::<EF>();
        let a_commit =
            BitCommitment::<EF>::new("b138982ce17ac813d505b5b40b665d404e9528e7", a);
        let b_commit =
            BitCommitment::<EF>::new("b138982ce17ac813d505b5b40b665d404e9528e6", b);

        let c = a.add(b);

        let a: &[F] = a.as_base_slice();
        let b: &[F] = b.as_base_slice();
        let c: &[F] = c.as_base_slice();

        let script = script! {
            { a[3].as_canonical_u32() } { a[2].as_canonical_u32() } { a[1].as_canonical_u32() } { a[0].as_canonical_u32() }
            { b[3].as_canonical_u32() } { b[2].as_canonical_u32() } { b[1].as_canonical_u32() } { b[0].as_canonical_u32() }
            { u31ext_add::<BabyBear4>() }
            { c[3].as_canonical_u32() } { c[2].as_canonical_u32() } { c[1].as_canonical_u32() } { c[0].as_canonical_u32() }
            { u31ext_equalverify::<BabyBear4>() }
            OP_PUSHNUM_1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let script = script! {
            { a_commit.recover_message_at_altstack() }
            { b_commit.recover_message_at_altstack() }
            { b_commit.message_FROMALTSTACK()}
            { a_commit.message_FROMALTSTACK()}
            { u31ext_add::<BabyBear4>() }
            { c[3].as_canonical_u32() } { c[2].as_canonical_u32() } { c[1].as_canonical_u32() } { c[0].as_canonical_u32() }
            { u31ext_equalverify::<BabyBear4>() }
            OP_1
        };
        let mut a_sigs = a_commit.signature();
        let mut b_sigs: Vec<Vec<u8>> = b_commit.signature();
        b_sigs.append(&mut a_sigs);
        let exec_result = execute_script_with_inputs(script, b_sigs);
        assert!(exec_result.success);
    }

    #[test]
    fn test_extension_bit_commit_sig_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(0u64);
        let a = rng.gen::<EF>();

        let a_commit =
            BitCommitment::<EF>::new("b138982ce17ac813d505b5b40b665d404e9528e7", a);

        let a: &[F] = a.as_base_slice();
        let script = script! {
            {a_commit.recover_message_euqal_to_commit_message()}
            OP_1
        };
        let a_sigs = a_commit.signature();
        let exec_result = execute_script_with_inputs(script, a_sigs);
        assert!(exec_result.success);
    }
}
