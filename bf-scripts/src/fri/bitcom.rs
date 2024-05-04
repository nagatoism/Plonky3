use std::marker::PhantomData;
use std::ops::Deref;

use bitcoin::opcodes::{OP_EQUAL, OP_EQUALVERIFY, OP_TOALTSTACK};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::{define_pushable, script};

use super::winternitz::*;
use super::BfField;
use crate::u32_std::u32_compress;
use crate::{BfBaseField, BitsCommitment};
define_pushable!();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitCommit<F: BfBaseField> {
    pub origin_value: u32,
    pub winter: Winternitz<F>,
    pub message: Vec<u8>, // every u8 only available for 4-bits
    _marker: PhantomData<F>,
}

impl<F: BfBaseField> BitCommit<F> {
    pub fn new(secret_key: &str, origin_value: F) -> Self {
        let origin_value = origin_value.as_u32();
        let winter = Winternitz::<F>::new(&secret_key);
        let message = to_digits(origin_value, F::N0);
        Self {
            origin_value,
            winter,
            message,
            _marker: PhantomData,
        }
    }

    pub fn commit_u32_as_4bytes(&self) -> Vec<u8> {
        let message = self.message.clone();
        let mut commit_message = vec![0u8; F::N0 / 2];
        for i in 0..F::N0 / 2 {
            let index = F::N0 / 2 - 1 - i;
            commit_message[i] = message[2 * index] ^ (message[2 * index + 1] << 4);
        }
        commit_message
    }

    pub fn commit_u32_as_4bytes_script(&self) -> Script {
        let commit_message = self.commit_u32_as_4bytes();
        script! {
            for i in 0..F::N0/2{
                {commit_message[ F::N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }

    pub fn check_equal_x_or_neg_x_script(&self, neg_x: &BitCommit<F>) -> Script {
        script! {
            for i in 0..F::N0/2{
                OP_DUP
                {self.commit_u32_as_4bytes()[ F::N0 / 2 - 1 - i]} OP_EQUAL OP_SWAP
                {neg_x.commit_u32_as_4bytes()[ F::N0 / 2 - 1 - i]} OP_EQUAL OP_ADD
                OP_1 OP_EQUALVERIFY
            }
        }
    }

    pub fn checksig_verify_script(&self) -> Script {
        script! {
            {self.winter.checksig_verify(self.winter.pub_key().as_slice())}
        }
    }

    pub fn signature_script(&self) -> Script {
        self.winter.sign_script(&self.message)
    }
}

impl<F: BfBaseField> BitsCommitment for BitCommit<F> {
    fn recover_message_at_stack(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {u32_compress()}
        }
    }

    fn recover_message_at_altstack(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {u32_compress()}
            OP_TOALTSTACK
        }
    }

    // signuture is the input of this script
    fn recover_message_euqal_to_commit_message(&self) -> Script {
        script! {
            {self.recover_message_at_stack()}
            {self.origin_value }
            OP_EQUALVERIFY
        }
    }

    fn signature(&self) -> Vec<Vec<u8>> {
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
        let x_commitment = BitCommit::new("0000", value);

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
        let x_commitment = BitCommit::new("0000", BabyBear::from_u32(0x11654321));
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

            let x_commitment = BitCommit::new(
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
}
