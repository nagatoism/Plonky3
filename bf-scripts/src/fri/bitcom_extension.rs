use bitcoin::ScriptBuf as Script;
use bitcoin_script::{define_pushable, script};

use super::bitcom::*;
use crate::fri::field::*;
use crate::{u31ext_equalverify, BabyBear4};
define_pushable!();

pub enum BitsCommitmentEnum<F: BfBaseField, EF: BfExtensionField<F>> {
    Base(BitCommit<F>),
    Extension(BitCommitExtension<F, EF>),
}

pub trait BitsCommitment {
    fn recover_message_at_stack(&self) -> Script;
    fn recover_message_at_altstack(&self) -> Script;
    fn recover_message_euqal_to_commit_message(&self) -> Script;
    fn signature(&self) -> Vec<Vec<u8>>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitCommitExtension<F: BfBaseField, EF: BfExtensionField<F>> {
    pub commit_message: EF,
    pub bit_commits: Vec<BitCommit<F>>,
    _marker: std::marker::PhantomData<EF>,
}

impl<F: BfBaseField, EF: BfExtensionField<F>> BitCommitExtension<F, EF> {
    pub fn new_from_bit_commits(value: EF, bcs: Vec<&BitCommit<F>>) -> BitCommitExtension<F, EF> {
        let mut bit_commits = Vec::new();
        for i in 0..EF::D {
            let bit_commit: BitCommit<F> = bcs[i].clone();
            bit_commits.push(bit_commit);
        }
        Self {
            commit_message: value,
            bit_commits,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new_from_base_slice(secret: &str, bs: &[F]) -> Self {
        let value = EF::from_base_slice(bs);
        Self::new(secret, value)
    }

    pub fn new(secret: &str, value: EF) -> Self {
        let mut bit_commits = Vec::new();
        for i in 0..EF::D {
            // let secret_i = format!("{}{}",secret,i);
            let secret_i = secret;
            let bit_commit = BitCommit::<F>::new(secret_i, value.as_base_slice()[i]);
            bit_commits.push(bit_commit)
        }
        Self {
            commit_message: value,
            bit_commits,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn message_TOALTSTACK(&self) -> Script {
        script! {
            for _ in 0..EF::D{
                OP_TOALTSTACK
            }
        }
    }

    pub fn message_FROMALTSTACK(&self) -> Script {
        script! {
            for _ in 0..EF::D{
                OP_FROMALTSTACK
            }
        }
    }
}

impl<F: BfBaseField, EF: BfExtensionField<F>> BitsCommitment for BitCommitExtension<F, EF> {
    fn recover_message_at_stack(&self) -> Script {
        // we must confirm the stack state look like below after the inputs enter to match the complete_script:
        // bit_commits[0].sig  <- top
        // bit_commits[1].sig
        //       ...
        // bit_commits[N].sig
        let script = script! {
            for i in 0..(EF::D-1){
                {self.bit_commits[i].recover_message_euqal_to_commit_message()}
                {self.bit_commits[i].origin_value}
                OP_TOALTSTACK
            }

            {self.bit_commits[EF::D-1].recover_message_euqal_to_commit_message()}
            {self.bit_commits[EF::D-1].origin_value}

            for _ in 0..EF::D-1{
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

    fn recover_message_at_altstack(&self) -> Script {
        // we must confirm the stack state look like below after the inputs enter to match the recover_message_at_altstack:
        // bit_commits[0].sig  <- top
        // bit_commits[1].sig
        //       ...
        // bit_commits[N].sig
        let script = script! {
            for i in 0..EF::D{
                {self.bit_commits[i].recover_message_euqal_to_commit_message()}
                {self.bit_commits[i].origin_value}
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
    fn recover_message_euqal_to_commit_message(&self) -> Script {
        let ms = self.commit_message.as_base_slice();
        script! {
            {self.recover_message_at_stack()}
            { ms[3].as_u32() } { ms[2].as_u32() } { ms[1].as_u32() } { ms[0].as_u32() }
            { u31ext_equalverify::<BabyBear4>() }
        }
    }

    fn signature(&self) -> Vec<Vec<u8>> {
        let mut sigs = Vec::new();
        for i in (0..EF::D).rev() {
            sigs.append(&mut self.bit_commits[i].signature());
        }
        sigs
    }
}

#[cfg(test)]
mod test {

    use core::ops::{Add, Mul, Neg};

    use p3_field::{AbstractExtensionField, AbstractField, PrimeField32};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        execute_script, execute_script_with_inputs, u31ext_add, u31ext_double, u31ext_equalverify,
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
            BitCommitExtension::<F, EF>::new("b138982ce17ac813d505b5b40b665d404e9528e7", a);
        let b_commit =
            BitCommitExtension::<F, EF>::new("b138982ce17ac813d505b5b40b665d404e9528e6", b);

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
            BitCommitExtension::<F, EF>::new("b138982ce17ac813d505b5b40b665d404e9528e7", a);

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
