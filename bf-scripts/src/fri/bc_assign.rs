use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;
use std::{array, mem};

use once_cell::sync::Lazy;
use p3_baby_bear::BabyBear;
use p3_field::ExtensionField;

use crate::{
    BaseCanCommit, BfBaseField, BfExtensionField, BitCommit, BitCommitExtension, BitsCommitment,
};
// static BC_ASSIGN: Lazy<Mutex<BCAssignment<BabyBear>>> = Lazy::new(|| {
//     Mutex::new(BCAssignment::<BabyBear>::new())
// });

#[derive(Debug, Clone, Default)]
pub struct ExtensionBCAssignment<F: BfBaseField, EF: BfExtensionField<F>> {
    pub ebcs: HashMap<EF, BitCommitExtension<F, EF>>,
    pub bc_assign: BCAssignment<F>,
}

impl<F: BfBaseField, EF: BfExtensionField<F>> ExtensionBCAssignment<F, EF> {
    pub fn new() -> Self {
        Self {
            ebcs: HashMap::new(),
            bc_assign: BCAssignment::new(),
        }
    }

    pub fn assign(&mut self, value: EF) -> &BitCommitExtension<F, EF> {
        self.ebcs.entry(value.clone()).or_insert_with(|| {
            // self.ebcs.insert(k, v);
            self.bc_assign.insert_extension(value.clone());
            let bc: BitCommitExtension<F, EF> = self.bc_assign.get_extension(value.clone());
            bc
        })
    }

    pub fn insert(&mut self, value: EF) {
        self.ebcs.entry(value.clone()).or_insert_with(|| {
            // self.ebcs.insert(k, v);
            self.bc_assign.insert_extension(value.clone());
            let bc: BitCommitExtension<F, EF> = self.bc_assign.get_extension(value.clone());
            bc
        });
    }

    pub fn get(&self, value: &EF) -> Option<&BitCommitExtension<F, EF>> {
        let b = self.ebcs.get(value);
        b
    }

    pub fn get_extension(&self, value: EF) -> BitCommitExtension<F, EF> {
        let commits = self.bc_assign.get_extension(value.clone());
        commits
    }

    pub fn assign_multi<I: Clone>(&mut self, items: I) -> Vec<&BitCommitExtension<F, EF>>
    where
        I: IntoIterator<Item = EF>,
    {
        self.insert_multi(items.clone());
        self.get_multi(items)
    }

    pub fn insert_multi<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = EF>,
    {
        for key in items {
            self.insert(key);
        }
    }

    pub fn get_multi<I>(&self, items: I) -> Vec<&BitCommitExtension<F, EF>>
    where
        I: IntoIterator<Item = EF>,
    {
        let mut bit_commits = Vec::new();
        for key in items {
            let bc: &BitCommitExtension<F, EF> = self.get(&key).unwrap();
            bit_commits.push(bc);
        }
        bit_commits
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BCAssignment<F: BfBaseField> {
    pub bcs: HashMap<F, BitCommit<F>>,
    secret_assign: SecretAssignment,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretAssignment;

impl SecretAssignment {
    pub fn new() -> Self {
        SecretAssignment
    }
    fn get_secret(&self) -> &str {
        "0000"
    }
}

impl<F: BfBaseField> BCAssignment<F> {
    pub fn new() -> Self {
        Self {
            bcs: HashMap::new(),
            // ebcs: HashMap::new(),
            secret_assign: SecretAssignment::new(),
        }
    }

    fn get_secret(&self) -> &str {
        self.secret_assign.get_secret()
    }

    pub fn force_insert(&mut self, value: F) -> &BitCommit<F> {
        let bc = BitCommit::<F>::new(self.get_secret(), value);
        self.bcs.insert(value, bc);
        self.get(value).unwrap()
    }

    pub fn get(&self, value: F) -> Option<&BitCommit<F>> {
        self.bcs.get(&value)
    }

    pub fn get_mut(&mut self, value: F) -> Option<&mut BitCommit<F>> {
        self.bcs.get_mut(&value)
    }

    pub fn assign(&mut self, value: F) -> &BitCommit<F> {
        let secret = self.secret_assign.get_secret();
        self.bcs
            .entry(value)
            .or_insert_with(|| BitCommit::<F>::new(secret, value))
    }

    pub fn assign_multi<I: Clone>(&mut self, items: I) -> Vec<&BitCommit<F>>
    where
        I: IntoIterator<Item = F>,
    {
        self.insert_multi(items.clone());
        self.get_multi(items)
    }

    pub fn insert_multi<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = F>,
    {
        for key in items {
            let secret = self.secret_assign.get_secret();
            self.bcs
                .entry(key)
                .or_insert_with(|| BitCommit::<F>::new(secret, key));
        }
    }

    pub fn get_multi<'a, I>(&'a self, items: I) -> Vec<&'a BitCommit<F>>
    where
        I: IntoIterator<Item = F>,
    {
        let mut bit_commits = Vec::new();
        for key in items {
            let bc: &'a BitCommit<F> = self.bcs.get(&key).unwrap();
            bit_commits.push(bc);
        }
        bit_commits
    }
}

impl<F: BfBaseField> BCAssignment<F> {
    pub fn insert_extension<EF: BfExtensionField<F>>(&mut self, value: EF) {
        self.insert_multi(value.as_base_slice().iter().cloned());
    }

    pub fn get_extension<EF: BfExtensionField<F>>(&self, value: EF) -> BitCommitExtension<F, EF> {
        let fs = value.as_base_slice();
        let commits = self.get_multi(fs.iter().cloned());
        BitCommitExtension::new_from_bit_commits(value, commits)
    }

    pub fn assign_extension<EF: BfExtensionField<F>>(
        &mut self,
        value: EF,
    ) -> BitCommitExtension<F, EF> {
        let fs = value.as_base_slice();
        BitCommitExtension::new_from_bit_commits(
            value.clone(),
            self.assign_multi(fs.iter().cloned()),
        )
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{AbstractExtensionField, AbstractField, PrimeField32};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    type F = BabyBear;
    type EF = p3_field::extension::BinomialExtensionField<BabyBear, 4>;

    #[test]
    fn test_assign_bitcommits() {
        use super::*;
        let key_origin = 123;
        let key = F::from_canonical_u32(key_origin);
        let bc_assign: &mut BCAssignment<F> = &mut BCAssignment::new();
        let mut bc_temp: BitCommit<F> = BitCommit::new("1223", key);
        {
            bc_assign.force_insert(key);
            let bc: &BitCommit<F> = bc_assign.get(key).unwrap();
            assert_eq!(bc.origin_value, key_origin);
            bc_temp = bc.clone();
        }

        {
            let bc1: &BitCommit<F> = bc_assign.assign(key);
            assert_eq!(bc1, &bc_temp);
        }
    }

    #[test]
    fn test_assign_extension_bitcommits() {
        let mut rng = ChaCha20Rng::seed_from_u64(0u64);
        let a = rng.gen::<EF>();

        let bc_assign: &mut BCAssignment<F> = &mut BCAssignment::new();
        // let mut bc_temp:BitCommit<F> = BitCommit::new("1223", key);
        bc_assign.insert_extension(a);
        let get_value = bc_assign.get_extension(a);
        assert_eq!(get_value.commit_message, a);

        let extension_bc_assign = &mut ExtensionBCAssignment::<F, EF>::new();
        let bc = extension_bc_assign.assign(a);
        let bc_actual = bc.clone();
        let bc_expect = extension_bc_assign.assign(a);
        assert_eq!(bc_actual, bc_expect.clone());
    }
}
