use std::collections::HashMap;
use std::{array, mem};

use p3_baby_bear::BabyBear;

use crate::{BfBaseField, BfExtensionField, BitCommit, BitCommitExtension, BitsCommitment};
use std::sync::Mutex;

use once_cell::sync::Lazy;
static BC_ASSIGN: Lazy<Mutex<BCAssignment<BabyBear>>> = Lazy::new(|| {
    Mutex::new(BCAssignment::<BabyBear>::new())
});


#[derive(Debug, Clone, Default)]
pub struct BCAssignment<F: BfBaseField> {
    pub bcs: HashMap<F, BitCommit<F>>,
    secret_assign: SecretAssignment,
}

#[derive(Debug, Clone, Default)]
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
            secret_assign: SecretAssignment::new(),
        }
    }

    fn get_secret(&self) -> &str {
        self.secret_assign.get_secret()
    }

    pub fn assign_bit_commit(&mut self, value: F) -> &BitCommit<F> {
        self.get_or_insert(value)
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

    pub fn get_or_insert(&mut self, value: F) -> &BitCommit<F> {
        let secret = self.secret_assign.get_secret();
        self.bcs
            .entry(value)
            .or_insert_with(|| BitCommit::<F>::new(secret, value))
    }

    pub fn get_or_insert_with(
        &mut self,
        value: F,
        f: impl FnOnce() -> BitCommit<F>,
    ) -> &BitCommit<F> {
        self.bcs.entry(value).or_insert_with(f)
    }

    pub fn insert_multi<'a, I>(&mut self, items: I)
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

    pub fn get_multi<I>(&self, items: I) -> Vec<&BitCommit<F>>
    where
        I: IntoIterator<Item = F>,
    {
        let mut bit_commits = Vec::new();
        for key in items {
            let bc = self.bcs.get(&key).unwrap();
            bit_commits.push(bc);
        }
        bit_commits
    }
}

impl<F: BfBaseField> BCAssignment<F> {
    pub fn insert_extension<EF: BfExtensionField<F>>(&mut self, value: EF) {
        self.insert_multi(value.as_base_slice().iter().cloned());
    }

    pub fn get_extension<EF: BfExtensionField<F>>(&self, value: EF) -> Vec<&BitCommit<F>> {
        let fs = value.as_base_slice();
        self.get_multi(fs.iter().cloned())
    }

    pub fn get_extension1<EF: BfExtensionField<F>>(&self, value: EF) -> BitCommitExtension<F, EF> {
        let commits = self.get_extension(value);
        BitCommitExtension::new_from_bit_commits(value, commits)
    }

    pub fn get_or_insert_extension<EF: BfExtensionField<F>>(
        &mut self,
        secret: &[&str],
        value: EF,
    ) -> Vec<&BitCommit<F>> {
        let fs = value.as_base_slice();
        self.insert_multi(fs.iter().cloned());
        self.get_extension(value)
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
            let bc1: &BitCommit<F> = bc_assign.get_or_insert(key);
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
        let get_value = bc_assign.get_extension1(a);
        assert_eq!(get_value.commit_message, a);
    }
}
