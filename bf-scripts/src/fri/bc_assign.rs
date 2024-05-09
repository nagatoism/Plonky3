use std::collections::HashMap;

use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

use crate::{bit_comm::BitCommitment, BfField};
// static BC_ASSIGN: Lazy<Mutex<BCAssignment<BabyBear>>> = Lazy::new(|| {
//     Mutex::new(BCAssignment::<BabyBear>::new())
// });



#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BCAssignment<F: BfField> {
    pub bcs: HashMap<Vec<u32>, BitCommitment<F>>,
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

impl<F: BfField> BCAssignment<F> {
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

    pub fn force_insert(&mut self, value: F,) -> &BitCommitment<F> {
        let u32_rep = value.as_u32_array().to_vec();
        let bc = BitCommitment::<F>::new(self.get_secret(), value);
        self.bcs.insert(value, bc);
        self.get(value).unwrap()
    }

    pub fn get(&self, value: F) -> Option<&BitCommitment<F>> {
        self.bcs.get(&value)
    }

    pub fn get_mut(&mut self, value: F) -> Option<&mut BitCommitment<F>> {
        self.bcs.get_mut(&value)
    }

    pub fn assign(&mut self, value: F) -> &BitCommitment<F> {
        let secret = self.secret_assign.get_secret();
        self.bcs
            .entry(value)
            .or_insert_with(|| BitCommitment::<F>::new(secret, value))
    }

    pub fn assign_multi<I: Clone>(&mut self, items: I) -> Vec<&BitCommitment<F>>
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
                .or_insert_with(|| BitCommitment::<F>::new(secret, key));
        }
    }

    pub fn get_multi<'a, I>(&'a self, items: I) -> Vec<&'a BitCommitment<F>>
    where
        I: IntoIterator<Item = F>,
    {
        let mut bit_commits = Vec::new();
        for key in items {
            let bc: &'a BitCommitment<F> = self.bcs.get(&key).unwrap();
            bit_commits.push(bc);
        }
        bit_commits
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
        let mut bc_temp: BitCommitment<F> = BitCommitment::new("1223", key);
        {
            bc_assign.force_insert(key);
            let bc: &BitCommitment<F> = bc_assign.get(key).unwrap();
            assert_eq!(bc.origin_value, key_origin);
            bc_temp = bc.clone();
        }

        {
            let bc1: &BitCommitment<F> = bc_assign.assign(key);
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
