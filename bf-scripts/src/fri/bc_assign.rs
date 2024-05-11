use std::collections::HashMap;

use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

use crate::{bit_comm::BitCommitment, bit_comm_u32::BitCommitmentU32, BfField};
// static BC_ASSIGN: Lazy<Mutex<BCAssignment<BabyBear>>> = Lazy::new(|| {
//     Mutex::new(BCAssignment::<BabyBear>::new())
// });



#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BCAssignment {
    pub bcs: HashMap<u32, BitCommitmentU32>,
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

impl BCAssignment {
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

    pub fn force_insert(&mut self, value: u32,) -> &BitCommitmentU32 {
        let bc = BitCommitmentU32::new(self.get_secret(), value);
        self.bcs.insert(value, bc);
        self.get(value).unwrap()
    }

    pub fn get(&self, value: u32) -> Option<&BitCommitmentU32> {
        self.bcs.get(&value)
    }

    pub fn get_mut(&mut self, value: u32) -> Option<&mut BitCommitmentU32> {
        self.bcs.get_mut(&value)
    }

    pub fn assign(&mut self, value: u32) -> &BitCommitmentU32 {
        let secret = self.secret_assign.get_secret();
        self.bcs
            .entry(value)
            .or_insert_with(|| BitCommitmentU32::new(secret, value))
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
        let bc_assign: &mut BCAssignment= &mut BCAssignment::new();
        let mut bc_temp: BitCommitment = BitCommitment::new("1223", key);
        {
            bc_assign.force_insert(key);
            let bc: &BitCommitment = bc_assign.get(key).unwrap();
            assert_eq!(bc.origin_value, key_origin);
            bc_temp = bc.clone();
        }

        {
            let bc1: &BitCommitment<F> = bc_assign.assign(key);
            assert_eq!(bc1, &bc_temp);
        }
    }
}
