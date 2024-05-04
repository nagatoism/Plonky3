use bitcoin::psbt::Output;
pub use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::{
    AbstractExtensionField, AbstractField, PackedValue, PrimeField, PrimeField32, TwoAdicField,
};
use rand::Rng;
pub trait BfField: AbstractField + TwoAdicField + Clone + Copy {
    // type AsU32Output;
    const BIS_SIZE: usize;
    const MOD: u32;
    const N0: usize;
    const N1: usize;
    const N: usize;

    fn from_u32(data: u32) -> Self {
        Self::from_canonical_u32(data)
    }
    fn group_genreator(group_bit_size: usize) -> Self {
        Self::two_adic_generator(group_bit_size)
    }

    fn sub_group(group_bit_size: usize) -> Vec<Self> {
        let generator = Self::group_genreator(group_bit_size);
        let group_size = 1 << group_bit_size;
        // let mut subgroups = Vec::with_capacity(2^group_bit_size);
        let mut subgroups = Vec::new();
        let mut acc = generator;
        subgroups.push(Self::one());
        for i in 0..group_size - 1 {
            subgroups.push(acc);
            acc = acc * generator;
        }
        subgroups
    }

    fn field_mod() -> Self {
        Self::from_wrapped_u32(Self::MOD)
    }
}

pub trait BfBaseField: BfField + PrimeField32 {
    fn as_u32(&self) -> u32;
}

pub trait FieldAsSlice: BfField {
    fn as_slice(&self) -> &[u32];
}

pub trait BfExtensionField<Base: BfBaseField>: BfField + AbstractExtensionField<Base> {
    type BfBase: BfBaseField;
}
impl BfField for BabyBear {
    const BIS_SIZE: usize = 32;
    const MOD: u32 = 0x78000001;
    const N: usize = 10;
    const N0: usize = 8;
    const N1: usize = 2;
}

impl BfBaseField for BabyBear {
    fn as_u32(&self) -> u32 {
        self.as_canonical_u32()
    }
}

// impl FieldAsSlice for BabyBear {
//     fn as_slice<'a>(&self) -> &'a [u32]{
//         let array = [self.as_canonical_u32()];
//         &array
//     }
// }
// type ExtensionBab = BinomialExtensionField<BabyBear, 4>;
impl BfField for BinomialExtensionField<BabyBear, 4> {
    // type AsU32Output = Vec<u32>;
    const BIS_SIZE: usize = 32;
    const MOD: u32 = 0x78000001;
    const N: usize = 10;
    const N0: usize = 8;
    const N1: usize = 2;
}

impl BfExtensionField<BabyBear> for BinomialExtensionField<BabyBear, 4> {
    type BfBase = BabyBear;
}

mod tests {
    use super::*;
    #[test]
    fn test_subgroup() {
        let generator = BabyBear::group_genreator(2);
        assert_eq!(
            generator * generator * generator * generator,
            BabyBear::one()
        );

        let subgroups = BabyBear::sub_group(2);
        let subgroups_size: usize = 1 << 2;
        assert_eq!(subgroups.len(), subgroups_size);
        subgroups
            .iter()
            .for_each(|v| println!("{:}", v.as_canonical_u32()));

        assert_eq!(BabyBear::field_mod() - subgroups[0], subgroups[2]);
    }

    #[test]
    fn test_from_to_u32() {
        let n = 0x1234;
        let b_n = BabyBear::from_u32(n);
        assert_eq!(n, b_n.as_u32());
    }
}

// impl NativeField for u32{
//     const BIS_SIZE:usize = 32;
//     fn as_u32(&self) -> u32{
//         return *self;
//     }

//     fn from_u32(data: u32) -> Self{
//         return data;
//     }

//     fn group_genreator(group_size: u32) -> Self {
//         return 1
//     }
// }
