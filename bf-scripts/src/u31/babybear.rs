use crate::u31::U31Config;

pub struct BabyBearU31;
impl U31Config for BabyBearU31 {
    const MOD: u32 = 15 * (1 << 27) + 1;
}
