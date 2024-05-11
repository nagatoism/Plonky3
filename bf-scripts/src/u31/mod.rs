use std::usize;

use bitcoin::opcodes::{OP_ADD, OP_FROMALTSTACK, OP_LSHIFT, OP_SWAP, OP_TOALTSTACK};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::script;

use crate::fri::BfField;
use crate::{pushable, unroll};
mod m31;
pub use m31::*;

mod babybear;
pub use babybear::BabyBearU31;

pub trait U31Config {
    const MOD: u32;
}

fn u31_adjust<M: U31Config>() -> Script {
    script! {
        OP_DUP
        0 OP_LESSTHAN
        OP_IF { M::MOD } OP_ADD OP_ENDIF
    }
}

pub fn u31_add<M: U31Config>() -> Script {
    script! {
        { M::MOD } OP_SUB
        OP_ADD
        { u31_adjust::<M>() }
    }
}

pub fn u31_double<M: U31Config>() -> Script {
    script! {
        OP_DUP
        { u31_add::<M>() }
    }
}

pub fn u31_sub<M: U31Config>() -> Script {
    script! {
        OP_SUB
        { u31_adjust::<M>() }
    }
}

pub fn u31_to_bits() -> Script {
    script! {
        {
            unroll(30, |i| {
                let a = 1 << (30 - i);
                let b = a - 1;
                script! {
                    OP_DUP
                    { b } OP_GREATERTHAN
                    OP_SWAP OP_OVER
                    OP_IF { a } OP_SUB OP_ENDIF
                }
        })}
    }
}

pub fn u31_mul<M: U31Config>() -> Script {
    script! {
        u31_to_bits
        { unroll(31, |_| script! {
            OP_TOALTSTACK
        }) }
        0
        OP_SWAP
        OP_DUP
        { u31_double::<M>() }
        OP_2DUP
        { u31_add::<M>() }
        0
        OP_FROMALTSTACK
        OP_IF
            3 OP_PICK
            { u31_add::<M>() }
        OP_ENDIF
        { u31_double::<M>() }
        { u31_double::<M>() }
        { unroll(14, |_| script! {
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_ADD
            4 OP_SWAP OP_SUB OP_PICK
            { u31_add::<M>() }
            { u31_double::<M>() }
            { u31_double::<M>() }
        })}
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_SWAP OP_DUP OP_ADD OP_ADD
        4 OP_SWAP OP_SUB OP_PICK
        { u31_add::<M>() }
        OP_TOALTSTACK
        OP_2DROP OP_2DROP
        OP_FROMALTSTACK
    }
}

pub fn convert_digits_to_u32<const DIGITS_BITSIZE: usize, const DIGITS_NUM: usize>() -> Script {
    //0x87654321;
    // The stack before convert_D_to_u31 looks like(DIGITS_BITSIZE=8,DIGITS_NUM=4 ):
    // 0x21
    // 0x43
    // 0x65
    // 0x87
    script! {
        // The Top Element of the stack is the lowest-bit-value and does not need to be dealed.
        OP_TOALTSTACK
        for i in 1..DIGITS_NUM{
            // STACK:[a,b]  OP_LSHIFT:Logical left shift b bits. Sign data is discarded
            {DIGITS_BITSIZE}
            OP_SWAP
            OP_LSHIFT
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
        }
    }
}

// y_0(r)= g_0,1(r^2) + r g_0,2(r^2)
// y_0(-r)= g_0,1(r^2) -r g_0,2(r^2)
// y_1(r^2) = g_0,1(r^2) + v_0 g_0,2(r^2)
pub fn fold_degree<M: U31Config>(
    degree: u32,
    x: u32,
    y_0_x: u32,
    y_0_neg_x: u32,
    beta: u32,
    y_1_x_quare: u32,
) -> Script {
    script! {

        // calculate 2 * g_0,1(r^2)
        {y_0_x}
        {y_0_neg_x}
        { u31_add::<M>() }
        // calculate 2 * x * g_0,1(r^2)
        { x}
        { u31_mul::<M>()}
        OP_TOALTSTACK

        // calculate 2 * x * g_0,2(r^2)
        {y_0_x}
        {y_0_neg_x}
        { u31_sub::<M>() }
        // calculate 2 * r * beta * g_0,2(r^2)
        {beta}
        {u31_mul::<M>()}
        // calaulate (2 * r * beta * g_0,2(r^2)) + (2 * r * g_0,1(r^2))
        OP_FROMALTSTACK
        { u31_add::<M>() }
        OP_TOALTSTACK

        // calculate 2*r*y_1(r^2)
        {y_1_x_quare}
        {u31_double::<M>()}
        {x}
        {u31_mul::<M>()}

        // Check Equal
        // y_1(r^2) = g_0,1(r^2) + beta g_0,2(r^2)
        // 2r y_1(r^2) = 2r g_0,1(r^2) + 2r beta g_0,2(r^2)
        OP_FROMALTSTACK
        OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use bitcoin::opcodes::OP_EQUAL;
    use bitcoin::Script;
    use p3_baby_bear::BabyBear;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{execute_script, BfField};

    #[test]
    fn test_folding_poly() {
        let beta = BabyBear::from_u32(2);

        let mut y0_vector = Vec::new();
        let mut y1_vector = Vec::new();

        let y0 = vec![1, 2013265920];
        let y1 = vec![2];
        y0_vector.push(y0);
        y1_vector.push(y1);

        let y0 = vec![6, 569722814, 2013265919, 1443543103];
        let y1 = vec![10, 2013265915];
        y0_vector.push(y0);
        y1_vector.push(y1);

        let y0 = vec![
            120, 1124803747, 1939037439, 700342088, 265625335, 1911300408, 1407786753, 1273260695,
            2013265913, 740005210, 605479152, 101965497, 1747640570, 1312923817, 74228466,
            888462158,
        ];
        let y1 = vec![
            184, 1790580475, 796876005, 196828417, 2013265897, 1816437456, 1216389868, 222685398,
        ];
        y0_vector.push(y0);
        y1_vector.push(y1);

        for (index, log_n) in vec![1, 2, 4].iter().enumerate() {
            let n = 1 << log_n;
            let y0 = y0_vector[index].clone();
            let y1 = y1_vector[index].clone();

            let subgroup = BabyBear::sub_group(*log_n as usize);

            for j in 0..n as usize {
                let x_index = j;
                let x_nge_index = (n / 2 + x_index) % n;
                let x = subgroup[x_index as usize];
                let y0_x = y0[x_index];
                let y0_neg_x = y0[x_nge_index];
                let y_1_x_quare = y1[x_index % (n / 2)];
                let script = fold_degree::<BabyBearU31>(
                    2,
                    x.as_u32_vec()[0],
                    y0_x,
                    y0_neg_x,
                    beta.as_u32_vec()[0],
                    y_1_x_quare,
                );

                let result = execute_script(script);
                assert!(result.success);
            }
        }
    }

    #[test]
    fn test_u32_add() {
        let v1: u32 = 0x1BCDEF12;
        let v2: u32 = 0x1BCDEFf0;
        let v1_babybear = v1 % BabyBearU31::MOD;
        let v2_babybear = v2 % BabyBearU31::MOD;
        let sum_babybear = (v1_babybear + v2_babybear) % BabyBearU31::MOD;
        let script = script! {
            { v1_babybear }
            { v2_babybear }
            { u31_add::<M31>() }
            { sum_babybear }
            OP_EQUAL
        };
        println!("{:}", script);
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u31_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);
        eprintln!("u31 add: {}", u31_add::<BabyBearU31>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let sum_m31 = (a_m31 + b_m31) % M31::MOD;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_add::<M31>() }
                { sum_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBearU31::MOD;
            let b_babybear = b % BabyBearU31::MOD;
            let sum_babybear = (a_babybear + b_babybear) % BabyBearU31::MOD;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_add::<BabyBearU31>() }
                { sum_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }

    #[test]
    fn test_u31_sub() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);
        eprintln!("u31 sub: {}", u31_sub::<BabyBearU31>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let diff_m31 = (M31::MOD + a_m31 - b_m31) % M31::MOD;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_sub::<M31>() }
                { diff_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBearU31::MOD;
            let b_babybear = b % BabyBearU31::MOD;
            let diff_babybear = (BabyBearU31::MOD + a_babybear - b_babybear) % BabyBearU31::MOD;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_sub::<BabyBearU31>() }
                { diff_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }

    #[test]
    fn test_u31_to_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let m31 = a % M31::MOD;

            let mut bits = vec![];
            let mut cur = m31;
            for _ in 0..31 {
                bits.push(cur % 2);
                cur >>= 1;
            }
            assert_eq!(cur, 0);

            let script = script! {
                { m31 }
                u31_to_bits
                { unroll(30, |i| script! {
                    { bits[i as usize] } OP_EQUALVERIFY
                })}
                { bits[30] } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let babybear = a % BabyBearU31::MOD;

            let mut bits = vec![];
            let mut cur = babybear;
            for _ in 0..31 {
                bits.push(cur % 2);
                cur >>= 1;
            }
            assert_eq!(cur, 0);

            let script = script! {
                { babybear }
                u31_to_bits
                { unroll(30, |i| script! {
                    { bits[i as usize] } OP_EQUALVERIFY
                })}
                { bits[30] } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_u31_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(6u64);
        eprintln!("u31 mul: {}", u31_mul::<BabyBearU31>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let prod_m31 =
                ((((a_m31 as u64) * (b_m31 as u64)) % (M31::MOD as u64)) & 0xffffffff) as u32;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_mul::<M31>() }
                { prod_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBearU31::MOD;
            let b_babybear = b % BabyBearU31::MOD;
            let prod_babybear = ((((a_babybear as u64) * (b_babybear as u64))
                % (BabyBearU31::MOD as u64))
                & 0xffffffff) as u32;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_mul::<BabyBearU31>() }
                { prod_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }
}
