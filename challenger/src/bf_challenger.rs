use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ChallengeField, PermutationField, PrimeField32};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicPermutation, Hash};
use tracing::instrument;

use crate::{CanObserve, CanSample, CanSampleBits};

/// A challenger that operates natively on PF but produces challenges of F: PrimeField32.

// BF_Fri uses Blake3 or Sha256 as Permutation Function
// The type of the taptree root is [u8;32], which is the input of the permutation function,
// and we expect to sample the babybear or babybear-extension point to challenge
// The input buffer is Vec<PF>
// The output buffer is Vec<PF> and we can mod F::P to get Vec<F>

pub trait BfGrindingChallenger:
    CanObserve<Self::Witness> + CanSampleBits<usize> + Sync + Clone
{
    type Witness: PermutationField<4>;

    fn grind(&mut self, bits: usize) -> Self::Witness;

    #[must_use]
    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

impl<F, PF, P, const WIDTH: usize> BfGrindingChallenger for BfChallenger<F, PF, P, WIDTH>
where
    F: ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    type Witness = PF;

    #[instrument(name = "grind for proof-of-work witness", skip_all)]
    fn grind(&mut self, bits: usize) -> Self::Witness {
        let witness = (0..PF::mod_p())
            .into_par_iter()
            .map(|i| PF::from_u64(i as u64))
            .find_any(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");
        assert!(self.check_witness(bits, witness));
        witness
    }
}

#[derive(Clone, Debug)]
pub struct BfChallenger<F, PF, P, const WIDTH: usize>
where
    F: PrimeField32,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    sponge_state: [PF; WIDTH],
    input_buffer: Vec<PF>,
    output_buffer: Vec<PF>,
    permutation: P,
    _marker: PhantomData<F>,
}

impl<F, PF, P, const WIDTH: usize> BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    pub fn new(permutation: P) -> Result<Self, String> {
        Ok(Self {
            sponge_state: [PF::default(); WIDTH],
            input_buffer: vec![],
            output_buffer: vec![],
            permutation,
            _marker: PhantomData,
        })
    }
}

impl<F, PF, P, const WIDTH: usize> BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn duplexing(&mut self) {
        assert!(self.input_buffer.len() <= WIDTH);

        for i in 0..self.input_buffer.len() {
            self.sponge_state[i] = self.input_buffer[i];
        }
        self.input_buffer.clear();

        // Apply the permutation.
        self.permutation.permute_mut(&mut self.sponge_state);

        self.output_buffer.clear();
        for i in 0..self.sponge_state.len() {
            self.output_buffer.push(self.sponge_state[i]);
        }
    }
}

impl<F, PF, P, const WIDTH: usize> CanObserve<PF> for BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32 + ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, value: PF) {
        // Any buffered output is now invalid.
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == WIDTH / 2 {
            self.duplexing();
        }
    }
}

impl<F, PF, const N: usize, P, const WIDTH: usize> CanObserve<[PF; N]>
    for BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32 + ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, values: [PF; N]) {
        for value in values {
            self.observe(value);
        }
    }
}

impl<F, PF, const N: usize, P, const WIDTH: usize> CanObserve<Hash<PF, PF, N>>
    for BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32 + ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, values: Hash<PF, PF, N>) {
        for pf_val in values {
            self.observe(pf_val);
        }
    }
}

// for TrivialPcs
impl<F, PF, P, const WIDTH: usize> CanObserve<Vec<Vec<PF>>> for BfChallenger<F, PF, P, WIDTH>
where
    F: PrimeField32 + ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, valuess: Vec<Vec<PF>>) {
        for values in valuess {
            for value in values {
                self.observe(value);
            }
        }
    }
}

impl<F, PF, P, const WIDTH: usize> CanSample<F> for BfChallenger<F, PF, P, WIDTH>
where
    F: ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn sample(&mut self) -> F {
        // If we have buffered inputs, we must perform a duplexing so that the challenge will
        // reflect them. Or if we've run out of outputs, we must perform a duplexing to get more.
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing();
        }

        let value = self
            .output_buffer
            .pop()
            .expect("Output buffer should be non-empty");

        F::from_pf(&value)
    }
}

// impl<F, EF, PF, P, const WIDTH: usize> CanSample<EF> for BfChallenger<F, PF, P, WIDTH>
// where
//     F: ChallengeField<4>,
//     EF: ExtensionField<F>,
//     PF: PermutationField<4>,
//     P: CryptographicPermutation<[PF; WIDTH]>,
// {
//     fn sample(&mut self) -> EF {
//         EF::from_base_fn(|_| {
//             // If we have buffered inputs, we must perform a duplexing so that the challenge will
//             // reflect them. Or if we've run out of outputs, we must perform a duplexing to get more.
//             if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
//                 self.duplexing();
//             }

//             let value = self.output_buffer
//                 .pop()
//                 .expect("Output buffer should be non-empty");

//             F::from_pf(&value)
//         })
//     }
// }

impl<F, PF, P, const WIDTH: usize> CanSampleBits<usize> for BfChallenger<F, PF, P, WIDTH>
where
    F: ChallengeField<4>,
    PF: PermutationField<4>,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        debug_assert!(bits < (usize::BITS as usize));
        debug_assert!((1 << bits) < F::ORDER_U64);
        let rand_f: F = self.sample();
        let rand_usize = rand_f.as_canonical_u64() as usize;
        rand_usize & ((1 << bits) - 1)
    }
}
