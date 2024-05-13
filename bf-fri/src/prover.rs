use alloc::vec;
use alloc::vec::Vec;

use itertools::Itertools;
use p3_challenger::{BfGrindingChallenger, CanObserve, CanSample, GrindingChallenger};
use p3_field::{Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use tracing::{info_span, instrument};

use crate::bf_mmcs::BFMmcs;
use crate::fold_even_odd::fold_even_odd;
use crate::{BfCommitPhaseProofStep, BfQueryProof, FriConfig, FriProof};

#[instrument(name = "FRI prover", skip_all)]
pub fn bf_prove<F, M, Challenger>(
    config: &FriConfig<M>,
    input: &[Option<Vec<F>>; 32],
    challenger: &mut Challenger,
) -> (FriProof<F, M, Challenger::Witness>, Vec<usize>)
where
    F: TwoAdicField,
    M: BFMmcs<F, Proof = BfCommitPhaseProofStep>,
    Challenger: BfGrindingChallenger + CanObserve<M::Commitment> + CanSample<F>,
{
    // ToDo: support Muti-Matrixs
    // assert_eq!(input.len(), 1);

    // 1. rposition start iterator from the end and calculate the valid leagth of the polynomial want commit
    let log_max_height = input.iter().rposition(Option::is_some).unwrap();

    let commit_phase_result = bf_commit_phase(config, input, log_max_height, challenger);

    let pow_witness = challenger.grind(config.proof_of_work_bits);

    let query_indices: Vec<usize> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(log_max_height))
        .collect();

    let query_proofs = info_span!("query phase").in_scope(|| {
        query_indices
            .iter()
            .map(|&index| bf_answer_query(config, &commit_phase_result.data, index))
            .collect()
    });

    (
        FriProof {
            commit_phase_commits: commit_phase_result.commits,
            query_proofs,
            final_poly: commit_phase_result.final_poly,
            pow_witness,
        },
        query_indices,
    )
}

fn bf_answer_query<F, M>(
    config: &FriConfig<M>,
    commit_phase_commits: &[M::ProverData],
    index: usize,
) -> BfQueryProof
where
    F: Field,
    M: BFMmcs<F, Proof = BfCommitPhaseProofStep>,
{
    let commit_phase_openings = commit_phase_commits
        .iter()
        .enumerate()
        .map(|(i, commit)| {
            let index_i = index >> i;

            let proof = config.mmcs.open_taptree(index_i, commit);
            proof
        })
        .collect();

    BfQueryProof {
        commit_phase_openings,
    }
}
// Commit two adjacent points to a leaf node
pub const DEFAULT_MATRIX_WIDTH: usize = 2;

#[instrument(name = "commit phase", skip_all)]
fn bf_commit_phase<F, M, Challenger>(
    config: &FriConfig<M>,
    input: &[Option<Vec<F>>; 32],
    log_max_height: usize,
    challenger: &mut Challenger,
) -> CommitPhaseResult<F, M>
where
    F: TwoAdicField,
    M: BFMmcs<F>,
    Challenger: CanObserve<M::Commitment> + CanSample<F>,
{
    let mut current = input[log_max_height].as_ref().unwrap().clone();

    let mut commits = vec![];
    let mut data = vec![];

    for log_folded_height in (config.log_blowup..log_max_height).rev() {
        let leaves = RowMajorMatrix::new(current.clone(), DEFAULT_MATRIX_WIDTH);
        let (commit, prover_data) = config.mmcs.commit_matrix(leaves);
        challenger.observe(commit.clone());
        commits.push(commit);
        data.push(prover_data);

        let beta: F = challenger.sample();
        current = fold_even_odd(current, beta);

        // if let Some(v) = &input[log_folded_height] {
        //     current.iter_mut().zip_eq(v).for_each(|(c, v)| *c += *v);
        // }
    }

    // We should be left with `blowup` evaluations of a constant polynomial.
    assert_eq!(current.len(), config.blowup());
    let final_poly = current[0];
    for x in current {
        assert_eq!(x, final_poly);
    }

    CommitPhaseResult {
        commits,
        data,
        final_poly,
    }
}

struct CommitPhaseResult<F: Send + Sync, M: BFMmcs<F>> {
    commits: Vec<M::Commitment>,
    data: Vec<M::ProverData>,
    final_poly: F,
}

#[cfg(test)]
mod tests {

    use bf_scripts::BabyBear;
    use p3_challenger::{BfChallenger, BfGrindingChallenger};
    use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
    use p3_field::{AbstractField, PrimeField64, U32};
    use p3_matrix::util::reverse_matrix_index_bits;
    use p3_matrix::Matrix;
    use p3_symmetric::{CryptographicPermutation, Permutation};
    use p3_util::log2_strict_usize;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::mmcs::taptree_mmcs::{TreeRoot, ROOT_WIDTH};
    use crate::taptree_mmcs::TapTreeMmcs;

    type PF = U32;
    const WIDTH: usize = ROOT_WIDTH;
    type F = BabyBear;
    #[derive(Clone)]
    struct TestPermutation {}

    impl Permutation<TreeRoot> for TestPermutation {
        fn permute(&self, mut input: TreeRoot) -> TreeRoot {
            self.permute_mut(&mut input);
            input
        }

        fn permute_mut(&self, input: &mut TreeRoot) {
            input.reverse();
        }
    }

    impl CryptographicPermutation<TreeRoot> for TestPermutation {}

    type Val = BabyBear;
    type ValMmcs = TapTreeMmcs<Val>;
    // type Challenge =
    // type Challenge = ValMmcs::Commitment;
    type MyFriConfig = FriConfig<ValMmcs>;

    #[test]
    fn test_commit_phase() {
        let permutation = TestPermutation {};
        let mut challenger =
            BfChallenger::<F, PF, TestPermutation, WIDTH>::new(permutation).unwrap();
        let mmcs = ValMmcs::new();
        let fri_config = FriConfig {
            log_blowup: 1,
            num_queries: 10,
            proof_of_work_bits: 8,
            mmcs,
        };

        let dft = Radix2Dit::default();

        let shift = Val::generator();
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let ldes: Vec<RowMajorMatrix<Val>> = (9..10)
            .map(|deg_bits| {
                let evals = RowMajorMatrix::<Val>::rand_nonzero(&mut rng, 1 << deg_bits, 1);
                let mut lde = dft.coset_lde_batch(evals, 1, shift);
                reverse_matrix_index_bits(&mut lde);
                lde
            })
            .collect();

        let alpha = BabyBear::one();
        let input: [_; 32] = core::array::from_fn(|log_height| {
            let matrices_with_log_height: Vec<&RowMajorMatrix<Val>> = ldes
                .iter()
                .filter(|m| log2_strict_usize(m.height()) == log_height)
                .collect();
            if matrices_with_log_height.is_empty() {
                None
            } else {
                let reduced: Vec<BabyBear> = (0..(1 << log_height))
                    .map(|r| {
                        alpha
                            .powers()
                            .zip(matrices_with_log_height.iter().flat_map(|m| m.row(r)))
                            .map(|(alpha_pow, v)| alpha_pow * v)
                            .sum()
                    })
                    .collect();
                Some(reduced)
            }
        });

        let (proof, idxs) = bf_prove(&fri_config, &input, &mut challenger);
    }
}
