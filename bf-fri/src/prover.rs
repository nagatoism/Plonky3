use alloc::vec;
use alloc::vec::Vec;

use itertools::Itertools;
use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
use p3_commit::{DirectMmcs, Mmcs};
use p3_field::{Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use tracing::{info_span, instrument};

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
    M: DirectMmcs<F, Proof = BfCommitPhaseProofStep>,
    Challenger: GrindingChallenger + CanObserve<M::Commitment> + CanSample<F>,
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
    M: Mmcs<F, Proof = BfCommitPhaseProofStep>,
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
    M: DirectMmcs<F>,
    Challenger: CanObserve<M::Commitment> + CanSample<F>,
{
    let mut current = input[log_max_height].as_ref().unwrap().clone();

    let mut commits = vec![];
    let mut data = vec![];

    for _log_folded_height in (config.log_blowup..log_max_height).rev() {
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

struct CommitPhaseResult<F, M: Mmcs<F>> {
    commits: Vec<M::Commitment>,
    data: Vec<M::ProverData>,
    final_poly: F,
}
