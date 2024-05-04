use alloc::vec;
use alloc::vec::Vec;

use bf_scripts::{execute_script, execute_script_with_inputs, BfField};
use bitcoin::taproot::TapLeaf;
use bitcoin::Script;
use itertools::izip;
use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
use p3_commit::Mmcs;
use p3_field::{Field, TwoAdicField};
use p3_matrix::Dimensions;
use p3_util::reverse_bits_len;

use crate::{
    get_leaf_index_by_query_index, BfCommitPhaseProofStep, BfQueryProof, FriConfig, FriProof,
};

#[derive(Debug)]
pub enum FriError<CommitMmcsErr> {
    InvalidProofShape,
    CommitPhaseMmcsError(CommitMmcsErr),
    FinalPolyMismatch,
    InvalidPowWitness,
}

#[derive(Debug)]
pub struct FriChallenges<F> {
    pub query_indices: Vec<usize>,
    betas: Vec<F>,
}

pub fn verify_shape_and_sample_challenges<F, M, Challenger>(
    config: &FriConfig<M>,
    proof: &FriProof<F, M, Challenger::Witness>,
    challenger: &mut Challenger,
) -> Result<FriChallenges<F>, FriError<M::Error>>
where
    F: Field,
    M: Mmcs<F, Proof = BfCommitPhaseProofStep>,
    Challenger: GrindingChallenger + CanObserve<M::Commitment> + CanSample<F>,
{
    let betas: Vec<F> = proof
        .commit_phase_commits
        .iter()
        .map(|comm| {
            challenger.observe(comm.clone());
            challenger.sample()
        })
        .collect();

    if proof.query_proofs.len() != config.num_queries {
        return Err(FriError::InvalidProofShape);
    }

    // Check PoW.
    if !challenger.check_witness(config.proof_of_work_bits, proof.pow_witness) {
        return Err(FriError::InvalidPowWitness);
    }

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;

    let query_indices: Vec<usize> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(log_max_height))
        .collect();

    Ok(FriChallenges {
        query_indices,
        betas,
    })
}
struct OpeningData<F: TwoAdicField> {
    leaf_index: usize,
    value: F,
    sibling_leaf_index: usize,
    sibling_value: F,
}
pub fn verify_challenges<F, M, Witness>(
    config: &FriConfig<M>,
    proof: &FriProof<F, M, Witness>,
    challenges: &FriChallenges<F>,
    reduced_openings: &[[&OpeningData<F>; 32]],
) -> Result<(), FriError<M::Error>>
where
    F: TwoAdicField,
    M: Mmcs<F, Proof = BfCommitPhaseProofStep>,
{
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for (&index, query_proof, ro) in izip!(
        &challenges.query_indices,
        &proof.query_proofs,
        reduced_openings
    ) {
        let folded_eval = verify_query(
            config,
            &proof.commit_phase_commits,
            index,
            query_proof,
            &challenges.betas,
            ro,
            log_max_height,
        )?;

        if folded_eval != proof.final_poly {
            return Err(FriError::FinalPolyMismatch);
        }
    }

    Ok(())
}

fn verify_query<F, M>(
    config: &FriConfig<M>,
    commit_phase_commits: &[M::Commitment],
    mut index: usize,
    proof: &BfQueryProof,
    betas: &[F],
    reduced_openings: &[&OpeningData<F>; 32],
    log_max_height: usize,
) -> Result<F, FriError<M::Error>>
where
    F: TwoAdicField,
    M: Mmcs<F, Proof = BfCommitPhaseProofStep>,
{
    let mut folded_eval = F::zero();
    let mut r = F::zero();
    let mut y_r = F::zero();
    let mut neg_r = F::zero();
    let mut y_neg_r = F::zero();

    let mut x = F::two_adic_generator(log_max_height)
        .exp_u64(reverse_bits_len(index, log_max_height) as u64);

    for (log_folded_height, commit, step, &beta) in izip!(
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    ) {
        let index_sibling = index ^ 1;
        let index_pair = index >> 1;

        let opening = reduced_openings[log_folded_height + 1];
        assert_eq!(opening.leaf_index, index);
        assert_eq!(opening.sibling_leaf_index, index_sibling);

        // Todo: get x p(x) -x p(-x) value
        r = x;
        neg_r = x * F::two_adic_generator(1);
        assert_eq!(y_r, opening.value);
        // y_r = opening.value;
        y_neg_r = opening.sibling_value;

        let mut evals = vec![y_r; 2];
        evals[index_sibling % 2] = y_neg_r;

        let mut xs = vec![r; 2];
        xs[index_sibling % 2] = neg_r;

        if let TapLeaf::Script(script, ver) = step.leaf_node.clone() {
            // Todo: Execute the script with input
            let res = execute_script(script);
            assert_eq!(res.success, true);
        } else {
            // None
        }

        config
            .mmcs
            .verify_taptree(step, commit)
            .map_err(FriError::CommitPhaseMmcsError)?;

        // let mut xs: [F; 2] = [x; 2];
        // // calculate the x-coordiate using index*generator
        // xs[index_sibling % 2] *= F::two_adic_generator(1);// with subgroup [1,generator]
        // interpolate and evaluate at beta
        y_r = evals[0] + (beta - xs[0]) * (evals[1] - evals[0]) / (xs[1] - xs[0]);

        index = index_pair;
        x = x.square();
    }

    debug_assert!(index < config.blowup(), "index was {}", index);
    debug_assert_eq!(x.exp_power_of_2(config.log_blowup), F::one());

    Ok(folded_eval)
}
