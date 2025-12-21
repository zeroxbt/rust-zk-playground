use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::merkle::spec::{DEPTH, MERKLE_NODE_DST};
use ark_ff::Field;

pub fn compute_root(
    cs: &ConstraintSystemRef<Fr>,
    sponge: &SpongeGadget<PoseidonPermutation, 3, 2>,
    leaf: State,
    path: &[State; DEPTH],
    index_bits: &[State; DEPTH],
) -> Result<State, SynthesisError> {
    let mut cur = leaf;
    for (&sib, &b) in path.iter().zip(index_bits.iter()) {
        enforce_bit(cs, b)?;
        let left = calculate_left(cs, cur, sib, b)?;
        let right = calculate_right(cs, cur, sib, b)?;
        cur = sponge.hash_with_dst(cs, &[left, right], Some(MERKLE_NODE_DST), 1)?;
    }

    Ok(cur)
}

fn enforce_bit(cs: &ConstraintSystemRef<Fr>, b: State) -> Result<(), SynthesisError> {
    // Enforce boolean: b * (b - 1) = 0
    cs.enforce_constraint(
        LinearCombination::from(b.var),
        LinearCombination::from(b.var) - (Fr::ONE, Variable::One),
        LinearCombination::<Fr>::zero(),
    )?;

    Ok(())
}

fn calculate_left(
    cs: &ConstraintSystemRef<Fr>,
    cur: State,
    sib: State,
    b: State,
) -> Result<State, SynthesisError> {
    let t_val = sib.val - cur.val;
    let t_var = cs.new_witness_variable(|| Ok(t_val))?;

    // Enforce: sib - cur = tmp
    cs.enforce_constraint(
        LinearCombination::from(sib.var) + (Fr::from(-1), cur.var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(t_var),
    )?;

    let m_val = b.val * t_val;
    let m_var = cs.new_witness_variable(|| Ok(m_val))?;

    // Enforce: b * t = m
    cs.enforce_constraint(
        LinearCombination::from(b.var),
        LinearCombination::from(t_var),
        LinearCombination::from(m_var),
    )?;

    let left_val = cur.val + m_val;
    let left_var = cs.new_witness_variable(|| Ok(left_val))?;

    // Enforce: cur + 1 * m = left
    cs.enforce_constraint(
        LinearCombination::from(cur.var) + (Fr::ONE, m_var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(left_var),
    )?;

    Ok(State {
        val: left_val,
        var: left_var,
    })
}

fn calculate_right(
    cs: &ConstraintSystemRef<Fr>,
    cur: State,
    sib: State,
    b: State,
) -> Result<State, SynthesisError> {
    let t_val = cur.val - sib.val;
    let t_var = cs.new_witness_variable(|| Ok(t_val))?;

    // Enforce: cur - sib = t
    cs.enforce_constraint(
        LinearCombination::from(cur.var) + (Fr::from(-1), sib.var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(t_var),
    )?;

    let m_val = b.val * t_val;
    let m_var = cs.new_witness_variable(|| Ok(m_val))?;

    // Enforce: b * t = m
    cs.enforce_constraint(
        LinearCombination::from(b.var),
        LinearCombination::from(t_var),
        LinearCombination::from(m_var),
    )?;

    let right_val = sib.val + m_val;
    let right_var = cs.new_witness_variable(|| Ok(right_val))?;

    // Enforce: sib + 1 * m = right
    cs.enforce_constraint(
        LinearCombination::from(sib.var) + (Fr::ONE, m_var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(right_var),
    )?;

    Ok(State {
        val: right_val,
        var: right_var,
    })
}
