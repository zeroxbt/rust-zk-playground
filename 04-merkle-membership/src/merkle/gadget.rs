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
        let (left, right) = conditional_swap(cs, cur, sib, b)?;
        cur = sponge.hash_with_dst(cs, &[left, right], Some(MERKLE_NODE_DST), 1)?;
    }

    Ok(cur)
}
/// Enforce boolean: b * (b - 1) = 0
pub fn enforce_bit(cs: &ConstraintSystemRef<Fr>, b: State) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var),
        LinearCombination::from(b.var) - (Fr::ONE, Variable::One),
        LinearCombination::<Fr>::zero(),
    )?;
    Ok(())
}

/// Conditional swap using one multiplication:
///   m = b * (sib - cur)
///   left  = cur + m
///   right = sib - m
pub fn conditional_swap(
    cs: &ConstraintSystemRef<Fr>,
    cur: State,
    sib: State,
    b: State,
) -> Result<(State, State), SynthesisError> {
    // Enforce: b * (sib - cur) = m
    let t_lc = LinearCombination::from(sib.var) + (Fr::from(-1i64), cur.var);
    let m_val = b.val * (sib.val - cur.val);
    let m_var = cs.new_witness_variable(|| Ok(m_val))?;
    cs.enforce_constraint(
        LinearCombination::from(b.var),
        t_lc,
        LinearCombination::from(m_var),
    )?;

    // Enforce: left = cur + m
    let left_val = cur.val + m_val;
    let left_var = cs.new_witness_variable(|| Ok(left_val))?;
    cs.enforce_constraint(
        LinearCombination::from(cur.var) + (Fr::ONE, m_var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(left_var),
    )?;

    // Enforce: right = sib - m
    let right_val = sib.val - m_val;
    let right_var = cs.new_witness_variable(|| Ok(right_val))?;
    cs.enforce_constraint(
        LinearCombination::from(sib.var) + (Fr::from(-1i64), m_var),
        LinearCombination::from(Variable::One),
        LinearCombination::from(right_var),
    )?;

    Ok((
        State {
            val: left_val,
            var: left_var,
        },
        State {
            val: right_val,
            var: right_var,
        },
    ))
}
