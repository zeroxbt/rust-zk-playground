use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};
use merkle_membership::merkle::spec::MERKLE_NODE_DST;

pub fn compute_root_with_spine<const DEPTH: usize>(
    cs: &ConstraintSystemRef<Fr>,
    sponge: &SpongeGadget<PoseidonPermutation, 3, 2>,
    leaf: State,
    path: &[State; DEPTH],
    index_bits: &[State; DEPTH],
) -> Result<(State, [State; DEPTH]), SynthesisError> {
    let mut cur = leaf;
    let mut spine = [State::zero(); DEPTH];
    for (i, (&sib, &b)) in path.iter().zip(index_bits.iter()).enumerate() {
        spine[i] = cur;
        let (left, right) = conditional_swap(cs, cur, sib, b)?;
        cur = sponge.hash_with_dst(cs, &[left, right], Some(MERKLE_NODE_DST), 1)?;
    }

    Ok((cur, spine))
}

/// Enforce boolean: b * (b - 1) = 0
pub fn enforce_bit(cs: &ConstraintSystemRef<Fr>, b: State) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        LinearCombination::from(b.var()) - (Fr::ONE, Variable::One),
        LinearCombination::zero(),
    )?;
    Ok(())
}

/// Enforce boolean: b * (b - 1) = 0, for all b in arr
pub fn enforce_bit_array<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    arr: &[State; T],
) -> Result<(), SynthesisError> {
    for &b in arr {
        enforce_bit(cs, b)?;
    }

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
    let t_lc = LinearCombination::from(sib.var()) + (-Fr::ONE, cur.var());
    let m = State::witness(cs, b.val() * (sib.val() - cur.val()))?;
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        t_lc,
        LinearCombination::from(m.var()),
    )?;

    // Enforce: left = cur + m
    let left = State::witness(cs, cur.val() + m.val())?;
    cs.enforce_constraint(
        LinearCombination::from(cur.var()) + (Fr::ONE, m.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(left.var()),
    )?;

    // Enforce: right = sib - m
    let right = State::witness(cs, sib.val() - m.val())?;
    cs.enforce_constraint(
        LinearCombination::from(sib.var()) + (-Fr::ONE, m.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(right.var()),
    )?;

    Ok((left, right))
}

/// Enforce that `selectors` is a *one-hot* vector.
pub fn enforce_one_hot(
    cs: &ConstraintSystemRef<Fr>,
    selectors: &[State],
) -> Result<(), SynthesisError> {
    let mut lc_acc = LinearCombination::zero();
    for &s in selectors {
        enforce_bit(cs, s)?;

        lc_acc += (Fr::ONE, s.var());
    }

    cs.enforce_constraint(
        LinearCombination::from(Variable::One),
        lc_acc,
        LinearCombination::from(Variable::One),
    )?;

    Ok(())
}

pub fn first_difference_selectors<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    a_arr: &[State; T],
    b_arr: &[State; T],
) -> Result<([State; T], State), SynthesisError> {
    let mut selectors = [State::zero(); T];
    let mut found = State::witness(cs, Fr::ZERO)?;
    for (i, (a, b)) in a_arr.iter().zip(b_arr).enumerate() {
        let diff_val = a.val() - b.val();
        let inv_val = diff_val.inverse().unwrap_or(Fr::ZERO);

        let z_val = if diff_val == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        };

        let inv = State::witness(cs, inv_val)?;
        let z = State::witness(cs, z_val)?;

        let diff_lc = LinearCombination::from(a.var()) + (-Fr::ONE, b.var());

        // (a - b) * inv = 1 - z
        cs.enforce_constraint(
            diff_lc.clone(),
            LinearCombination::from(inv.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
        )?;

        // z * (a - b) = 0
        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            diff_lc,
            LinearCombination::zero(),
        )?;

        // z ∈ {0,1}
        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::zero(),
        )?;

        let s = State::witness(cs, (Fr::ONE - found.val()) * (Fr::ONE - z.val()))?;
        // (1 - found) × (1 - z) = s
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(s.var()),
        )?;
        selectors[i] = s;

        let old_found = found;
        found = State::witness(
            cs,
            (Fr::ONE - z.val()) * (Fr::ONE - old_found.val()) + old_found.val(),
        )?;
        // (1 - old_found) × (1 - z) = found - old_found
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, old_found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(found.var()) + (-Fr::ONE, old_found.var()),
        )?;

        enforce_bit(cs, found)?;
    }

    Ok((selectors, found))
}

/// Update exactly one value of an array using one-hot selectors.
pub fn update_one_slot<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    selectors: &[State; T],
    values: &[State; T],
    new_val: State,
) -> Result<[State; T], SynthesisError> {
    let mut new_values = [State::zero(); T];
    for (i, (&a, &s)) in values.iter().zip(selectors).enumerate() {
        let new_a = State::witness(cs, s.val() * (new_val.val() - a.val()) + a.val())?;
        cs.enforce_constraint(
            LinearCombination::from(new_val.var()) + (-Fr::ONE, a.var()),
            LinearCombination::from(s.var()),
            LinearCombination::from(new_a.var()) + (-Fr::ONE, a.var()),
        )?;

        new_values[i] = new_a;
    }

    Ok(new_values)
}

/// Select exactly one value from an array using one-hot selectors.
pub fn select_from_array<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    selectors: &[State; T],
    values: &[State; T],
) -> Result<State, SynthesisError> {
    let mut acc_lc = LinearCombination::zero();
    let mut acc_val = Fr::ZERO;

    for (&a, &s) in values.iter().zip(selectors) {
        let p_val = s.val() * a.val();
        let p = State::witness(cs, p_val)?;
        cs.enforce_constraint(
            LinearCombination::from(s.var()),
            LinearCombination::from(a.var()),
            LinearCombination::from(p.var()),
        )?;
        acc_lc += (Fr::ONE, p.var());
        acc_val += p_val;
    }

    let acc = State::witness(cs, acc_val)?;
    cs.enforce_constraint(
        acc_lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(acc.var()),
    )?;

    Ok(acc)
}
