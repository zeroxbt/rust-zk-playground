use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

pub fn less_than<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    a_arr: &[State; T],
    b_arr: &[State; T],
) -> Result<State, SynthesisError> {
    let mut found = State::witness(cs, Fr::ZERO)?;
    let mut result = State::witness(cs, Fr::ZERO)?;
    for (a, b) in a_arr.iter().zip(b_arr) {
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

        // if z == 1 { a == b}
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

        // s = if found {0} else {1-z}
        // s = found * (0 - 1 + z) + 1 - z
        // s = z * found - found + 1 - z
        // s = (1 - found) × (1 - z)
        let s = State::witness(cs, (Fr::ONE - found.val()) * (Fr::ONE - z.val()))?;
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(s.var()),
        )?;

        let old_result = result;
        // result = old_result + s * b
        // result - old_result = + s * b
        result = State::witness(cs, old_result.val() + s.val() * b.val())?;
        cs.enforce_constraint(
            LinearCombination::from(s.var()),
            LinearCombination::from(b.var()),
            LinearCombination::from(result.var()) + (-Fr::ONE, old_result.var()),
        )?;

        let old_found = found;
        // found = if !z {1} else {old_found}
        // found = (1 - z) * (1 - old_found) + old_found
        // found - old_found = (1 - old_found) × (1 - z)
        found = State::witness(
            cs,
            (Fr::ONE - z.val()) * (Fr::ONE - old_found.val()) + old_found.val(),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, old_found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(found.var()) + (-Fr::ONE, old_found.var()),
        )?;
    }

    Ok(result)
}

pub fn verify_sorted_non_membership<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    nullifier_bits: &[State; T],
    lower_bits: &[State; T],
    upper_bits: &[State; T],
) -> Result<(), SynthesisError> {
    let x = less_than(cs, lower_bits, nullifier_bits)?;
    let y = less_than(cs, nullifier_bits, upper_bits)?;

    cs.enforce_constraint(
        LinearCombination::from(x.var()),
        LinearCombination::from(y.var()),
        LinearCombination::from(Variable::One),
    )
}
