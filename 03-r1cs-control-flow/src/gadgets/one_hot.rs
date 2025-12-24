use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable},
};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::bool::enforce_bool;

/// Enforce that `selectors` is a *one-hot* vector.
pub fn enforce_one_hot(
    cs: &ConstraintSystemRef<Fr>,
    selectors: &[State],
) -> Result<(), SynthesisError> {
    let mut lc_acc = lc!();
    for &s in selectors {
        enforce_bool(cs, s)?;

        lc_acc += (Fr::ONE, s.var());
    }

    cs.enforce_constraint(
        LinearCombination::from(Variable::One),
        lc_acc,
        LinearCombination::from(Variable::One),
    )?;

    Ok(())
}

#[cfg(test)]
mod one_hot_tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::AdditiveGroup;
    use ark_relations::r1cs::ConstraintSystem;

    /// Helper: witness an array of selectors from u64s.
    fn wits<const N: usize>(
        cs: &ark_relations::r1cs::ConstraintSystemRef<Fr>,
        vals: [u64; N],
    ) -> [State; N] {
        let frs: Vec<Fr> = vals.into_iter().map(Fr::from).collect();
        State::witness_array::<N>(cs, &frs).unwrap()
    }

    #[test]
    fn one_hot_accepts_single_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<4>(&cs, [0, 1, 0, 0]);

        enforce_one_hot(&cs, &s).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_accepts_single_one_in_any_position() {
        for i in 0..5 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let mut vals = [0u64; 5];
            vals[i] = 1;
            let s = wits::<5>(&cs, vals);

            enforce_one_hot(&cs, &s).unwrap();

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn one_hot_rejects_all_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<4>(&cs, [0, 0, 0, 0]);

        enforce_one_hot(&cs, &s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_rejects_two_ones() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<4>(&cs, [1, 0, 1, 0]);

        enforce_one_hot(&cs, &s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_rejects_three_ones() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<5>(&cs, [1, 1, 0, 1, 0]);

        enforce_one_hot(&cs, &s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_rejects_non_boolean_selector_even_if_sum_is_one() {
        // This test enforces the key point: "sum = 1" is not enough.
        // Example: [1/2, 1/2, 0, 0] should be UNSAT if booleanity is enforced.
        let cs = ConstraintSystem::<Fr>::new_ref();

        let half = Fr::from(2u64).inverse().unwrap();
        let s0 = State::witness(&cs, half).unwrap();
        let s1 = State::witness(&cs, half).unwrap();
        let s2 = State::witness(&cs, Fr::ZERO).unwrap();
        let s3 = State::witness(&cs, Fr::ZERO).unwrap();
        let s = [s0, s1, s2, s3];

        enforce_one_hot(&cs, &s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_rejects_non_boolean_selector_even_if_only_one_is_nonzero() {
        // Another important negative case: [2,0,0,0] should be UNSAT.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<4>(&cs, [2, 0, 0, 0]);

        enforce_one_hot(&cs, &s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_constraint_count_regression_guard() {
        // Replace EXPECTED once you finalize your gadget:
        // Typical shape if you enforce booleanity for each selector + one sum constraint:
        // EXPECTED = N (boolean constraints) + 1 (sum-to-one constraint)
        let cs = ConstraintSystem::<Fr>::new_ref();
        let s = wits::<6>(&cs, [0, 0, 0, 1, 0, 0]);

        enforce_one_hot(&cs, &s).unwrap();
        assert!(cs.is_satisfied().unwrap());

        const N: usize = 6;
        let expected = N + 1;
        assert_eq!(cs.num_constraints(), expected);
    }
}
