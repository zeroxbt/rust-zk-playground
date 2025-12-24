use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable},
};
use hash_preimage::sponge::gadget::State;

/// Select exactly one value from an array using one-hot selectors.
pub fn select_from_array<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    selectors: &[State; T],
    values: &[State; T],
) -> Result<State, SynthesisError> {
    let mut acc_lc = lc!();
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

#[cfg(test)]
mod select_from_array_tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, LinearCombination, Variable};

    use crate::gadgets::array_select::select_from_array;
    use crate::gadgets::one_hot::enforce_one_hot;

    fn witness_vals<const T: usize>(cs: &ConstraintSystemRef<Fr>, vals: [u64; T]) -> [State; T] {
        let frs: Vec<Fr> = vals.into_iter().map(Fr::from).collect();
        State::witness_array::<T>(cs, &frs).unwrap()
    }

    fn witness_selectors<const T: usize>(cs: &ConstraintSystemRef<Fr>, idx: usize) -> [State; T] {
        assert!(idx < T);
        let mut arr = [Fr::ZERO; T];
        arr[idx] = Fr::ONE;
        State::witness_array::<T>(cs, &arr).unwrap()
    }
    fn bind_public_equal(cs: &ConstraintSystemRef<Fr>, z: State, out: State) {
        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(out.var()),
        )
        .unwrap();
    }

    #[test]
    fn select_from_array_sat_for_each_index() {
        const T: usize = 5;

        for idx in 0..T {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let selectors = witness_selectors::<T>(&cs, idx);
            let values = witness_vals::<T>(&cs, [10, 20, 30, 40, 50]);

            enforce_one_hot(&cs, &selectors).unwrap();
            let out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

            assert!(cs.is_satisfied().unwrap());
            assert_eq!(out.val(), values[idx].val());
        }
    }

    #[test]
    fn select_from_array_unsat_if_public_output_is_wrong() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let idx = 2;
        let selectors = witness_selectors::<T>(&cs, idx);
        let values = witness_vals::<T>(&cs, [7, 11, 13, 17]);

        enforce_one_hot(&cs, &selectors).unwrap();
        let out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        let z_wrong = State::input(&cs, Fr::from(999u64)).unwrap();
        bind_public_equal(&cs, z_wrong, out);

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_from_array_sat_if_public_output_matches() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let idx = 1;
        let selectors = witness_selectors::<T>(&cs, idx);
        let values = witness_vals::<T>(&cs, [7, 11, 13, 17]);

        enforce_one_hot(&cs, &selectors).unwrap();
        let out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        let z = State::input(&cs, values[idx].val()).unwrap();
        bind_public_equal(&cs, z, out);

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_from_array_unsat_if_selectors_not_one_hot_two_ones() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let arr = [Fr::ONE, Fr::ZERO, Fr::ONE, Fr::ZERO];
        let selectors = State::witness_array::<T>(&cs, &arr).unwrap();
        let values = witness_vals::<T>(&cs, [1, 2, 3, 4]);

        enforce_one_hot(&cs, &selectors).unwrap();

        let _out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_from_array_unsat_if_selectors_all_zero() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let selectors = State::witness_array::<T>(&cs, &[Fr::ZERO; T]).unwrap();
        let values = witness_vals::<T>(&cs, [1, 2, 3, 4]);

        enforce_one_hot(&cs, &selectors).unwrap();
        let _out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_from_array_unsat_if_selector_non_boolean_even_if_sum_is_one() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let half = Fr::from(2u64).inverse().unwrap();
        let selectors = State::witness_array::<T>(&cs, &[half, half, Fr::ZERO, Fr::ZERO]).unwrap();
        let values = witness_vals::<T>(&cs, [10, 20, 30, 40]);

        enforce_one_hot(&cs, &selectors).unwrap();
        let _out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn constraint_count_regression_guard() {
        const T: usize = 6;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let selectors = witness_selectors::<T>(&cs, 4);
        let values = witness_vals::<T>(&cs, [3, 5, 7, 11, 13, 17]);

        enforce_one_hot(&cs, &selectors).unwrap();
        let out = select_from_array::<T>(&cs, &selectors, &values).unwrap();

        let z = State::input(&cs, values[4].val()).unwrap();
        bind_public_equal(&cs, z, out);

        assert!(cs.is_satisfied().unwrap());

        let expected = 2 * T + 3;
        assert_eq!(cs.num_constraints(), expected);
    }
}
