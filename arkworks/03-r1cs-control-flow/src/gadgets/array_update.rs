use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
use hash_preimage::sponge::gadget::State;

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

#[cfg(test)]
mod array_update_tests {
    use ark_bls12_381::Fr;
    use ark_ff::AdditiveGroup;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, LinearCombination, Variable};

    use super::*;
    use crate::gadgets::{array_update::update_one_slot, one_hot::enforce_one_hot};

    fn witness_array<const T: usize>(cs: &ConstraintSystemRef<Fr>, vals: [u64; T]) -> [State; T] {
        let frs: Vec<Fr> = vals.into_iter().map(Fr::from).collect();
        State::witness_array::<T>(cs, &frs).unwrap()
    }

    fn one_hot_selectors<const T: usize>(cs: &ConstraintSystemRef<Fr>, idx: usize) -> [State; T] {
        assert!(idx < T);
        let mut arr = [Fr::ZERO; T];
        arr[idx] = Fr::ONE;
        State::witness_array::<T>(cs, &arr).unwrap()
    }

    fn bind_output_array_public<const T: usize>(
        cs: &ConstraintSystemRef<Fr>,
        out: &[State; T],
        expected: [Fr; T],
    ) -> [State; T] {
        let mut pub_out = [State::zero(); T];
        for i in 0..T {
            let z = State::input(cs, expected[i]).unwrap();
            cs.enforce_constraint(
                LinearCombination::from(z.var()),
                LinearCombination::from(Variable::One),
                LinearCombination::from(out[i].var()),
            )
            .unwrap();
            pub_out[i] = z;
        }
        pub_out
    }

    #[test]
    fn update_one_slot_sat_updates_selected_index_only() {
        const T: usize = 5;

        for idx in 0..T {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let old = witness_array::<T>(&cs, [10, 20, 30, 40, 50]);
            let selectors = one_hot_selectors::<T>(&cs, idx);
            let new_val = State::witness(&cs, Fr::from(777u64)).unwrap();

            enforce_one_hot(&cs, &selectors).unwrap();

            let out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

            let mut expected = [Fr::ZERO; T];
            for i in 0..T {
                expected[i] = old[i].val();
            }
            expected[idx] = new_val.val();

            bind_output_array_public::<T>(&cs, &out, expected);

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn update_one_slot_unsat_if_output_changes_non_selected_index() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [1, 2, 3, 4]);
        let selectors = one_hot_selectors::<T>(&cs, 1);
        let new_val = State::witness(&cs, Fr::from(99u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        let out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        let mut expected = [Fr::ZERO; T];
        for i in 0..T {
            expected[i] = old[i].val();
        }
        expected[1] = new_val.val();
        expected[3] += Fr::ONE;

        bind_output_array_public::<T>(&cs, &out, expected);

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn update_one_slot_unsat_if_selected_index_not_updated() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [1, 2, 3, 4]);
        let selectors = one_hot_selectors::<T>(&cs, 2);
        let new_val = State::witness(&cs, Fr::from(123u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        let out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        let mut expected = [Fr::ZERO; T];
        for i in 0..T {
            expected[i] = old[i].val();
        }

        bind_output_array_public::<T>(&cs, &out, expected);

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn update_one_slot_unsat_with_two_hot_selectors() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [10, 20, 30, 40]);

        let selectors =
            State::witness_array::<T>(&cs, &[Fr::ONE, Fr::ZERO, Fr::ONE, Fr::ZERO]).unwrap();
        let new_val = State::witness(&cs, Fr::from(777u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();
        let _out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn update_one_slot_unsat_with_all_zero_selectors() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [10, 20, 30, 40]);
        let selectors = State::witness_array::<T>(&cs, &[Fr::ZERO; T]).unwrap();
        let new_val = State::witness(&cs, Fr::from(777u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();
        let _out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn update_one_slot_unsat_with_non_boolean_selectors_even_if_sum_is_one() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [10, 20, 30, 40]);
        let half = Fr::from(2u64).inverse().unwrap();
        let selectors = State::witness_array::<T>(&cs, &[half, half, Fr::ZERO, Fr::ZERO]).unwrap();
        let new_val = State::witness(&cs, Fr::from(777u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();
        let _out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn constraint_count_regression_guard() {
        const T: usize = 6;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let old = witness_array::<T>(&cs, [1, 2, 3, 4, 5, 6]);
        let selectors = one_hot_selectors::<T>(&cs, 3);
        let new_val = State::witness(&cs, Fr::from(99u64)).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        let out = update_one_slot::<T>(&cs, &selectors, &old, new_val).unwrap();

        let mut expected = [Fr::ZERO; T];
        for i in 0..T {
            expected[i] = old[i].val();
        }
        expected[3] = new_val.val();

        bind_output_array_public::<T>(&cs, &out, expected);

        assert!(cs.is_satisfied().unwrap());

        let expected_constraints = 3 * T + 1;
        assert_eq!(cs.num_constraints(), expected_constraints);
    }
}
