use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

pub fn enforce_neq(cs: &ConstraintSystemRef<Fr>, a: State, b: State) -> Result<(), SynthesisError> {
    let diff = a.val() - b.val();
    let inv = State::witness(cs, diff.inverse().unwrap_or(Fr::ZERO))?;

    cs.enforce_constraint(
        LinearCombination::from(a.var()) + (-Fr::ONE, b.var()),
        LinearCombination::from(inv.var()),
        LinearCombination::from(Variable::One),
    )?;

    Ok(())
}

#[cfg(test)]
mod neq_tests {
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use hash_preimage::sponge::gadget::State;

    use crate::gadgets::neq::enforce_neq;

    fn w(cs: &ConstraintSystemRef<Fr>, v: u64) -> State {
        State::witness(cs, Fr::from(v)).unwrap()
    }

    #[test]
    fn neq_accepts_unequal_values() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = w(&cs, 10);
        let b = w(&cs, 11);

        enforce_neq(&cs, a, b).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_accepts_various_unequal_pairs() {
        let pairs = [(1u64, 2u64), (2, 5), (123, 999), (42, 7)];

        for (x, y) in pairs {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = w(&cs, x);
            let b = w(&cs, y);

            enforce_neq(&cs, a, b).unwrap();

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn neq_rejects_equal_values() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = w(&cs, 10);
        let b = w(&cs, 10);

        enforce_neq(&cs, a, b).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_works_with_public_input_and_witness() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = State::input(&cs, Fr::from(10u64)).unwrap();
        let b = w(&cs, 11);

        enforce_neq(&cs, a, b).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_rejects_equal_even_if_one_is_public_input() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = State::input(&cs, Fr::from(10u64)).unwrap();
        let b = w(&cs, 10);

        enforce_neq(&cs, a, b).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_constraint_count_is_one_if_built_from_nonzero_of_difference() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = w(&cs, 123);
        let b = w(&cs, 456);

        enforce_neq(&cs, a, b).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 1);
    }
}
