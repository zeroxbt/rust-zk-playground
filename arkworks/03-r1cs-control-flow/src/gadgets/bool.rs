use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

/// Enforce b ∈ {0,1}: b * (b - 1) = 0
pub fn enforce_bool(cs: &ConstraintSystemRef<Fr>, b: State) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        LinearCombination::from(b.var()) + (-Fr::ONE, Variable::One),
        LinearCombination::zero(),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::enforce_bool;

    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use hash_preimage::sponge::gadget::State;

    #[test]
    fn bool_allows_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, Fr::ZERO).unwrap();

        enforce_bool(&cs, b).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn bool_allows_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, Fr::ONE).unwrap();

        enforce_bool(&cs, b).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn bool_rejects_two() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, Fr::from(2u64)).unwrap();

        enforce_bool(&cs, b).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn bool_rejects_minus_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, -Fr::ONE).unwrap();

        enforce_bool(&cs, b).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn bool_rejects_random_non_boolean() {
        let mut rng = test_rng();

        let mut v = Fr::rand(&mut rng);
        while v == Fr::ZERO || v == Fr::ONE {
            v = Fr::rand(&mut rng);
        }

        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, v).unwrap();

        enforce_bool(&cs, b).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn bool_constraint_count_is_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, Fr::ONE).unwrap();

        let before = cs.num_constraints();
        enforce_bool(&cs, b).unwrap();
        let after = cs.num_constraints();

        assert_eq!(after - before, 1);
        assert!(cs.is_satisfied().unwrap());
    }
}
