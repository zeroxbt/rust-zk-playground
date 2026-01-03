use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

pub fn enforce_nonzero(cs: &ConstraintSystemRef<Fr>, x: State) -> Result<(), SynthesisError> {
    let inv = State::witness(cs, x.val().inverse().unwrap_or(Fr::ZERO))?;
    cs.enforce_constraint(
        LinearCombination::from(x.var()),
        LinearCombination::from(inv.var()),
        LinearCombination::from(Variable::One),
    )?;

    Ok(())
}

#[cfg(test)]
mod enforce_nonzero_tests {
    use super::*;
    use crate::gadgets::nonzero::enforce_nonzero;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use hash_preimage::sponge::gadget::State;

    fn w(cs: &ConstraintSystemRef<Fr>, v: Fr) -> State {
        State::witness(cs, v).unwrap()
    }

    #[test]
    fn nonzero_accepts_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = w(&cs, Fr::ONE);

        enforce_nonzero(&cs, x).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn nonzero_accepts_random_nonzero_values() {
        let xs = [
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(123456u64),
        ];

        for &v in &xs {
            let cs_i = ConstraintSystem::<Fr>::new_ref();
            let x = w(&cs_i, v);

            enforce_nonzero(&cs_i, x).unwrap();

            assert!(cs_i.is_satisfied().unwrap());
        }
    }

    #[test]
    fn nonzero_rejects_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = w(&cs, Fr::ZERO);

        enforce_nonzero(&cs, x).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn nonzero_uses_one_constraint() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = w(&cs, Fr::from(7u64));

        enforce_nonzero(&cs, x).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 1);
    }

    #[test]
    fn nonzero_constraint_is_binding_via_public_input_link() {
        use ark_relations::r1cs::{LinearCombination, Variable};

        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = w(&cs, Fr::from(42u64));

        enforce_nonzero(&cs, x).unwrap();

        let z0 = State::input(&cs, Fr::ZERO).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(x.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(z0.var()),
        )
        .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn nonzero_rejects_zero_even_if_other_constraints_hold() {
        use ark_relations::r1cs::{LinearCombination, Variable};

        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = w(&cs, Fr::ZERO);

        enforce_nonzero(&cs, x).unwrap();

        let z0 = State::input(&cs, Fr::ZERO).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(x.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(z0.var()),
        )
        .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
