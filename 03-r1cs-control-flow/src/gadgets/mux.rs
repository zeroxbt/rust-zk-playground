use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
use hash_preimage::sponge::gadget::State;

/// z = if b { x } else { y }.
/// This gadget does NOT enforce that b is boolean.
pub fn select(
    cs: &ConstraintSystemRef<Fr>,
    b: State,
    x: State,
    y: State,
) -> Result<State, SynthesisError> {
    // z = b * (x - y) + y
    let z = State::witness(cs, b.val() * (x.val() - y.val()) + y.val())?;
    cs.enforce_constraint(
        LinearCombination::from(x.var()) + (-Fr::ONE, y.var()),
        LinearCombination::from(b.var()),
        LinearCombination::from(z.var()) + (-Fr::ONE, y.var()),
    )?;

    Ok(z)
}

#[cfg(test)]
mod select_tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::AdditiveGroup;
    use ark_relations::r1cs::ConstraintSystem;

    fn w(cs: &ark_relations::r1cs::ConstraintSystemRef<Fr>, v: u64) -> State {
        State::witness(cs, Fr::from(v)).unwrap()
    }

    fn mux_poly(b: Fr, x: Fr, y: Fr) -> Fr {
        y + b * (x - y)
    }

    #[test]
    fn select_b0_returns_y_and_is_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let b = State::witness(&cs, Fr::ZERO).unwrap();
        let x = w(&cs, 10);
        let y = w(&cs, 99);

        let z = select(&cs, b, x, y).unwrap();

        assert!(cs.is_satisfied().unwrap());

        assert_eq!(z.val(), y.val());
    }

    #[test]
    fn select_b1_returns_x_and_is_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let b = State::witness(&cs, Fr::ONE).unwrap();
        let x = w(&cs, 10);
        let y = w(&cs, 99);

        let z = select(&cs, b, x, y).unwrap();

        assert!(cs.is_satisfied().unwrap());

        assert_eq!(z.val(), x.val());
    }

    #[test]
    fn select_matches_mux_polynomial_for_boolean_b() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let b = State::witness(&cs, Fr::ONE).unwrap();
        let x = w(&cs, 123);
        let y = w(&cs, 456);

        let z = select(&cs, b, x, y).unwrap();
        assert!(cs.is_satisfied().unwrap());

        assert_eq!(z.val(), mux_poly(b.val(), x.val(), y.val()));
    }

    #[test]
    fn select_does_not_enforce_booleanity_by_itself() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let b = State::witness(&cs, Fr::from(2u64)).unwrap();
        let x = w(&cs, 10);
        let y = w(&cs, 99);

        let z = select(&cs, b, x, y).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(z.val(), mux_poly(b.val(), x.val(), y.val()));
    }

    #[test]
    fn select_uses_one_constraint_for_mux_relation() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let b = State::witness(&cs, Fr::ONE).unwrap();
        let x = w(&cs, 10);
        let y = w(&cs, 99);

        let _z = select(&cs, b, x, y).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 1);
    }
}
