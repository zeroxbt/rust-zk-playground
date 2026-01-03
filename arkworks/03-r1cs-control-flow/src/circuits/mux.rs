use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::mux::select;

pub struct SelectCircuit {
    b: Option<Fr>,
    x: Option<Fr>,
    y: Option<Fr>,
    z: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SelectCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let b = State::witness(&cs, self.b.ok_or(SynthesisError::AssignmentMissing)?)?;
        let x = State::witness(&cs, self.x.ok_or(SynthesisError::AssignmentMissing)?)?;
        let y = State::witness(&cs, self.y.ok_or(SynthesisError::AssignmentMissing)?)?;
        let z = State::input(&cs, self.z.ok_or(SynthesisError::AssignmentMissing)?)?;

        let out = select(&cs, b, x, y)?;

        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(out.var()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod select_circuit_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;

    fn mux_poly(b: Fr, x: Fr, y: Fr) -> Fr {
        y + b * (x - y)
    }

    fn run(cs_name: &str, c: SelectCircuit) -> ark_relations::r1cs::ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).expect(cs_name);
        cs
    }

    #[test]
    fn select_circuit_satisfies_for_b0_z_equals_y() {
        let b = Fr::ZERO;
        let x = Fr::from(10u64);
        let y = Fr::from(99u64);
        let z = mux_poly(b, x, y);

        let cs = run(
            "constraints",
            SelectCircuit {
                b: Some(b),
                x: Some(x),
                y: Some(y),
                z: Some(z),
            },
        );

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_circuit_satisfies_for_b1_z_equals_x() {
        let b = Fr::ONE;
        let x = Fr::from(10u64);
        let y = Fr::from(99u64);
        let z = mux_poly(b, x, y);

        let cs = run(
            "constraints",
            SelectCircuit {
                b: Some(b),
                x: Some(x),
                y: Some(y),
                z: Some(z),
            },
        );

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_circuit_rejects_wrong_z_witness() {
        let b = Fr::ONE;
        let x = Fr::from(5u64);
        let y = Fr::from(7u64);
        let correct = mux_poly(b, x, y);
        let wrong = correct + Fr::ONE;

        let cs = run(
            "constraints",
            SelectCircuit {
                b: Some(b),
                x: Some(x),
                y: Some(y),
                z: Some(wrong),
            },
        );

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_circuit_accepts_non_boolean_b_if_not_boolean_enforced() {
        let b = Fr::from(2u64);
        let x = Fr::from(10u64);
        let y = Fr::from(99u64);
        let z = mux_poly(b, x, y);

        let cs = run(
            "constraints",
            SelectCircuit {
                b: Some(b),
                x: Some(x),
                y: Some(y),
                z: Some(z),
            },
        );

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_circuit_missing_assignments_errors() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let res = SelectCircuit {
            b: None,
            x: Some(Fr::ONE),
            y: Some(Fr::ONE),
            z: Some(Fr::ONE),
        }
        .generate_constraints(cs);

        assert!(res.is_err());
    }

    #[test]
    fn select_circuit_constraint_count_matches_intent() {
        const EXPECTED: usize = 2;

        let b = Fr::ONE;
        let x = Fr::from(123u64);
        let y = Fr::from(456u64);
        let z = mux_poly(b, x, y);

        let cs = run(
            "constraints",
            SelectCircuit {
                b: Some(b),
                x: Some(x),
                y: Some(y),
                z: Some(z),
            },
        );

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), EXPECTED);
    }
}
