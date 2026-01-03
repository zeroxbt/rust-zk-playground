use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::neq::enforce_neq;

pub struct NeqCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for NeqCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let a = State::witness(&cs, self.a.ok_or(SynthesisError::AssignmentMissing)?)?;
        let b = State::witness(&cs, self.b.ok_or(SynthesisError::AssignmentMissing)?)?;

        enforce_neq(&cs, a, b)?;

        Ok(())
    }
}

#[cfg(test)]
mod neq_circuit_tests {
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;

    fn run(c: NeqCircuit) -> ark_relations::r1cs::ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs
    }

    #[test]
    fn neq_circuit_sat_for_unequal_values() {
        let cs = run(NeqCircuit {
            a: Some(Fr::from(10u64)),
            b: Some(Fr::from(11u64)),
        });

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_circuit_sat_for_various_unequal_pairs() {
        let pairs = [(1u64, 2u64), (2, 5), (123, 999), (42, 7), (7, 42)];

        for (x, y) in pairs {
            let cs = run(NeqCircuit {
                a: Some(Fr::from(x)),
                b: Some(Fr::from(y)),
            });

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn neq_circuit_unsat_for_equal_values() {
        let cs = run(NeqCircuit {
            a: Some(Fr::from(10u64)),
            b: Some(Fr::from(10u64)),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn neq_circuit_missing_assignment_errors() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = NeqCircuit {
            a: None,
            b: Some(Fr::ONE),
        }
        .generate_constraints(cs);
        assert!(res.is_err());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = NeqCircuit {
            a: Some(Fr::ONE),
            b: None,
        }
        .generate_constraints(cs);
        assert!(res.is_err());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = NeqCircuit { a: None, b: None }.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn neq_circuit_constraint_count_regression_guard() {
        let cs = run(NeqCircuit {
            a: Some(Fr::from(123u64)),
            b: Some(Fr::from(456u64)),
        });

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 1);
    }
}
