use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::nonzero::enforce_nonzero;

pub struct NonZeroCircuit {
    x: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for NonZeroCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let x = State::witness(&cs, self.x.ok_or(SynthesisError::AssignmentMissing)?)?;

        enforce_nonzero(&cs, x)?;
        Ok(())
    }
}

#[cfg(test)]
mod nonzero_circuit_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;

    fn run(c: NonZeroCircuit) -> ark_relations::r1cs::ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs
    }

    #[test]
    fn nonzero_circuit_sat_for_nonzero_x() {
        let cs = run(NonZeroCircuit { x: Some(Fr::ONE) });
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn nonzero_circuit_sat_for_various_nonzero_values() {
        let xs = [
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(123456u64),
        ];

        for x in xs {
            let cs = run(NonZeroCircuit { x: Some(x) });
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn nonzero_circuit_unsat_for_zero_x() {
        let cs = run(NonZeroCircuit { x: Some(Fr::ZERO) });
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn nonzero_circuit_missing_assignment_errors() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = NonZeroCircuit { x: None }.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn nonzero_circuit_constraint_count_is_one() {
        let cs = run(NonZeroCircuit {
            x: Some(Fr::from(7u64)),
        });

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 1);
    }
}
