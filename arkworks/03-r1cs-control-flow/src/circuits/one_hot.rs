use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::one_hot::enforce_one_hot;

pub struct OneHotCircuit<const T: usize> {
    selectors: Option<[Fr; T]>,
}

impl<const T: usize> ConstraintSynthesizer<Fr> for OneHotCircuit<T> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let selectors = State::witness_array::<T>(
            &cs,
            &self.selectors.ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        enforce_one_hot(&cs, &selectors)?;
        Ok(())
    }
}

#[cfg(test)]
mod one_hot_circuit_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;

    fn run<const T: usize>(c: OneHotCircuit<T>) -> ark_relations::r1cs::ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs
    }

    #[test]
    fn one_hot_circuit_accepts_single_one() {
        let cs = run::<4>(OneHotCircuit {
            selectors: Some([Fr::ZERO, Fr::ONE, Fr::ZERO, Fr::ZERO]),
        });

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_circuit_accepts_single_one_any_position() {
        const T: usize = 6;

        for i in 0..T {
            let mut arr = [Fr::ZERO; T];
            arr[i] = Fr::ONE;

            let cs = run::<T>(OneHotCircuit {
                selectors: Some(arr),
            });
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn one_hot_circuit_rejects_all_zero() {
        let cs = run::<4>(OneHotCircuit {
            selectors: Some([Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ZERO]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_circuit_rejects_two_ones() {
        let cs = run::<4>(OneHotCircuit {
            selectors: Some([Fr::ONE, Fr::ZERO, Fr::ONE, Fr::ZERO]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_circuit_rejects_non_boolean_even_if_sum_is_one() {
        let half = Fr::from(2u64).inverse().unwrap();

        let cs = run::<4>(OneHotCircuit {
            selectors: Some([half, half, Fr::ZERO, Fr::ZERO]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_circuit_rejects_non_boolean_single_nonzero() {
        let cs = run::<4>(OneHotCircuit {
            selectors: Some([Fr::from(2u64), Fr::ZERO, Fr::ZERO, Fr::ZERO]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn one_hot_circuit_missing_assignment_errors() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = OneHotCircuit::<4> { selectors: None }.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn one_hot_circuit_constraint_count_matches_t_plus_one() {
        const T: usize = 7;

        let mut arr = [Fr::ZERO; T];
        arr[3] = Fr::ONE;

        let cs = run::<T>(OneHotCircuit {
            selectors: Some(arr),
        });

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), T + 1);
    }
}
