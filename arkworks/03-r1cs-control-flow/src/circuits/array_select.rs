use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::{array_select::select_from_array, one_hot::enforce_one_hot};

pub struct ArraySelectCircuit<const T: usize> {
    selectors: Option<[Fr; T]>, // witness
    values: Option<[Fr; T]>,    // witness
    z: Option<Fr>,              // public input
}

impl<const T: usize> ConstraintSynthesizer<Fr> for ArraySelectCircuit<T> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let selectors = State::witness_array::<T>(
            &cs,
            &self.selectors.ok_or(SynthesisError::AssignmentMissing)?,
        )?;
        let values =
            State::witness_array::<T>(&cs, &self.values.ok_or(SynthesisError::AssignmentMissing)?)?;
        let z = State::input(&cs, self.z.ok_or(SynthesisError::AssignmentMissing)?)?;

        enforce_one_hot(&cs, &selectors)?;
        let out = select_from_array(&cs, &selectors, &values)?;

        cs.enforce_constraint(
            LinearCombination::from(out.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(z.var()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod array_select_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use crate::circuits::array_select::ArraySelectCircuit;

    fn one_hot<const T: usize>(idx: usize) -> [Fr; T] {
        assert!(idx < T);
        let mut s = [Fr::ZERO; T];
        s[idx] = Fr::ONE;
        s
    }

    fn run<C: ConstraintSynthesizer<Fr>>(c: C) -> ark_relations::r1cs::ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs
    }

    #[test]
    fn array_select_circuit_sat_for_each_index() {
        const T: usize = 5;
        let values = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
            Fr::from(50u64),
        ];

        for idx in 0..T {
            let selectors = one_hot::<T>(idx);
            let z = values[idx];

            let cs = run(ArraySelectCircuit::<T> {
                selectors: Some(selectors),
                values: Some(values),
                z: Some(z),
            });

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn array_select_circuit_unsat_if_z_wrong() {
        const T: usize = 4;
        let values = [
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
            Fr::from(17u64),
        ];
        let selectors = one_hot::<T>(2);

        let correct = values[2];
        let wrong = correct + Fr::ONE;

        let cs = run(ArraySelectCircuit::<T> {
            selectors: Some(selectors),
            values: Some(values),
            z: Some(wrong),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_select_circuit_unsat_if_selectors_all_zero() {
        const T: usize = 4;
        let values = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let selectors = [Fr::ZERO; T];

        let cs = run(ArraySelectCircuit::<T> {
            selectors: Some(selectors),
            values: Some(values),
            z: Some(values[0]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_select_circuit_unsat_if_selectors_two_ones() {
        const T: usize = 4;
        let values = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let selectors = [Fr::ONE, Fr::ZERO, Fr::ONE, Fr::ZERO];

        let cs = run(ArraySelectCircuit::<T> {
            selectors: Some(selectors),
            values: Some(values),
            z: Some(values[0]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_select_circuit_unsat_if_selectors_non_boolean_even_if_sum_is_one() {
        const T: usize = 4;
        let values = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];

        let half = Fr::from(2u64).inverse().unwrap();
        let selectors = [half, half, Fr::ZERO, Fr::ZERO];

        let cs = run(ArraySelectCircuit::<T> {
            selectors: Some(selectors),
            values: Some(values),
            z: Some(values[0]),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_select_circuit_missing_assignment_errors() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = ArraySelectCircuit::<T> {
            selectors: None,
            values: Some([Fr::ZERO; T]),
            z: Some(Fr::ZERO),
        }
        .generate_constraints(cs);

        assert!(res.is_err());
    }

    #[test]
    fn array_select_circuit_constraint_count_regression_guard() {
        const T: usize = 6;

        let values = [
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
            Fr::from(17u64),
        ];
        let selectors = one_hot::<T>(4);
        let z = values[4];

        let cs = run(ArraySelectCircuit::<T> {
            selectors: Some(selectors),
            values: Some(values),
            z: Some(z),
        });

        assert!(cs.is_satisfied().unwrap());

        let expected = 2 * T + 3;
        assert_eq!(cs.num_constraints(), expected);
    }
}
