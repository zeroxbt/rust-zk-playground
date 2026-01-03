use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::{array_update::update_one_slot, one_hot::enforce_one_hot};

pub struct ArrayUpdateCircuit<const T: usize> {
    selectors: Option<[Fr; T]>, // witness
    values: Option<[Fr; T]>,    // witness
    new_val: Option<Fr>,        // witness
    out: Option<[Fr; T]>,       // public inputs
}

impl<const T: usize> ConstraintSynthesizer<Fr> for ArrayUpdateCircuit<T> {
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
        let out =
            State::input_array::<T>(&cs, &self.out.ok_or(SynthesisError::AssignmentMissing)?)?;
        let new_val = State::witness(&cs, self.new_val.ok_or(SynthesisError::AssignmentMissing)?)?;

        enforce_one_hot(&cs, &selectors)?;
        let res = update_one_slot(&cs, &selectors, &values, new_val)?;

        for (r, o) in out.iter().zip(res) {
            cs.enforce_constraint(
                LinearCombination::from(o.var()),
                LinearCombination::from(Variable::One),
                LinearCombination::from(r.var()),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod array_update_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use crate::circuits::array_update::ArrayUpdateCircuit;

    fn mux_poly(b: Fr, x: Fr, y: Fr) -> Fr {
        y + b * (x - y)
    }

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
    fn array_update_circuit_sat_updates_selected_index_only() {
        const T: usize = 5;

        let old = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
            Fr::from(50u64),
        ];

        for idx in 0..T {
            let selectors = one_hot::<T>(idx);
            let new_val = Fr::from(777u64);

            let mut expected = old;
            expected[idx] = new_val;

            let cs = run(ArrayUpdateCircuit::<T> {
                selectors: Some(selectors),
                values: Some(old),
                new_val: Some(new_val),
                out: Some(expected),
            });

            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn array_update_circuit_unsat_if_out_wrong_changes_non_selected_index() {
        const T: usize = 4;
        let old = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];

        let selectors = one_hot::<T>(1);
        let new_val = Fr::from(99u64);

        let mut wrong = old;
        wrong[1] = new_val;
        wrong[3] += Fr::ONE;

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(wrong),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_update_circuit_unsat_if_selected_index_not_updated() {
        const T: usize = 4;
        let old = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];

        let selectors = one_hot::<T>(2);
        let new_val = Fr::from(123u64);

        let wrong = old;

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(wrong),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_update_circuit_unsat_if_selectors_all_zero() {
        const T: usize = 4;
        let old = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let selectors = [Fr::ZERO; T];
        let new_val = Fr::from(777u64);

        let mut out = old;
        out[0] = new_val;

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(out),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_update_circuit_unsat_if_selectors_two_ones() {
        const T: usize = 4;
        let old = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let selectors = [Fr::ONE, Fr::ZERO, Fr::ONE, Fr::ZERO];
        let new_val = Fr::from(777u64);

        let mut out = old;
        out[0] = new_val; // arbitrary

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(out),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_update_circuit_unsat_if_selectors_non_boolean_even_if_sum_is_one() {
        const T: usize = 4;
        let old = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let new_val = Fr::from(777u64);

        let half = Fr::from(2u64).inverse().unwrap();
        let selectors = [half, half, Fr::ZERO, Fr::ZERO];

        let mut out = old;
        out[0] = new_val;

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(out),
        });

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn array_update_circuit_missing_assignment_errors() {
        const T: usize = 4;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = ArrayUpdateCircuit::<T> {
            selectors: None,
            values: Some([Fr::ZERO; T]),
            new_val: Some(Fr::ZERO),
            out: Some([Fr::ZERO; T]),
        }
        .generate_constraints(cs);

        assert!(res.is_err());
    }

    #[test]
    fn array_update_circuit_constraint_count_regression_guard() {
        const T: usize = 6;

        let old = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
        ];
        let selectors = one_hot::<T>(3);
        let new_val = Fr::from(99u64);

        let mut out = old;
        out[3] = new_val;

        let cs = run(ArrayUpdateCircuit::<T> {
            selectors: Some(selectors),
            values: Some(old),
            new_val: Some(new_val),
            out: Some(out),
        });

        assert!(cs.is_satisfied().unwrap());

        let expected = 3 * T + 1;
        assert_eq!(cs.num_constraints(), expected);
    }

    #[test]
    fn array_update_expected_values_match_mux_poly_per_slot() {
        const T: usize = 4;
        let old = [
            Fr::from(8u64),
            Fr::from(9u64),
            Fr::from(10u64),
            Fr::from(11u64),
        ];
        let selectors = one_hot::<T>(0);
        let new_val = Fr::from(123u64);

        for i in 0..T {
            let expected_i = mux_poly(selectors[i], new_val, old[i]); // if s=1 -> new, else old
            if i == 0 {
                assert_eq!(expected_i, new_val);
            } else {
                assert_eq!(expected_i, old[i]);
            }
        }
    }
}
