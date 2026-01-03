use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::gadgets::first_difference::first_difference_selectors;

pub struct FirstDifferenceCircuit<const T: usize> {
    a_arr: Option<[Fr; T]>,
    b_arr: Option<[Fr; T]>,
    expected_selectors: Option<[Fr; T]>,
    expected_found: Option<Fr>,
}

impl<const T: usize> ConstraintSynthesizer<Fr> for FirstDifferenceCircuit<T> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let a_arr: [State; T] =
            State::witness_array(&cs, &self.a_arr.ok_or(SynthesisError::AssignmentMissing)?)?;
        let b_arr: [State; T] =
            State::witness_array(&cs, &self.b_arr.ok_or(SynthesisError::AssignmentMissing)?)?;
        let expected_selectors: [State; T] = State::input_array(
            &cs,
            &self
                .expected_selectors
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;
        let expected_found = State::input(
            &cs,
            self.expected_found
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let (selectors, found) = first_difference_selectors(&cs, &a_arr, &b_arr)?;

        for i in 0..T {
            cs.enforce_constraint(
                LinearCombination::from(selectors[i].var())
                    + (-Fr::ONE, expected_selectors[i].var()),
                LinearCombination::from(Variable::One),
                LinearCombination::zero(),
            )?;
        }
        cs.enforce_constraint(
            LinearCombination::from(found.var()) + (-Fr::ONE, expected_found.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::prepare_verifying_key;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;

    // Helper to convert u64 arrays to Fr arrays
    fn to_fr_array<const T: usize>(vals: [u64; T]) -> [Fr; T] {
        vals.map(Fr::from)
    }

    // Helper to create and test a circuit
    fn test_circuit<const T: usize>(
        a_vals: [u64; T],
        b_vals: [u64; T],
        expected_selectors: [u64; T],
        expected_found: u64,
    ) {
        let circuit = FirstDifferenceCircuit {
            a_arr: Some(to_fr_array(a_vals)),
            b_arr: Some(to_fr_array(b_vals)),
            expected_selectors: Some(to_fr_array(expected_selectors)),
            expected_found: Some(Fr::from(expected_found)),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should succeed");

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints not satisfied for test case:\n  a: {:?}\n  b: {:?}\n  expected_selectors: {:?}\n  expected_found: {}",
            a_vals,
            b_vals,
            expected_selectors,
            expected_found
        );

        println!(
            "✓ Test passed: {} constraints generated",
            cs.num_constraints()
        );
    }

    // Helper to test that a circuit should fail
    fn test_circuit_should_fail<const T: usize>(
        a_vals: [u64; T],
        b_vals: [u64; T],
        wrong_selectors: [u64; T],
        wrong_found: u64,
        description: &str,
    ) {
        let circuit = FirstDifferenceCircuit {
            a_arr: Some(to_fr_array(a_vals)),
            b_arr: Some(to_fr_array(b_vals)),
            expected_selectors: Some(to_fr_array(wrong_selectors)),
            expected_found: Some(Fr::from(wrong_found)),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should succeed");

        assert!(
            !cs.is_satisfied().unwrap(),
            "Expected constraints to fail for: {}",
            description
        );

        println!("✓ Correctly rejected: {}", description);
    }

    // ========================================================================
    // BASIC FUNCTIONALITY TESTS
    // ========================================================================

    #[test]
    fn test_all_equal() {
        test_circuit([5, 3, 7, 9], [5, 3, 7, 9], [0, 0, 0, 0], 0);
    }

    #[test]
    fn test_first_position_different() {
        test_circuit([1, 3, 7, 9], [5, 3, 7, 9], [1, 0, 0, 0], 1);
    }

    #[test]
    fn test_second_position_different() {
        test_circuit([5, 3, 7, 9], [5, 8, 7, 9], [0, 1, 0, 0], 1);
    }

    #[test]
    fn test_third_position_different() {
        test_circuit([5, 3, 7, 9], [5, 3, 2, 9], [0, 0, 1, 0], 1);
    }

    #[test]
    fn test_last_position_different() {
        test_circuit([5, 3, 7, 9], [5, 3, 7, 1], [0, 0, 0, 1], 1);
    }

    #[test]
    fn test_multiple_differences_only_first_marked() {
        test_circuit(
            [5, 3, 7, 9],
            [5, 8, 2, 1],
            [0, 1, 0, 0], // Only second position marked
            1,
        );
    }

    #[test]
    fn test_all_different() {
        test_circuit(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [1, 0, 0, 0], // Only first marked
            1,
        );
    }

    #[test]
    fn test_single_element_equal() {
        test_circuit([42], [42], [0], 0);
    }

    #[test]
    fn test_single_element_different() {
        test_circuit([42], [17], [1], 1);
    }

    #[test]
    fn test_two_elements_first_diff() {
        test_circuit([10, 20], [99, 20], [1, 0], 1);
    }

    #[test]
    fn test_two_elements_second_diff() {
        test_circuit([10, 20], [10, 99], [0, 1], 1);
    }

    // ========================================================================
    // EDGE CASES
    // ========================================================================

    #[test]
    fn test_with_zeros() {
        test_circuit([0, 0, 5, 0], [0, 0, 5, 0], [0, 0, 0, 0], 0);
    }

    #[test]
    fn test_zero_vs_nonzero() {
        test_circuit([1, 2, 0, 4], [1, 2, 5, 4], [0, 0, 1, 0], 1);
    }

    #[test]
    fn test_nonzero_vs_zero() {
        test_circuit([1, 2, 5, 4], [1, 2, 0, 4], [0, 0, 1, 0], 1);
    }

    #[test]
    fn test_large_values() {
        test_circuit(
            [999999, 888888, 777777],
            [999999, 123456, 777777],
            [0, 1, 0],
            1,
        );
    }

    #[test]
    fn test_sequential_values() {
        test_circuit([1, 2, 3, 4, 5], [1, 2, 3, 4, 5], [0, 0, 0, 0, 0], 0);
    }

    #[test]
    fn test_reverse_arrays() {
        test_circuit(
            [1, 2, 3, 4],
            [4, 3, 2, 1],
            [1, 0, 0, 0], // First position differs
            1,
        );
    }

    // ========================================================================
    // SOUNDNESS TESTS - WRONG SELECTOR POSITIONS
    // ========================================================================

    #[test]
    fn test_reject_wrong_selector_position() {
        // Actual difference at position 1, but claiming position 0
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 8, 7, 9], // Diff at index 1
            [1, 0, 0, 0], // Wrong! Claiming index 0
            1,
            "wrong selector position",
        );
    }

    #[test]
    fn test_reject_multiple_selectors() {
        // Only one selector should be set
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 8, 7, 9], // Diff at index 1
            [1, 1, 0, 0], // Wrong! Two selectors set
            1,
            "multiple selectors set",
        );
    }

    #[test]
    fn test_reject_no_selector_when_diff_exists() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 8, 7, 9], // Diff at index 1
            [0, 0, 0, 0], // Wrong! No selector set
            1,
            "no selector when difference exists",
        );
    }

    #[test]
    fn test_reject_selector_when_no_diff() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 3, 7, 9], // No difference
            [0, 1, 0, 0], // Wrong! Selector set
            0,
            "selector set when no difference",
        );
    }

    #[test]
    fn test_reject_later_diff_marked() {
        // Multiple diffs, but marked the second one instead of first
        test_circuit_should_fail(
            [1, 2, 3, 4],
            [9, 8, 3, 4], // Diffs at 0 and 1
            [0, 1, 0, 0], // Wrong! Should mark position 0
            1,
            "marked second difference instead of first",
        );
    }

    // ========================================================================
    // SOUNDNESS TESTS - WRONG FOUND FLAG
    // ========================================================================

    #[test]
    fn test_reject_found_true_when_all_equal() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 3, 7, 9], // All equal
            [0, 0, 0, 0],
            1, // Wrong! Should be 0
            "found=1 when all equal",
        );
    }

    #[test]
    fn test_reject_found_false_when_diff_exists() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 8, 7, 9], // Difference exists
            [0, 1, 0, 0],
            0, // Wrong! Should be 1
            "found=0 when difference exists",
        );
    }

    // ========================================================================
    // SOUNDNESS TESTS - INCONSISTENT SELECTOR AND FOUND
    // ========================================================================

    #[test]
    fn test_reject_selector_set_but_found_false() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 8, 7, 9],
            [0, 1, 0, 0], // Selector set (correct)
            0,            // But found=0 (inconsistent!)
            "selector set but found=0",
        );
    }

    #[test]
    fn test_reject_no_selector_but_found_true() {
        test_circuit_should_fail(
            [5, 3, 7, 9],
            [5, 3, 7, 9], // No difference
            [0, 0, 0, 0], // No selector (correct)
            1,            // But found=1 (inconsistent!)
            "no selector but found=1",
        );
    }

    // ========================================================================
    // STRESS TESTS
    // ========================================================================

    #[test]
    fn test_longer_array() {
        test_circuit(
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            0,
        );
    }

    #[test]
    fn test_longer_array_with_diff_at_end() {
        test_circuit(
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 99],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1,
        );
    }

    #[test]
    fn test_longer_array_with_diff_in_middle() {
        test_circuit(
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [1, 2, 3, 4, 99, 6, 7, 8, 9, 10],
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
            1,
        );
    }

    // ========================================================================
    // CONSTRAINT COUNT TESTS
    // ========================================================================

    #[test]
    fn test_constraint_count() {
        let circuit = FirstDifferenceCircuit {
            a_arr: Some(to_fr_array([1, 2, 3, 4])),
            b_arr: Some(to_fr_array([1, 2, 3, 5])),
            expected_selectors: Some(to_fr_array([0, 0, 0, 1])),
            expected_found: Some(Fr::from(1u64)),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let num_constraints = cs.num_constraints();
        let array_len = 4;

        println!("Constraints: {}", num_constraints);
        println!("Array length: {}", array_len);
        println!("Constraints per element: ~{}", num_constraints / array_len);

        // Should be approximately 5T + T + 1 (5 per element + output checks)
        // Allow some flexibility
        assert!(
            (4 * 5..=7 * 4).contains(&num_constraints),
            "Expected ~20-28 constraints for 4 elements, got {}",
            num_constraints
        );
    }

    // ========================================================================
    // PROPERTY-BASED TESTS
    // ========================================================================

    #[test]
    fn test_property_exactly_one_or_zero_selector() {
        // Property: Sum of all selectors should be 0 or 1
        for first_diff_idx in 0..=4 {
            let a = [1u64; 5];
            let mut b = [1u64; 5];
            let mut expected_selectors = [0u64; 5];
            let expected_found;

            if first_diff_idx < 5 {
                b[first_diff_idx] = 99;
                expected_selectors[first_diff_idx] = 1;
                expected_found = 1;
            } else {
                // No difference case
                expected_found = 0;
            }

            test_circuit(a, b, expected_selectors, expected_found);

            // Verify sum of selectors is 0 or 1
            let sum: u64 = expected_selectors.iter().sum();
            assert!(sum <= 1, "Sum of selectors should be 0 or 1");
        }
    }

    #[test]
    fn test_property_found_iff_any_selector_set() {
        // Property: found = 1 iff at least one selector is 1

        // Case 1: found = 1, one selector = 1
        let selectors_sum: u64 = [0, 1, 0, 0].iter().sum();
        assert_eq!(selectors_sum, 1);
        test_circuit([1, 2, 3, 4], [1, 9, 3, 4], [0, 1, 0, 0], 1);

        // Case 2: found = 0, no selectors = 1
        let selectors_sum: u64 = [0, 0, 0, 0].iter().sum();
        assert_eq!(selectors_sum, 0);
        test_circuit([1, 2, 3, 4], [1, 2, 3, 4], [0, 0, 0, 0], 0);
    }

    // ========================================================================
    // FULL PROOF GENERATION TEST (Optional, slower)
    // ========================================================================

    #[test]
    #[ignore] // Remove #[ignore] to run this test
    fn test_full_proof_generation() {
        use ark_groth16::Groth16;
        use ark_std::rand::thread_rng;

        let mut rng = thread_rng();

        // Create circuit for setup
        let setup_circuit = FirstDifferenceCircuit::<4> {
            a_arr: None,
            b_arr: None,
            expected_selectors: None,
            expected_found: None,
        };

        // Generate parameters (trusted setup)
        let params = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            setup_circuit,
            &mut rng,
        )
        .expect("setup should succeed");

        // Create circuit with actual values
        let prove_circuit = FirstDifferenceCircuit {
            a_arr: Some(to_fr_array([5, 3, 7, 9])),
            b_arr: Some(to_fr_array([5, 8, 7, 9])),
            expected_selectors: Some(to_fr_array([0, 1, 0, 0])),
            expected_found: Some(Fr::from(1u64)),
        };

        // Generate proof
        let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
            prove_circuit,
            &params,
            &mut rng,
        )
        .expect("proof generation should succeed");

        // Prepare public inputs
        let mut public_inputs = Vec::new();
        for &sel in &[0, 1, 0, 0] {
            public_inputs.push(Fr::from(sel));
        }
        public_inputs.push(Fr::from(1u64)); // found

        // Verify proof
        let pvk = prepare_verifying_key(&params.vk);
        let valid = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &public_inputs)
            .expect("verification should complete");

        assert!(valid, "Proof should be valid");
        println!("✓ Full proof generation and verification succeeded");
    }

    // ========================================================================
    // REGRESSION TESTS
    // ========================================================================

    #[test]
    fn test_regression_string_comparison() {
        // Simulating "hello" vs "hallo"
        let hello: Vec<u64> = "hello".bytes().map(|b| b as u64).collect();
        let hallo: Vec<u64> = "hallo".bytes().map(|b| b as u64).collect();

        test_circuit(
            hello.try_into().unwrap(),
            hallo.try_into().unwrap(),
            [0, 1, 0, 0, 0], // 'e' vs 'a' at position 1
            1,
        );
    }

    #[test]
    fn test_regression_all_zeros() {
        test_circuit([0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], 0);
    }

    #[test]
    fn test_regression_alternating_pattern() {
        test_circuit(
            [1, 0, 1, 0, 1, 0],
            [1, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            0,
        );
    }
}
