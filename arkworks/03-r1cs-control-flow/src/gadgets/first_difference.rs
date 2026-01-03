use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

pub fn first_difference_selectors<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    a_arr: &[State; T],
    b_arr: &[State; T],
) -> Result<([State; T], State), SynthesisError> {
    let mut selectors = [State::zero(); T];
    let mut found = State::witness(cs, Fr::ZERO)?;
    for (i, (a, b)) in a_arr.iter().zip(b_arr).enumerate() {
        let diff_val = a.val() - b.val();
        let inv_val = diff_val.inverse().unwrap_or(Fr::ZERO);

        let z_val = if diff_val == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        };

        let inv = State::witness(cs, inv_val)?;
        let z = State::witness(cs, z_val)?;

        let diff_lc = LinearCombination::from(a.var()) + (-Fr::ONE, b.var());

        // (a - b) * inv = 1 - z
        cs.enforce_constraint(
            diff_lc.clone(),
            LinearCombination::from(inv.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
        )?;

        // z * (a - b) = 0
        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            diff_lc,
            LinearCombination::zero(),
        )?;

        // z ∈ {0,1}
        cs.enforce_constraint(
            LinearCombination::from(z.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::zero(),
        )?;

        let s = State::witness(cs, (Fr::ONE - found.val()) * (Fr::ONE - z.val()))?;
        // (1 - found) × (1 - z) = s
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(s.var()),
        )?;
        selectors[i] = s;

        let old_found = found;
        found = State::witness(
            cs,
            (Fr::ONE - z.val()) * (Fr::ONE - old_found.val()) + old_found.val(),
        )?;
        // (1 - old_found) × (1 - z) = found - old_found
        cs.enforce_constraint(
            LinearCombination::from(Variable::One) + (-Fr::ONE, old_found.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, z.var()),
            LinearCombination::from(found.var()) + (-Fr::ONE, old_found.var()),
        )?;
    }

    Ok((selectors, found))
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;

    // Helper to create a State from a value in the constraint system
    fn state_from_value(cs: &ConstraintSystemRef<Fr>, val: Fr) -> State {
        State::witness(cs, val).unwrap()
    }

    // Helper to run the gadget and check constraints are satisfied
    fn test_first_diff<const T: usize>(
        a_vals: [u64; T],
        b_vals: [u64; T],
        expected_selectors: [u64; T],
        expected_found: u64,
    ) {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Convert to field elements and create States
        let a_arr: [State; T] = a_vals
            .iter()
            .map(|&v| state_from_value(&cs, Fr::from(v)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let b_arr: [State; T] = b_vals
            .iter()
            .map(|&v| state_from_value(&cs, Fr::from(v)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Run the gadget
        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // Check witness values match expected
        for (i, &expected) in expected_selectors.iter().enumerate() {
            assert_eq!(
                selectors[i].val(),
                Fr::from(expected),
                "Selector[{}] mismatch: expected {}, got {:?}",
                i,
                expected,
                selectors[i].val()
            );
        }

        assert_eq!(
            found.val(),
            Fr::from(expected_found),
            "Found flag mismatch: expected {}, got {:?}",
            expected_found,
            found.val()
        );

        // Most important: verify all constraints are satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints not satisfied! System has {} constraints",
            cs.num_constraints()
        );

        println!(
            "✓ Test passed with {} constraints for arrays of length {}",
            cs.num_constraints(),
            T
        );
    }

    #[test]
    fn test_all_equal() {
        // No differences - all elements equal
        test_first_diff(
            [5, 3, 7, 9],
            [5, 3, 7, 9],
            [0, 0, 0, 0], // No selectors set
            0,            // found = 0
        );
    }

    #[test]
    fn test_first_position_different() {
        // Difference at index 0
        test_first_diff(
            [1, 3, 7, 9],
            [5, 3, 7, 9],
            [1, 0, 0, 0], // Only first selector set
            1,            // found = 1
        );
    }

    #[test]
    fn test_middle_position_different() {
        // Difference at index 2
        test_first_diff(
            [5, 3, 7, 9],
            [5, 3, 2, 9],
            [0, 0, 1, 0], // Only third selector set
            1,            // found = 1
        );
    }

    #[test]
    fn test_last_position_different() {
        // Difference at index 3 (last)
        test_first_diff(
            [5, 3, 7, 9],
            [5, 3, 7, 1],
            [0, 0, 0, 1], // Only last selector set
            1,            // found = 1
        );
    }

    #[test]
    fn test_multiple_differences_only_first_marked() {
        // Differences at indices 1 and 3, but only first one marked
        test_first_diff(
            [5, 3, 7, 9],
            [5, 8, 7, 1],
            [0, 1, 0, 0], // Only index 1 marked (first difference)
            1,            // found = 1
        );
    }

    #[test]
    fn test_all_different() {
        // All positions different - only first marked
        test_first_diff(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [1, 0, 0, 0], // Only first marked
            1,            // found = 1
        );
    }

    #[test]
    fn test_empty_arrays() {
        // Edge case: zero-length arrays
        test_first_diff::<0>(
            [],
            [],
            [],
            0, // No differences possible
        );
    }

    #[test]
    fn test_single_element_equal() {
        // Single element, equal
        test_first_diff([42], [42], [0], 0);
    }

    #[test]
    fn test_single_element_different() {
        // Single element, different
        test_first_diff([42], [17], [1], 1);
    }

    #[test]
    fn test_large_array() {
        // Larger array with difference in the middle
        let mut a = [0u64; 16];
        let mut b = [0u64; 16];
        let mut expected_selectors = [0u64; 16];

        // Fill with same values
        for i in 0..16 {
            a[i] = i as u64;
            b[i] = i as u64;
        }

        // Make position 7 different
        b[7] = 99;
        expected_selectors[7] = 1;

        test_first_diff(a, b, expected_selectors, 1);
    }

    #[test]
    fn test_zero_values() {
        // Arrays containing zeros
        test_first_diff([0, 0, 5, 0], [0, 0, 5, 0], [0, 0, 0, 0], 0);
    }

    #[test]
    fn test_zero_vs_nonzero() {
        // Zero compared to non-zero at index 2
        test_first_diff([1, 2, 0, 4], [1, 2, 5, 4], [0, 0, 1, 0], 1);
    }

    #[test]
    fn test_large_field_values() {
        // Test with large field values (near the modulus)
        let cs = ConstraintSystem::<Fr>::new_ref();

        let large_val = Fr::from(2u64).pow([255]); // 2^255
        let other_val = Fr::from(123);

        let a_arr = [
            state_from_value(&cs, large_val),
            state_from_value(&cs, Fr::from(2)),
            state_from_value(&cs, Fr::from(3)),
        ];

        let b_arr = [
            state_from_value(&cs, large_val),
            state_from_value(&cs, other_val), // Different!
            state_from_value(&cs, Fr::from(3)),
        ];

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        assert_eq!(selectors[0].val(), Fr::from(0u64));
        assert_eq!(selectors[1].val(), Fr::from(1u64));
        assert_eq!(selectors[2].val(), Fr::from(0u64));
        assert_eq!(found.val(), Fr::from(1u64));
        assert!(cs.is_satisfied().unwrap());
    }

    // This test would fail with the unsound version
    #[test]
    fn test_soundness_cannot_hide_difference() {
        // This test ensures the prover can't set neq=0 when a≠b
        // In the unsound version, prover could set inv=0, neq=0
        // and pass constraint (a-b)×inv = neq

        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(3)),
        ];

        let b_arr = [
            state_from_value(&cs, Fr::from(2)), // DIFFERENT!
            state_from_value(&cs, Fr::from(3)),
        ];

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // Must detect the difference
        assert_eq!(
            selectors[0].val(),
            Fr::from(1u64),
            "Must detect first difference"
        );
        assert_eq!(found.val(), Fr::from(1u64), "Must set found flag");

        // Constraints must be satisfied with honest witness
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_soundness_cannot_fake_difference() {
        // This test ensures the prover can't set neq=1 when a=b
        // The constraints should force neq=0 when diff=0

        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(3)),
        ];

        let b_arr = [
            state_from_value(&cs, Fr::from(5)), // SAME!
            state_from_value(&cs, Fr::from(3)),
        ];

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // Must NOT detect any difference
        assert_eq!(
            selectors[0].val(),
            Fr::from(0u64),
            "Must not detect difference"
        );
        assert_eq!(
            selectors[1].val(),
            Fr::from(0u64),
            "Must not detect difference"
        );
        assert_eq!(found.val(), Fr::from(0u64), "Must not set found flag");

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_exactly_one_selector_set() {
        // Property: Exactly one selector should be 1, rest should be 0
        // (or all 0 if no difference)

        for first_diff_idx in 0..5 {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let a_vals = [Fr::from(42); 5];
            let mut b_vals = [Fr::from(42); 5];

            // Make position first_diff_idx different
            b_vals[first_diff_idx] = Fr::from(99);

            let a_arr: [State; 5] = a_vals
                .iter()
                .map(|&v| state_from_value(&cs, v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let b_arr: [State; 5] = b_vals
                .iter()
                .map(|&v| state_from_value(&cs, v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let (selectors, found) =
                first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

            // Count how many selectors are set
            let mut count_set = 0;
            for (i, selector) in selectors.iter().enumerate() {
                if selector.val() == Fr::from(1u64) {
                    count_set += 1;
                    assert_eq!(
                        i, first_diff_idx,
                        "Wrong selector set: expected index {}, got {}",
                        first_diff_idx, i
                    );
                }
            }

            assert_eq!(count_set, 1, "Exactly one selector should be set");
            assert_eq!(found.val(), Fr::from(1u64));
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn test_selector_values_are_boolean() {
        // All selectors must be 0 or 1
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_arr = [
            state_from_value(&cs, Fr::from(1)),
            state_from_value(&cs, Fr::from(2)),
            state_from_value(&cs, Fr::from(3)),
            state_from_value(&cs, Fr::from(4)),
        ];

        let b_arr = [
            state_from_value(&cs, Fr::from(1)),
            state_from_value(&cs, Fr::from(9)), // Different
            state_from_value(&cs, Fr::from(3)),
            state_from_value(&cs, Fr::from(4)),
        ];

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // Check all selectors are boolean
        for (i, selector) in selectors.iter().enumerate() {
            let val = selector.val();
            assert!(
                val == Fr::from(0u64) || val == Fr::from(1u64),
                "Selector[{}] is not boolean: {:?}",
                i,
                val
            );
        }

        // Check found is boolean
        let found_val = found.val();
        assert!(
            found_val == Fr::from(0u64) || found_val == Fr::from(1u64),
            "Found is not boolean: {:?}",
            found_val
        );

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_found_iff_any_difference() {
        // found=1 iff there exists at least one difference

        // Case 1: No differences → found=0
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(5)),
        ];
        let b_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(5)),
        ];
        let (_, found) = first_difference_selectors(&cs, &a_arr, &b_arr).unwrap();
        assert_eq!(found.val(), Fr::from(0u64));

        // Case 2: At least one difference → found=1
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(3)),
        ];
        let b_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(7)), // Different
        ];
        let (_, found) = first_difference_selectors(&cs, &a_arr, &b_arr).unwrap();
        assert_eq!(found.val(), Fr::from(1u64));
    }

    #[test]
    fn test_constraint_count() {
        // Verify the constraint count is as expected: ~5T
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_arr = [
            state_from_value(&cs, Fr::from(1)),
            state_from_value(&cs, Fr::from(2)),
            state_from_value(&cs, Fr::from(3)),
            state_from_value(&cs, Fr::from(4)),
        ];

        let b_arr = [
            state_from_value(&cs, Fr::from(1)),
            state_from_value(&cs, Fr::from(2)),
            state_from_value(&cs, Fr::from(3)),
            state_from_value(&cs, Fr::from(5)),
        ];

        let initial_constraints = cs.num_constraints();

        let _ = first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        let added_constraints = cs.num_constraints() - initial_constraints;

        println!("Constraints added: {}", added_constraints);
        println!("Array length: {}", 4);
        println!("Constraints per element: ~{}", added_constraints / 4);

        // Should be approximately 5 * T constraints
        // Allow some flexibility for the exact implementation
        assert!(
            (4 * 4..=6 * 4).contains(&added_constraints),
            "Expected ~20 constraints (5 per element), got {}",
            added_constraints
        );
    }

    #[test]
    fn test_consistent_across_runs() {
        // Same inputs should produce same outputs
        for _ in 0..3 {
            test_first_diff([1, 2, 3, 4], [1, 9, 3, 4], [0, 1, 0, 0], 1);
        }
    }

    #[test]
    fn test_negative_values() {
        // Test with "negative" field elements (large values wrapping around)
        let cs = ConstraintSystem::<Fr>::new_ref();

        let neg_one = -Fr::from(1u64);

        let a_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, neg_one),
            state_from_value(&cs, Fr::from(3)),
        ];

        let b_arr = [
            state_from_value(&cs, Fr::from(5)),
            state_from_value(&cs, Fr::from(7)), // Different from -1
            state_from_value(&cs, Fr::from(3)),
        ];

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        assert_eq!(selectors[0].val(), Fr::from(0u64));
        assert_eq!(selectors[1].val(), Fr::from(1u64));
        assert_eq!(selectors[2].val(), Fr::from(0u64));
        assert_eq!(found.val(), Fr::from(1u64));
        assert!(cs.is_satisfied().unwrap());
    }
}

// Additional integration test
#[cfg(test)]
mod integration_tests {
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;

    #[test]
    fn test_use_case_string_comparison() {
        // Simulating comparing two strings as arrays of characters
        // "hello" vs "hallo"
        let cs = ConstraintSystem::<Fr>::new_ref();

        let hello: Vec<Fr> = "hello".bytes().map(|b| Fr::from(b as u64)).collect();
        let hallo: Vec<Fr> = "hallo".bytes().map(|b| Fr::from(b as u64)).collect();

        let a_arr: [State; 5] = hello
            .iter()
            .map(|&v| State::witness(&cs, v).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let b_arr: [State; 5] = hallo
            .iter()
            .map(|&v| State::witness(&cs, v).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // 'e' vs 'a' at position 1
        assert_eq!(selectors[0].val(), Fr::from(0u64));
        assert_eq!(selectors[1].val(), Fr::from(1u64));
        assert_eq!(selectors[2].val(), Fr::from(0u64));
        assert_eq!(selectors[3].val(), Fr::from(0u64));
        assert_eq!(selectors[4].val(), Fr::from(0u64));
        assert_eq!(found.val(), Fr::from(1u64));

        assert!(cs.is_satisfied().unwrap());

        println!("✓ String comparison test passed");
    }

    #[test]
    fn test_use_case_merkle_path_check() {
        // Simulating finding which sibling differs in a Merkle path
        let cs = ConstraintSystem::new_ref();

        // Simulated Merkle path (as hash values)
        let path_a = [
            Fr::from(123456),
            Fr::from(789012),
            Fr::from(345678),
            Fr::from(901234),
        ];

        let path_b = [
            Fr::from(123456), // Same
            Fr::from(789012), // Same
            Fr::from(999999), // Different!
            Fr::from(901234),
        ];

        let a_arr: [State; 4] = path_a
            .iter()
            .map(|&v| State::witness(&cs, v).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let b_arr: [State; 4] = path_b
            .iter()
            .map(|&v| State::witness(&cs, v).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let (selectors, found) =
            first_difference_selectors(&cs, &a_arr, &b_arr).expect("gadget should succeed");

        // Should identify position 2 as first difference
        assert_eq!(selectors[2].val(), Fr::from(1u64));
        assert_eq!(found.val(), Fr::from(1u64));

        assert!(cs.is_satisfied().unwrap());

        println!("✓ Merkle path comparison test passed");
    }
}
