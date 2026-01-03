use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
use hash_preimage::sponge::gadget::State;

/// Enforce: if b {x == y}
/// Precondition: b ∈ {0,1}
pub fn enforce_eq_if(
    cs: &ConstraintSystemRef<Fr>,
    b: State,
    x: State,
    y: State,
) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        LinearCombination::from(x.var()) + (-Fr::ONE, y.var()),
        LinearCombination::zero(),
    )?;
    Ok(())
}

/// Enforce: if b {x == 0}
/// Precondition: b ∈ {0,1}
pub fn enforce_zero_if(
    cs: &ConstraintSystemRef<Fr>,
    b: State,
    x: State,
) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        LinearCombination::from(x.var()),
        LinearCombination::zero(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;

    // Helper to create a State from a value
    fn state_from_value(cs: &ConstraintSystemRef<Fr>, val: Fr) -> State {
        State::witness(cs, val).unwrap()
    }

    // ========================================================================
    // TESTS FOR enforce_eq_if
    // ========================================================================

    mod enforce_eq_if_tests {
        use super::*;

        #[test]
        fn test_b_true_x_equals_y() {
            // When b=1, x=5, y=5 → should pass (x == y)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(5u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=1 and x==y"
            );
            println!("✓ b=1, x=5, y=5: PASS");
        }

        #[test]
        fn test_b_true_x_not_equals_y() {
            // When b=1, x=5, y=3 → should FAIL (x != y)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(3u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Constraints should FAIL when b=1 and x!=y"
            );
            println!("✓ b=1, x=5, y=3: Correctly REJECTED");
        }

        #[test]
        fn test_b_false_x_equals_y() {
            // When b=0, x=5, y=5 → should pass (condition not active)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(0u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(5u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=0 (regardless of x,y)"
            );
            println!("✓ b=0, x=5, y=5: PASS (condition inactive)");
        }

        #[test]
        fn test_b_false_x_not_equals_y() {
            // When b=0, x=5, y=3 → should PASS (condition not active)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(0u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(3u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=0 (even if x!=y)"
            );
            println!("✓ b=0, x=5, y=3: PASS (condition inactive, difference ignored)");
        }

        #[test]
        fn test_with_zero_values() {
            // b=1, x=0, y=0 → should pass
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));
            let y = state_from_value(&cs, Fr::from(0u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(cs.is_satisfied().unwrap(), "Should work with zero values");
            println!("✓ b=1, x=0, y=0: PASS");
        }

        #[test]
        fn test_zero_not_equal_nonzero() {
            // b=1, x=0, y=5 → should FAIL
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));
            let y = state_from_value(&cs, Fr::from(5u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Should reject when b=1 and x=0, y=5"
            );
            println!("✓ b=1, x=0, y=5: Correctly REJECTED");
        }

        #[test]
        fn test_large_field_values() {
            // Test with large field values
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let large_val = Fr::from(2u64).pow([100]); // 2^100
            let x = state_from_value(&cs, large_val);
            let y = state_from_value(&cs, large_val);

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Should work with large field values"
            );
            println!("✓ b=1, x=2^100, y=2^100: PASS");
        }

        #[test]
        fn test_negative_field_values() {
            // Test with "negative" field values (large values wrapping around)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let neg_five = -Fr::from(5u64);
            let x = state_from_value(&cs, neg_five);
            let y = state_from_value(&cs, neg_five);

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Should work with negative field values"
            );
            println!("✓ b=1, x=-5, y=-5: PASS");
        }

        #[test]
        fn test_negative_not_equal_positive() {
            // b=1, x=-5, y=5 → should FAIL
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, -Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(5u64));

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Should reject when x=-5 and y=5"
            );
            println!("✓ b=1, x=-5, y=5: Correctly REJECTED");
        }

        #[test]
        fn test_multiple_constraints() {
            // Test multiple enforce_eq_if constraints in same system
            let cs = ConstraintSystem::<Fr>::new_ref();

            let b1 = state_from_value(&cs, Fr::from(1u64));
            let x1 = state_from_value(&cs, Fr::from(10u64));
            let y1 = state_from_value(&cs, Fr::from(10u64));

            let b2 = state_from_value(&cs, Fr::from(0u64));
            let x2 = state_from_value(&cs, Fr::from(20u64));
            let y2 = state_from_value(&cs, Fr::from(99u64));

            let b3 = state_from_value(&cs, Fr::from(1u64));
            let x3 = state_from_value(&cs, Fr::from(30u64));
            let y3 = state_from_value(&cs, Fr::from(30u64));

            enforce_eq_if(&cs, b1, x1, y1).unwrap();
            enforce_eq_if(&cs, b2, x2, y2).unwrap(); // b=0, so diff ignored
            enforce_eq_if(&cs, b3, x3, y3).unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "Multiple constraints should all be satisfied"
            );
            println!("✓ Multiple constraints: PASS");
        }

        #[test]
        fn test_soundness_cannot_bypass_with_non_boolean_b() {
            // IMPORTANT: This gadget assumes b ∈ {0,1}
            // If b is not properly constrained elsewhere, it could be exploited

            // Example: If b=0.5 (or any non-boolean), the constraint becomes:
            // 0.5 × (x - y) = 0
            // Which allows x ≠ y if their difference is small enough

            let cs = ConstraintSystem::<Fr>::new_ref();

            // Let's say b = 2 (not boolean!)
            let b = state_from_value(&cs, Fr::from(2u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(3u64)); // Different!

            enforce_eq_if(&cs, b, x, y).expect("constraint should succeed");

            // The constraint is: 2 × (5 - 3) = 2 × 2 = 4 ≠ 0
            // So this SHOULD fail (and does)
            assert!(!cs.is_satisfied().unwrap(), "Should fail when b=2 and x!=y");

            println!("✓ b=2 (non-boolean), x=5, y=3: Correctly REJECTED");
            println!("  Note: This shows why b MUST be boolean-constrained elsewhere!");
        }

        #[test]
        fn test_constraint_equation_directly() {
            // Verify the constraint is exactly: b × (x - y) = 0
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(7u64));
            let y = state_from_value(&cs, Fr::from(7u64));

            let initial_constraints = cs.num_constraints();
            enforce_eq_if(&cs, b, x, y).unwrap();
            let added_constraints = cs.num_constraints() - initial_constraints;

            assert_eq!(added_constraints, 1, "Should add exactly 1 constraint");
            assert!(cs.is_satisfied().unwrap());
            println!("✓ Constraint count: 1 (as expected)");
        }
    }

    // ========================================================================
    // TESTS FOR enforce_zero_if
    // ========================================================================

    mod enforce_zero_if_tests {
        use super::*;

        #[test]
        fn test_b_true_x_is_zero() {
            // When b=1, x=0 → should pass
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=1 and x=0"
            );
            println!("✓ b=1, x=0: PASS");
        }

        #[test]
        fn test_b_true_x_not_zero() {
            // When b=1, x=5 → should FAIL
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(5u64));

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Constraints should FAIL when b=1 and x!=0"
            );
            println!("✓ b=1, x=5: Correctly REJECTED");
        }

        #[test]
        fn test_b_false_x_is_zero() {
            // When b=0, x=0 → should pass
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(0u64));
            let x = state_from_value(&cs, Fr::from(0u64));

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=0"
            );
            println!("✓ b=0, x=0: PASS");
        }

        #[test]
        fn test_b_false_x_not_zero() {
            // When b=0, x=5 → should PASS (condition not active)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(0u64));
            let x = state_from_value(&cs, Fr::from(5u64));

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraints should be satisfied when b=0 (even if x!=0)"
            );
            println!("✓ b=0, x=5: PASS (condition inactive, non-zero ignored)");
        }

        #[test]
        fn test_large_nonzero_value() {
            // b=1, x=(large value) → should FAIL
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let large_val = Fr::from(2u64).pow([100]);
            let x = state_from_value(&cs, large_val);

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Should reject large non-zero value when b=1"
            );
            println!("✓ b=1, x=2^100: Correctly REJECTED");
        }

        #[test]
        fn test_negative_value() {
            // b=1, x=-5 → should FAIL (negative is not zero)
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, -Fr::from(5u64));

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");
            assert!(
                !cs.is_satisfied().unwrap(),
                "Should reject negative value when b=1"
            );
            println!("✓ b=1, x=-5: Correctly REJECTED");
        }

        #[test]
        fn test_multiple_constraints() {
            // Multiple enforce_zero_if in same system
            let cs = ConstraintSystem::<Fr>::new_ref();

            let b1 = state_from_value(&cs, Fr::from(1u64));
            let x1 = state_from_value(&cs, Fr::from(0u64));

            let b2 = state_from_value(&cs, Fr::from(0u64));
            let x2 = state_from_value(&cs, Fr::from(999u64)); // Non-zero but b=0

            let b3 = state_from_value(&cs, Fr::from(1u64));
            let x3 = state_from_value(&cs, Fr::from(0u64));

            enforce_zero_if(&cs, b1, x1).unwrap();
            enforce_zero_if(&cs, b2, x2).unwrap();
            enforce_zero_if(&cs, b3, x3).unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "Multiple constraints should all be satisfied"
            );
            println!("✓ Multiple constraints: PASS");
        }

        #[test]
        fn test_soundness_non_boolean_b() {
            // If b is not properly boolean-constrained, could be exploited

            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(2u64)); // Not boolean!
            let x = state_from_value(&cs, Fr::from(5u64)); // Non-zero

            enforce_zero_if(&cs, b, x).expect("constraint should succeed");

            // Constraint: 2 × 5 = 10 ≠ 0, so should fail
            assert!(
                !cs.is_satisfied().unwrap(),
                "Should fail with non-boolean b"
            );
            println!("✓ b=2 (non-boolean), x=5: Correctly REJECTED");
        }

        #[test]
        fn test_constraint_count() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));

            let initial_constraints = cs.num_constraints();
            enforce_zero_if(&cs, b, x).unwrap();
            let added_constraints = cs.num_constraints() - initial_constraints;

            assert_eq!(added_constraints, 1, "Should add exactly 1 constraint");
            assert!(cs.is_satisfied().unwrap());
            println!("✓ Constraint count: 1 (as expected)");
        }
    }

    // ========================================================================
    // COMBINED USAGE TESTS
    // ========================================================================

    mod combined_usage_tests {
        use super::*;

        #[test]
        fn test_using_both_gadgets_together() {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let b1 = state_from_value(&cs, Fr::from(1u64));
            let b2 = state_from_value(&cs, Fr::from(0u64));

            let x = state_from_value(&cs, Fr::from(10u64));
            let y = state_from_value(&cs, Fr::from(10u64));
            let z = state_from_value(&cs, Fr::from(0u64));
            let w = state_from_value(&cs, Fr::from(99u64));

            // If b1 then x == y (should pass)
            enforce_eq_if(&cs, b1, x, y).unwrap();

            // If b1 then z == 0 (should pass)
            enforce_zero_if(&cs, b1, z).unwrap();

            // If b2 then x == w (ignored since b2=0)
            enforce_eq_if(&cs, b2, x, w).unwrap();

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Combined usage: PASS");
        }

        #[test]
        fn test_conditional_chain() {
            // Simulate: if (condition1) { assert x == y; assert y == 0; }
            let cs = ConstraintSystem::<Fr>::new_ref();

            let condition = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));
            let y = state_from_value(&cs, Fr::from(0u64));

            enforce_eq_if(&cs, condition, x, y).unwrap();
            enforce_zero_if(&cs, condition, y).unwrap();

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Conditional chain: PASS");
        }

        #[test]
        fn test_conditional_chain_fails() {
            // Same as above but with x != y
            let cs = ConstraintSystem::<Fr>::new_ref();

            let condition = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(5u64));
            let y = state_from_value(&cs, Fr::from(0u64));

            enforce_eq_if(&cs, condition, x, y).unwrap();
            enforce_zero_if(&cs, condition, y).unwrap();

            assert!(!cs.is_satisfied().unwrap(), "Should fail when x != y");
            println!("✓ Conditional chain with mismatch: Correctly REJECTED");
        }

        #[test]
        fn test_mutually_exclusive_conditions() {
            // if (b1) { x == y } else { x == z }
            // Simulate with: if b1 { x == y }, if (1-b1) { x == z }
            let cs = ConstraintSystem::<Fr>::new_ref();

            let b1 = state_from_value(&cs, Fr::from(1u64));
            let b2 = state_from_value(&cs, Fr::from(0u64)); // 1 - b1

            let x = state_from_value(&cs, Fr::from(10u64));
            let y = state_from_value(&cs, Fr::from(10u64));
            let z = state_from_value(&cs, Fr::from(99u64));

            enforce_eq_if(&cs, b1, x, y).unwrap(); // Active
            enforce_eq_if(&cs, b2, x, z).unwrap(); // Inactive

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Mutually exclusive conditions: PASS");
        }
    }

    // ========================================================================
    // DOCUMENTATION / USAGE EXAMPLES
    // ========================================================================

    mod examples {
        use super::*;

        /// Example: Conditional equality in a larger circuit
        #[test]
        fn example_usage_enforce_eq_if() {
            let cs = ConstraintSystem::<Fr>::new_ref();

            // Suppose we have a flag indicating whether to check equality
            let should_check = state_from_value(&cs, Fr::from(1u64));

            // Two values that should be equal when flag is set
            let computed_value = state_from_value(&cs, Fr::from(42u64));
            let expected_value = state_from_value(&cs, Fr::from(42u64));

            // Only enforce equality if should_check = 1
            enforce_eq_if(&cs, should_check, computed_value, expected_value)
                .expect("should succeed");

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Example usage of enforce_eq_if");
        }

        /// Example: Conditional zero check
        #[test]
        fn example_usage_enforce_zero_if() {
            let cs = ConstraintSystem::<Fr>::new_ref();

            // Flag indicating whether value must be zero
            let must_be_zero = state_from_value(&cs, Fr::from(1u64));

            // A value that should be zero when flag is set
            let value = state_from_value(&cs, Fr::from(0u64));

            // Only enforce zero if must_be_zero = 1
            enforce_zero_if(&cs, must_be_zero, value).expect("should succeed");

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Example usage of enforce_zero_if");
        }

        /// Example: Use in selector-based computation
        #[test]
        fn example_selector_based_logic() {
            let cs = ConstraintSystem::<Fr>::new_ref();

            // Suppose selectors indicate which operation to perform
            let selector_add = state_from_value(&cs, Fr::from(1u64));
            let selector_mult = state_from_value(&cs, Fr::from(0u64));

            let result = state_from_value(&cs, Fr::from(7u64)); // 3 + 4
            let expected_product = state_from_value(&cs, Fr::from(12u64));

            // If selector_add = 1, then result == a + b
            let sum = state_from_value(&cs, Fr::from(7u64));
            enforce_eq_if(&cs, selector_add, result, sum).unwrap();

            // If selector_mult = 1, then result == a * b
            enforce_eq_if(&cs, selector_mult, result, expected_product).unwrap();

            assert!(cs.is_satisfied().unwrap());
            println!("✓ Selector-based logic example");
        }
    }

    // ========================================================================
    // EDGE CASE TESTS
    // ========================================================================

    mod edge_cases {
        use super::*;

        #[test]
        fn test_both_x_and_y_are_same_variable() {
            // Edge case: x and y point to same variable
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(5u64));

            // Comparing x with itself - should always pass
            enforce_eq_if(&cs, b, x, x).unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!("✓ x == x (same variable): PASS");
        }

        #[test]
        fn test_zero_equals_zero() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let zero1 = state_from_value(&cs, Fr::from(0u64));
            let zero2 = state_from_value(&cs, Fr::from(0u64));

            enforce_eq_if(&cs, b, zero1, zero2).unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!("✓ 0 == 0: PASS");
        }

        #[test]
        fn test_enforce_zero_on_same_variable() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = state_from_value(&cs, Fr::from(1u64));
            let x = state_from_value(&cs, Fr::from(0u64));

            enforce_zero_if(&cs, b, x).unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!("✓ enforce_zero on variable that is zero: PASS");
        }
    }
}
