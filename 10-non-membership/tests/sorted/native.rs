use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use non_membership::sorted::native::{less_than, verify_sorted_non_membership};

// ============================================================================
// LESS_THAN BASIC
// ============================================================================

#[test]
fn less_than_small_values() {
    assert!(less_than(Fr::from(1u64), Fr::from(2u64)));
    assert!(less_than(Fr::from(0u64), Fr::from(1u64)));
    assert!(less_than(Fr::from(100u64), Fr::from(200u64)));
}

#[test]
fn less_than_returns_false_when_greater() {
    assert!(!less_than(Fr::from(2u64), Fr::from(1u64)));
    assert!(!less_than(Fr::from(200u64), Fr::from(100u64)));
    assert!(!less_than(Fr::from(1u64), Fr::from(0u64)));
}

#[test]
fn less_than_equal_values() {
    assert!(!less_than(Fr::from(0u64), Fr::from(0u64)));
    assert!(!less_than(Fr::from(1u64), Fr::from(1u64)));
    assert!(!less_than(Fr::from(999u64), Fr::from(999u64)));
}

#[test]
fn less_than_zero() {
    assert!(less_than(Fr::ZERO, Fr::from(1u64)));
    assert!(less_than(Fr::ZERO, Fr::from(1000u64)));
    assert!(!less_than(Fr::from(1u64), Fr::ZERO));
}

#[test]
fn less_than_adjacent_values() {
    for i in 0u64..100 {
        assert!(less_than(Fr::from(i), Fr::from(i + 1)));
        assert!(!less_than(Fr::from(i + 1), Fr::from(i)));
    }
}

#[test]
fn less_than_large_values() {
    let large_a = Fr::from(u64::MAX - 1);
    let large_b = Fr::from(u64::MAX);
    assert!(less_than(large_a, large_b));
    assert!(!less_than(large_b, large_a));
}

#[test]
fn less_than_field_max() {
    let max = -Fr::ONE; // p - 1, the largest field element
    let zero = Fr::ZERO;
    let one = Fr::ONE;

    assert!(less_than(zero, max));
    assert!(less_than(one, max));
    assert!(!less_than(max, zero));
    assert!(!less_than(max, one));
    assert!(!less_than(max, max));
}

// ============================================================================
// VERIFY_SORTED_NON_MEMBERSHIP
// ============================================================================

#[test]
fn non_membership_valid_range() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    assert!(verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_adjacent_bounds() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(11u64);
    let upper = Fr::from(12u64);

    assert!(verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_nullifier_equals_lower() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(10u64);
    let upper = Fr::from(20u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_nullifier_equals_upper() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(20u64);
    let upper = Fr::from(20u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_nullifier_below_lower() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(5u64);
    let upper = Fr::from(20u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_nullifier_above_upper() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(25u64);
    let upper = Fr::from(20u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_invalid_bounds() {
    // lower >= upper is invalid
    let lower = Fr::from(20u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(10u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_fails_equal_bounds() {
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(10u64);
    let upper = Fr::from(10u64);

    assert!(!verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_zero_lower_bound() {
    let lower = Fr::ZERO;
    let nullifier = Fr::from(50u64);
    let upper = Fr::from(100u64);

    assert!(verify_sorted_non_membership(nullifier, lower, upper));
}

#[test]
fn non_membership_at_field_extremes() {
    let lower = Fr::ZERO;
    let nullifier = Fr::from(1000u64);
    let upper = -Fr::ONE; // p - 1

    assert!(verify_sorted_non_membership(nullifier, lower, upper));
}
