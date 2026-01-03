use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use hash_preimage::sponge::gadget::State;

use non_membership::sorted::{
    gadget::{less_than, verify_sorted_non_membership},
    native::{less_than as native_less_than, verify_sorted_non_membership as native_verify},
};

const NUM_BITS: usize = 254;

fn setup_cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

fn to_bits_be(val: Fr) -> [Fr; NUM_BITS] {
    let bits = val.into_bigint().to_bits_be();
    let mut result = [Fr::ZERO; NUM_BITS];
    // Skip first 2 bits, take bits[2..256]
    for (i, bit) in bits.iter().skip(2).enumerate() {
        result[i] = if *bit { Fr::ONE } else { Fr::ZERO };
    }
    result
}

fn witness_bits(cs: &ConstraintSystemRef<Fr>, val: Fr) -> [State; NUM_BITS] {
    let bits = to_bits_be(val);
    let mut result = [State::zero(); NUM_BITS];
    for (i, bit) in bits.iter().enumerate() {
        result[i] = State::witness(cs, *bit).unwrap();
    }
    result
}

// ============================================================================
// LESS_THAN CONSTRAINT SATISFACTION
// ============================================================================

#[test]
fn less_than_satisfies_when_true() {
    let cs = setup_cs();
    let a = Fr::from(10u64);
    let b = Fr::from(20u64);

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ONE, "result should be 1 when a < b");
}

#[test]
fn less_than_satisfies_when_false() {
    let cs = setup_cs();
    let a = Fr::from(20u64);
    let b = Fr::from(10u64);

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ZERO, "result should be 0 when a > b");
}

#[test]
fn less_than_satisfies_when_equal() {
    let cs = setup_cs();
    let a = Fr::from(15u64);
    let b = Fr::from(15u64);

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ZERO, "result should be 0 when a == b");
}

#[test]
fn less_than_adjacent_values() {
    for i in 0u64..10 {
        let cs = setup_cs();
        let a = Fr::from(i);
        let b = Fr::from(i + 1);

        let a_bits = witness_bits(&cs, a);
        let b_bits = witness_bits(&cs, b);

        let result = less_than(&cs, &a_bits, &b_bits).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.val(), Fr::ONE);
    }
}

#[test]
fn less_than_zero_vs_nonzero() {
    let cs = setup_cs();
    let a = Fr::ZERO;
    let b = Fr::from(1u64);

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ONE);
}

// ============================================================================
// CONSISTENCY WITH NATIVE
// ============================================================================

#[test]
fn less_than_consistent_with_native() {
    let test_cases = vec![
        (Fr::from(1u64), Fr::from(2u64)),
        (Fr::from(2u64), Fr::from(1u64)),
        (Fr::from(0u64), Fr::from(0u64)),
        (Fr::from(100u64), Fr::from(200u64)),
        (Fr::from(200u64), Fr::from(100u64)),
        (Fr::ZERO, Fr::from(1u64)),
        (Fr::from(1u64), Fr::ZERO),
    ];

    for (a, b) in test_cases {
        let cs = setup_cs();
        let a_bits = witness_bits(&cs, a);
        let b_bits = witness_bits(&cs, b);

        let gadget_result = less_than(&cs, &a_bits, &b_bits).unwrap();
        let native_result = native_less_than(a, b);

        assert!(cs.is_satisfied().unwrap());

        let expected = if native_result { Fr::ONE } else { Fr::ZERO };
        assert_eq!(
            gadget_result.val(),
            expected,
            "gadget and native disagree for a={:?}, b={:?}",
            a,
            b
        );
    }
}

// ============================================================================
// VERIFY_SORTED_NON_MEMBERSHIP
// ============================================================================

#[test]
fn non_membership_satisfies_valid_range() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "should satisfy when lower < nullifier < upper"
    );
}

#[test]
fn non_membership_fails_nullifier_equals_lower() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(10u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should fail when nullifier == lower"
    );
}

#[test]
fn non_membership_fails_nullifier_equals_upper() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(20u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should fail when nullifier == upper"
    );
}

#[test]
fn non_membership_fails_nullifier_below_lower() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(5u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should fail when nullifier < lower"
    );
}

#[test]
fn non_membership_fails_nullifier_above_upper() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(25u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should fail when nullifier > upper"
    );
}

#[test]
fn non_membership_consistent_with_native() {
    let test_cases = vec![
        (Fr::from(10u64), Fr::from(15u64), Fr::from(20u64), true),
        (Fr::from(10u64), Fr::from(10u64), Fr::from(20u64), false),
        (Fr::from(10u64), Fr::from(20u64), Fr::from(20u64), false),
        (Fr::from(10u64), Fr::from(5u64), Fr::from(20u64), false),
        (Fr::from(10u64), Fr::from(25u64), Fr::from(20u64), false),
        (Fr::ZERO, Fr::from(50u64), Fr::from(100u64), true),
    ];

    for (lower, nullifier, upper, expected) in test_cases {
        let cs = setup_cs();
        let lower_bits = witness_bits(&cs, lower);
        let nullifier_bits = witness_bits(&cs, nullifier);
        let upper_bits = witness_bits(&cs, upper);

        verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

        let gadget_satisfied = cs.is_satisfied().unwrap();
        let native_result = native_verify(nullifier, lower, upper);

        assert_eq!(
            gadget_satisfied, expected,
            "gadget result mismatch for lower={:?}, nullifier={:?}, upper={:?}",
            lower, nullifier, upper
        );
        assert_eq!(
            native_result, expected,
            "native result mismatch for lower={:?}, nullifier={:?}, upper={:?}",
            lower, nullifier, upper
        );
    }
}

// ============================================================================
// CONSTRAINT COUNT
// ============================================================================

#[test]
fn less_than_constraint_count() {
    let cs = setup_cs();
    let a = Fr::from(10u64);
    let b = Fr::from(20u64);

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    less_than(&cs, &a_bits, &b_bits).unwrap();

    let num_constraints = cs.num_constraints();
    println!(
        "less_than constraints (NUM_BITS={}): {}",
        NUM_BITS, num_constraints
    );

    // Expected: ~6 constraints per bit = ~1524 for 254 bits
    assert!(num_constraints > 0);
    assert!(num_constraints < 2000, "constraint count seems too high");
}

#[test]
fn non_membership_constraint_count() {
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    let num_constraints = cs.num_constraints();
    println!(
        "verify_sorted_non_membership constraints (NUM_BITS={}): {}",
        NUM_BITS, num_constraints
    );

    // Expected: ~2 * less_than + 1 = ~3049
    assert!(num_constraints > 0);
    assert!(num_constraints < 5000, "constraint count seems too high");
}
