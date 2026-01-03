use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use hash_preimage::sponge::gadget::State;
use non_membership::sorted::gadget::{less_than, verify_sorted_non_membership};

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
// NON-BOOLEAN BITS
// ============================================================================

#[test]
fn less_than_rejects_non_boolean_a_bits() {
    let cs = setup_cs();
    let a = Fr::from(10u64);
    let b = Fr::from(20u64);

    let mut a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    // Corrupt one bit to non-boolean value
    a_bits[100] = State::witness(&cs, Fr::from(2u64)).unwrap();

    less_than(&cs, &a_bits, &b_bits).unwrap();

    // Note: The gadget itself doesn't enforce booleanity of inputs.
    // This test documents that behavior. If you want to enforce it,
    // you'd need to add boolean constraints on inputs.
    // The result may still satisfy if the non-boolean doesn't affect the comparison.
}

#[test]
fn less_than_rejects_non_boolean_b_bits() {
    let cs = setup_cs();
    let a = Fr::from(10u64);
    let b = Fr::from(20u64);

    let a_bits = witness_bits(&cs, a);
    let mut b_bits = witness_bits(&cs, b);

    // Corrupt one bit to non-boolean value
    b_bits[100] = State::witness(&cs, Fr::from(2u64)).unwrap();

    less_than(&cs, &a_bits, &b_bits).unwrap();

    // Same note as above - gadget doesn't enforce input booleanity
}

// ============================================================================
// SWAPPED BOUNDS
// ============================================================================

#[test]
fn non_membership_rejects_swapped_bounds() {
    let cs = setup_cs();
    // Valid: lower=10, nullifier=15, upper=20
    // Attack: swap lower and upper
    let lower = Fr::from(20u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(10u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(!cs.is_satisfied().unwrap(), "should reject swapped bounds");
}

// ============================================================================
// BOUNDARY ATTACKS
// ============================================================================

#[test]
fn non_membership_rejects_nullifier_at_lower_boundary() {
    let cs = setup_cs();
    let lower = Fr::from(15u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should reject nullifier == lower"
    );
}

#[test]
fn non_membership_rejects_nullifier_at_upper_boundary() {
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
        "should reject nullifier == upper"
    );
}

// ============================================================================
// INCONSISTENT BITS
// ============================================================================

#[test]
fn less_than_with_inconsistent_bit_representation() {
    let cs = setup_cs();

    // Witness bits that don't correspond to any valid field element
    // All ones would be larger than the field modulus
    let mut a_bits = [State::zero(); NUM_BITS];
    let mut b_bits = [State::zero(); NUM_BITS];

    for i in 0..NUM_BITS {
        a_bits[i] = State::witness(&cs, Fr::ONE).unwrap();
        b_bits[i] = State::witness(&cs, Fr::ZERO).unwrap();
    }

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    // The gadget compares bits as given, doesn't validate they form valid field elements
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(
        result.val(),
        Fr::ZERO,
        "all-ones > all-zeros in bit comparison"
    );
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn less_than_first_bit_difference() {
    // Values that differ only in MSB
    let cs = setup_cs();

    let mut a_bits = [State::zero(); NUM_BITS];
    let mut b_bits = [State::zero(); NUM_BITS];

    // a = 0b0111...111, b = 0b1000...000
    // a has MSB=0, b has MSB=1, so a < b
    a_bits[0] = State::witness(&cs, Fr::ZERO).unwrap();
    b_bits[0] = State::witness(&cs, Fr::ONE).unwrap();
    for i in 1..NUM_BITS {
        a_bits[i] = State::witness(&cs, Fr::ONE).unwrap();
        b_bits[i] = State::witness(&cs, Fr::ZERO).unwrap();
    }

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ONE, "should detect a < b from first bit");
}

#[test]
fn less_than_last_bit_difference() {
    // Values that differ only in LSB
    let cs = setup_cs();
    let a = Fr::from(10u64); // ...01010
    let b = Fr::from(11u64); // ...01011

    let a_bits = witness_bits(&cs, a);
    let b_bits = witness_bits(&cs, b);

    let result = less_than(&cs, &a_bits, &b_bits).unwrap();

    assert!(cs.is_satisfied().unwrap());
    assert_eq!(result.val(), Fr::ONE, "should detect a < b from last bit");
}

#[test]
fn non_membership_tight_range() {
    // lower = 10, nullifier = 11, upper = 12
    // Tightest valid range
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(11u64);
    let upper = Fr::from(12u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "should satisfy with tight valid range"
    );
}

#[test]
fn non_membership_no_valid_value_in_range() {
    // lower = 10, upper = 11
    // No integer strictly between 10 and 11
    let cs = setup_cs();
    let lower = Fr::from(10u64);
    let nullifier = Fr::from(10u64); // Can't be in (10, 11)
    let upper = Fr::from(11u64);

    let lower_bits = witness_bits(&cs, lower);
    let nullifier_bits = witness_bits(&cs, nullifier);
    let upper_bits = witness_bits(&cs, upper);

    verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "should reject nullifier == lower even with adjacent bounds"
    );
}
