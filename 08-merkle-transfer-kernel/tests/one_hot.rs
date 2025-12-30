use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::ConstraintSystem;
use hash_preimage::sponge::gadget::State;
use merkle_transfer_kernel::circuit::DEPTH;
use merkle_transfer_kernel::gadget::{enforce_one_hot, first_difference_selectors};

/// Test helper: Manually construct selectors that violate one-hot property
/// and verify this breaks the circuit when one-hot isn't enforced.
///
/// This test documents that enforce_one_hot is CRITICAL for soundness.
#[test]
fn test_one_hot_is_load_bearing_documentation() {
    // This test demonstrates WHY one-hot is necessary by showing what
    // would happen if selectors weren't properly constrained.

    // If selectors were [0.5, 0.5, 0, 0, ...] instead of one-hot:
    // - select_from_array would return a weighted average
    // - update_one_slot would partially update multiple slots
    // This could allow creating inconsistent state transitions.

    // We can't actually bypass enforce_one_hot in the circuit without
    // modifying it, but we CAN verify that our first_difference_selectors
    // always produces valid one-hot outputs for valid inputs.

    let test_cases: Vec<([Fr; DEPTH], [Fr; DEPTH])> = vec![
        // Case 1: Differ at position 0
        ([Fr::ZERO; DEPTH], {
            let mut b = [Fr::ZERO; DEPTH];
            b[0] = Fr::ONE;
            b
        }),
        // Case 2: Differ at position 3
        (
            {
                let mut a = [Fr::ZERO; DEPTH];
                a[0] = Fr::ONE;
                a[1] = Fr::ONE;
                a[2] = Fr::ONE;
                a
            },
            {
                let mut b = [Fr::ZERO; DEPTH];
                b[0] = Fr::ONE;
                b[1] = Fr::ONE;
                b[2] = Fr::ONE;
                b[3] = Fr::ONE;
                b
            },
        ),
        // Case 3: Differ at last position
        (
            {
                let mut a = [Fr::ZERO; DEPTH];
                for elem in a.iter_mut().take(DEPTH - 1) {
                    *elem = Fr::ONE;
                }
                a
            },
            [Fr::ONE; DEPTH],
        ),
    ];

    for (i, (a_bits, b_bits)) in test_cases.iter().enumerate() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_states: [State; DEPTH] = State::witness_array(&cs, a_bits).unwrap();
        let b_states: [State; DEPTH] = State::witness_array(&cs, b_bits).unwrap();

        let (selectors, found) = first_difference_selectors(&cs, &a_states, &b_states).unwrap();

        // Verify exactly one selector is 1
        let sum: Fr = selectors.iter().map(|s| s.val()).sum();
        assert_eq!(sum, Fr::ONE, "Case {}: selectors must sum to 1", i);

        // Verify each selector is binary
        for (j, s) in selectors.iter().enumerate() {
            assert!(
                s.val() == Fr::ZERO || s.val() == Fr::ONE,
                "Case {}: selector {} must be binary, got {:?}",
                i,
                j,
                s.val()
            );
        }

        // Verify found is 1
        assert_eq!(found.val(), Fr::ONE, "Case {}: found must be 1", i);

        // Verify the one-hot constraint is satisfied
        enforce_one_hot(&cs, &selectors).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "Case {}: constraints must be satisfied",
            i
        );
    }

    println!("✓ One-hot: first_difference_selectors always produces valid one-hot");
}

#[test]
fn test_one_hot_multi_select_attack_blocked() {
    // This test verifies that if an attacker tried to set multiple selectors to 1
    // (which would allow selecting/updating multiple values simultaneously),
    // the one-hot constraint would catch it.

    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create "malicious" selectors where two positions are 1
    let mut malicious_vals = [Fr::ZERO; DEPTH];
    malicious_vals[0] = Fr::ONE;
    malicious_vals[1] = Fr::ONE; // TWO positions are 1!

    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    // Try to enforce one-hot on these malicious selectors
    enforce_one_hot(&cs, &selectors).unwrap();

    // The constraint system should NOT be satisfied
    assert!(
        !cs.is_satisfied().unwrap(),
        "Multi-select (two 1s) should be rejected by one-hot constraint"
    );

    println!("✓ One-hot: multi-select attack (two 1s) correctly blocked");
}

#[test]
fn test_one_hot_zero_select_attack_blocked() {
    // This test verifies that if an attacker tried to set ALL selectors to 0
    // (which would mean no update happens), the one-hot constraint catches it.

    let cs = ConstraintSystem::<Fr>::new_ref();

    // All zeros - no selection at all
    let malicious_vals = [Fr::ZERO; DEPTH];
    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Zero-select (all 0s) should be rejected by one-hot constraint"
    );

    println!("✓ One-hot: zero-select attack (all 0s) correctly blocked");
}

#[test]
fn test_one_hot_fractional_attack_blocked() {
    // This test verifies that non-binary selector values are rejected.
    // An attacker might try to use fractional values to partially update.

    let cs = ConstraintSystem::<Fr>::new_ref();

    // Try fractional values that sum to 1
    let half = Fr::ONE.double().inverse().unwrap(); // 0.5 in the field
    let mut fractional_vals = [Fr::ZERO; DEPTH];
    fractional_vals[0] = half;
    fractional_vals[1] = half; // 0.5 + 0.5 = 1, but not binary!

    let selectors: [State; DEPTH] = State::witness_array(&cs, &fractional_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Fractional selectors should be rejected by one-hot constraint"
    );

    println!("✓ One-hot: fractional attack (0.5 + 0.5) correctly blocked");
}

#[test]
fn test_one_hot_valid_cases() {
    // Verify that all valid one-hot vectors ARE accepted

    for active_idx in 0..DEPTH {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut vals = [Fr::ZERO; DEPTH];
        vals[active_idx] = Fr::ONE;

        let selectors: [State; DEPTH] = State::witness_array(&cs, &vals).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Valid one-hot with 1 at position {} should be accepted",
            active_idx
        );
    }

    println!("✓ One-hot: all {} valid one-hot vectors accepted", DEPTH);
}

#[test]
fn test_one_hot_three_ones_blocked() {
    // More extreme case: three 1s

    let cs = ConstraintSystem::<Fr>::new_ref();

    let mut malicious_vals = [Fr::ZERO; DEPTH];
    malicious_vals[0] = Fr::ONE;
    malicious_vals[2] = Fr::ONE;
    malicious_vals[4] = Fr::ONE; // THREE positions are 1!

    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Three 1s should be rejected by one-hot constraint"
    );

    println!("✓ One-hot: three 1s correctly blocked");
}

#[test]
fn test_one_hot_all_ones_blocked() {
    // Extreme case: all positions are 1

    let cs = ConstraintSystem::<Fr>::new_ref();

    let malicious_vals = [Fr::ONE; DEPTH];
    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "All 1s should be rejected by one-hot constraint"
    );

    println!("✓ One-hot: all 1s correctly blocked");
}

#[test]
fn test_one_hot_negative_value_blocked() {
    // Try a "negative" value (which wraps in the field)

    let cs = ConstraintSystem::<Fr>::new_ref();

    let mut malicious_vals = [Fr::ZERO; DEPTH];
    malicious_vals[0] = Fr::ZERO - Fr::ONE; // p - 1 in the field

    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Negative (wrapped) value should be rejected"
    );

    println!("✓ One-hot: negative value correctly blocked");
}

#[test]
fn test_one_hot_large_value_blocked() {
    // Try a large value that's not 0 or 1

    let cs = ConstraintSystem::<Fr>::new_ref();

    let mut malicious_vals = [Fr::ZERO; DEPTH];
    malicious_vals[0] = Fr::from(12345u64);

    let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

    enforce_one_hot(&cs, &selectors).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Large non-binary value should be rejected"
    );

    println!("✓ One-hot: large value correctly blocked");
}
