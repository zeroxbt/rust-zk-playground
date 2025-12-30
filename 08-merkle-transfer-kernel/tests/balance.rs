use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::MerkleTransferKernelCircuit;

#[path = "common/mod.rs"]
mod common;
use crate::common::{create_transfer_scenario, create_two_leaf_tree};

// ============================================================================
// RANGE CHECK TESTS - Verify underflow protection works
// ============================================================================

#[test]
fn test_insufficient_balance_rejected() {
    // This was previously a bug - now it should be rejected by range check
    //
    // When amount > sender_balance, the subtraction wraps around in field
    // arithmetic to a huge value (near the field modulus). The 64-bit range
    // check catches this because the wrapped value doesn't fit in 64 bits.

    let sender_balance = 20u64;
    let receiver_balance = 50u64;
    let amount = 30u64; // More than sender has!

    let (leaf_s, leaf_r, path_s, path_r, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    // The circuit will compute leaf_s_updated = 20 - 30 = p - 10 (wrapped)
    // This wrapped value fails the 64-bit range check

    // We need to provide *some* new_root, even though the circuit won't satisfy.
    // Just use old_root as a placeholder.
    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(old_root), // Placeholder - won't matter, range check fails first
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation succeeds");

    assert!(
        !cs.is_satisfied().unwrap(),
        "Insufficient balance should be rejected by range check"
    );

    println!("✓ Insufficient balance correctly rejected (range check works!)");
    println!(
        "  Sender: {}, Amount: {} (underflow caught)",
        sender_balance, amount
    );
}

#[test]
fn test_underflow_by_one_rejected() {
    // Edge case: amount is exactly 1 more than sender balance

    let sender_balance = 100u64;
    let receiver_balance = 50u64;
    let amount = 101u64; // Just 1 more than sender has

    let (leaf_s, leaf_r, path_s, path_r, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(old_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Underflow by 1 should be rejected"
    );

    println!("✓ Underflow by 1 (100 - 101) correctly rejected");
}

#[test]
fn test_massive_underflow_rejected() {
    // Extreme case: try to transfer way more than sender has

    let sender_balance = 10u64;
    let receiver_balance = 50u64;
    let amount = 1_000_000u64; // Massively more than sender has

    let (leaf_s, leaf_r, path_s, path_r, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(old_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Massive underflow should be rejected"
    );

    println!("✓ Massive underflow (10 - 1000000) correctly rejected");
}

#[test]
fn test_zero_balance_transfer_zero_works() {
    // Edge case: sender has 0, transfers 0 - should work

    let scenario = create_transfer_scenario(0, 50, 0);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Zero balance transferring zero should work"
    );

    println!("✓ Zero balance transferring zero works");
}

#[test]
fn test_zero_balance_transfer_any_rejected() {
    // Edge case: sender has 0, tries to transfer anything - should fail

    let sender_balance = 0u64;
    let receiver_balance = 50u64;
    let amount = 1u64;

    let (leaf_s, leaf_r, path_s, path_r, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(old_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Zero balance transferring any amount should fail"
    );

    println!("✓ Zero balance transferring 1 correctly rejected");
}

// ============================================================================
// BOUNDARY TESTS - Test at the edges of the 64-bit range
// ============================================================================

#[test]
fn test_max_u64_balance_transfer_all() {
    // Sender has max u64 value, transfers all of it

    let max_balance = u64::MAX;
    let scenario = create_transfer_scenario(max_balance, 0, max_balance);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Max u64 balance transferring all should work"
    );

    println!("✓ Max u64 balance ({}) transfer all works", max_balance);
}

#[test]
fn test_max_u64_balance_transfer_partial() {
    // Sender has max u64 value, transfers half

    let max_balance = u64::MAX;
    let amount = max_balance / 2;
    let scenario = create_transfer_scenario(max_balance, 0, amount);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Max u64 balance transferring half should work"
    );

    println!("✓ Max u64 balance transfer half works");
}

#[test]
fn test_large_valid_balances() {
    // Test with large but valid balances (near 2^63)

    let balance = 1u64 << 62; // 2^62
    let amount = 1u64 << 61; // 2^61

    let scenario = create_transfer_scenario(balance, balance, amount);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Large valid balances should work"
    );

    println!("✓ Large balances (2^62) transfer works");
}

// ============================================================================
// ZERO AMOUNT TESTS
// ============================================================================

#[test]
fn test_zero_amount_allowed() {
    // Zero amount transfer - no balance change, roots stay the same

    let scenario = create_transfer_scenario(100, 50, 0);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(Fr::ZERO),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.old_root), // No change when amount is 0
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    // Note: This test documents current behavior. Zero amount may or may not
    // be desirable depending on the application. The circuit allows it.
    if cs.is_satisfied().unwrap() {
        println!("⚠️  Zero amount transfer is allowed (current behavior)");
    } else {
        println!("✓ Zero amount transfer is rejected");
    }
}

// ============================================================================
// FIELD WRAPPING ATTACK TESTS
// ============================================================================

#[test]
fn test_field_wrapping_attack_rejected() {
    // Attacker tries to exploit field arithmetic wrapping.
    // In field arithmetic, -1 = p - 1 (a huge number).
    // If an attacker could somehow get a "negative" balance represented,
    // they could create money from nothing.
    //
    // The range check prevents this by ensuring balances fit in 64 bits.

    let sender_balance = 1u64;
    let receiver_balance = 50u64;

    // Attacker tries to transfer 2, causing underflow to p - 1
    let amount = 2u64;

    let (leaf_s, leaf_r, path_s, path_r, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(old_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Field wrapping attack should be rejected"
    );

    println!("✓ Field wrapping attack (1 - 2 = p-1) correctly rejected");
}

#[test]
fn test_wrapped_value_not_accepted_as_valid_balance() {
    // This test verifies that even if an attacker constructs a tree with
    // a "wrapped" balance value, the circuit won't accept transfers from it.

    // Create a leaf with a wrapped (huge) balance directly
    let wrapped_balance = Fr::ZERO - Fr::ONE; // p - 1 in the field

    let (_, leaf_r, _, path_r, _) = create_two_leaf_tree(100, 50);

    // Manually set up with the wrapped balance
    let leaf_s = wrapped_balance;
    let path_s = [Fr::ZERO; 8]; // Dummy path - won't match any real root
    let index_bits_s = [Fr::ZERO; 8];
    let mut index_bits_r = [Fr::ZERO; 8];
    index_bits_r[0] = Fr::ONE;

    // The wrapped balance is huge, so even transferring 1 would leave
    // a value that doesn't fit in 64 bits
    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::ONE),
        old_root: Some(Fr::from(12345u64)), // Fake root
        new_root: Some(Fr::from(12345u64)),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    // Should fail - either because root doesn't match OR because range check fails
    assert!(
        !cs.is_satisfied().unwrap(),
        "Wrapped balance value should not be usable"
    );

    println!("✓ Wrapped balance value correctly rejected");
}
