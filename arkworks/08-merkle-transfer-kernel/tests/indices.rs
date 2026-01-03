use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::MerkleTransferKernelCircuit;

#[path = "common/mod.rs"]
mod common;
use crate::common::create_transfer_scenario;

#[test]
fn test_same_sender_receiver_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_s), // SAME as sender!
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation succeeds");

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject when sender = receiver"
    );

    println!("✓ Same sender/receiver correctly rejected");
}

#[test]
fn test_invalid_index_bit_value_2_rejected() {
    let mut scenario = create_transfer_scenario(100, 50, 30);

    scenario.index_bits_s[0] = Fr::from(2u64); // Invalid bit!

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
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation succeeds");

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject invalid bit value"
    );

    println!("✓ Invalid index bit (value=2) correctly rejected");
}

#[test]
fn test_invalid_index_bit_negative_rejected() {
    let mut scenario = create_transfer_scenario(100, 50, 30);

    // Try a "negative" value (which wraps in the field)
    scenario.index_bits_s[0] = Fr::ZERO - Fr::ONE; // p - 1

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
        !cs.is_satisfied().unwrap(),
        "Should reject negative (wrapped) bit value"
    );

    println!("✓ Invalid index bit (negative/wrapped) correctly rejected");
}

#[test]
fn test_invalid_receiver_index_bit_rejected() {
    let mut scenario = create_transfer_scenario(100, 50, 30);

    scenario.index_bits_r[1] = Fr::from(5u64); // Invalid bit in receiver

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
        !cs.is_satisfied().unwrap(),
        "Should reject invalid receiver bit value"
    );

    println!("✓ Invalid receiver index bit correctly rejected");
}

#[test]
fn test_all_zero_indices_for_both_rejected() {
    // Both sender and receiver at index 0 - same index, should be rejected

    let scenario = create_transfer_scenario(100, 50, 30);

    let all_zeros = [Fr::ZERO; 8];

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(all_zeros),
        index_bits_r: Some(all_zeros), // Same as sender!
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Both indices all-zero (same) should be rejected"
    );

    println!("✓ Both indices all-zero correctly rejected (same sender/receiver)");
}

#[test]
fn test_all_one_indices_for_both_rejected() {
    // Both sender and receiver at max index - same index

    let scenario = create_transfer_scenario(100, 50, 30);

    let all_ones = [Fr::ONE; 8];

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(all_ones),
        index_bits_r: Some(all_ones), // Same as sender!
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Both indices all-one (same) should be rejected"
    );

    println!("✓ Both indices all-one correctly rejected (same sender/receiver)");
}

#[test]
fn test_fractional_index_bit_rejected() {
    use ark_ff::Field;

    let mut scenario = create_transfer_scenario(100, 50, 30);

    // Try 0.5 as a bit value
    let half = Fr::from(2u64).inverse().unwrap();
    scenario.index_bits_s[0] = half;

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
        !cs.is_satisfied().unwrap(),
        "Fractional index bit should be rejected"
    );

    println!("✓ Fractional index bit (0.5) correctly rejected");
}
