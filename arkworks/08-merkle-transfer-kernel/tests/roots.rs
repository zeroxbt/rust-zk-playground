use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::MerkleTransferKernelCircuit;

#[path = "common/mod.rs"]
mod common;
use crate::common::create_transfer_scenario;

#[test]
fn test_wrong_old_root_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(Fr::from(99999u64)), // Wrong!
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation succeeds");

    assert!(!cs.is_satisfied().unwrap(), "Should reject wrong old_root");

    println!("✓ Wrong old_root correctly rejected");
}

#[test]
fn test_wrong_new_root_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(Fr::from(88888u64)), // Wrong!
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation succeeds");

    assert!(!cs.is_satisfied().unwrap(), "Should reject wrong new_root");

    println!("✓ Wrong new_root correctly rejected");
}

#[test]
fn test_swapped_roots_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    // Swap old and new roots
    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.new_root), // Swapped!
        new_root: Some(scenario.old_root), // Swapped!
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject swapped old/new roots"
    );

    println!("✓ Swapped roots correctly rejected");
}

#[test]
fn test_wrong_sender_path_rejected() {
    let mut scenario = create_transfer_scenario(100, 50, 30);

    scenario.path_s[0] = Fr::from(77777u64); // Corrupt path

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
        "Should reject corrupted sender path"
    );

    println!("✓ Wrong sender path correctly rejected");
}

#[test]
fn test_wrong_receiver_path_rejected() {
    let mut scenario = create_transfer_scenario(100, 50, 30);

    scenario.path_r[0] = Fr::from(66666u64); // Corrupt path

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
        "Should reject corrupted receiver path"
    );

    println!("✓ Wrong receiver path correctly rejected");
}

#[test]
fn test_all_path_elements_wrong_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    // Completely wrong paths
    let wrong_path = [Fr::from(11111u64); 8];

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(wrong_path),
        path_r: Some(wrong_path),
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
        "Should reject completely wrong paths"
    );

    println!("✓ Completely wrong paths correctly rejected");
}

#[test]
fn test_zero_roots_rejected() {
    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(Fr::ZERO),
        new_root: Some(Fr::ZERO),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject zero roots (unless tree actually has zero root)"
    );

    println!("✓ Zero roots correctly rejected");
}

#[test]
fn test_old_root_matches_computed_but_new_root_wrong() {
    // Old root is correct, but new root doesn't match the transfer result

    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root), // Correct
        new_root: Some(scenario.old_root), // Wrong - using old root as new root
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject when new_root doesn't match computed result"
    );

    println!("✓ Mismatched new_root correctly rejected");
}
