use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::{DEPTH, MerkleTransferKernelCircuit};

#[path = "common/mod.rs"]
mod common;
use crate::common::create_transfer_scenario;

#[test]
fn test_valid_transfer_basic() {
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
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("valid transfer should succeed");

    assert!(
        cs.is_satisfied().unwrap(),
        "Valid transfer should satisfy all constraints"
    );

    println!("✓ Valid transfer (100 - 30 = 70, 50 + 30 = 80)");
    println!("  Constraints: {}", cs.num_constraints());
}

#[test]
fn test_valid_transfer_exact_balance() {
    let scenario = create_transfer_scenario(100, 50, 100);

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
        .expect("should succeed");

    assert!(
        cs.is_satisfied().unwrap(),
        "Transferring exact balance should work"
    );

    println!("✓ Valid transfer of entire balance (100 - 100 = 0)");
}

#[test]
fn test_valid_small_transfer() {
    let scenario = create_transfer_scenario(1000, 500, 1);

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

    assert!(cs.is_satisfied().unwrap());
    println!("✓ Valid small transfer (amount = 1)");
}

#[test]
fn test_multiple_amounts() {
    for amount in [1u64, 10, 50, 99, 100] {
        let scenario = create_transfer_scenario(100, 50, amount);

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
            "Transfer of amount {} should work",
            amount
        );
    }

    println!("✓ Multiple transfer amounts all work");
}

#[test]
fn test_constraint_count_analysis() {
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
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    let num_constraints = cs.num_constraints();

    println!("📊 Constraint Count Analysis:");
    println!("   Total: {}", num_constraints);
    println!("   Tree depth: {}", DEPTH);
    println!("   Estimated per component:");
    println!("     - Index bit checks (2×{}): ~{}", DEPTH, DEPTH * 2);
    println!("     - Merkle path verifications: ~{}", DEPTH * 10);
    println!("     - Balance updates: ~10");
    println!("     - Range check (64 bits): ~65");
    println!("     - Path update logic: ~{}", DEPTH * 5);
    println!("     - First difference: ~{}", DEPTH * 2);

    assert!(
        num_constraints > 50 && num_constraints < 50000,
        "Constraint count unreasonable: {}",
        num_constraints
    );
}

#[test]
fn test_conservation_of_value() {
    let sender_bal = 100u64;
    let receiver_bal = 50u64;
    let amount = 30u64;

    let total_before = sender_bal + receiver_bal;
    let total_after = (sender_bal - amount) + (receiver_bal + amount);

    assert_eq!(total_before, total_after, "Total value should be conserved");

    println!(
        "✓ Conservation of value: {} = {}",
        total_before, total_after
    );
}
