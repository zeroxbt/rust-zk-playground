use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::{DEPTH, MerkleTransferKernelCircuit};
#[path = "common/mod.rs"]
mod common;
use crate::common::{
    compute_native_root, compute_spine, create_divergence_at_depth, create_two_leaf_tree,
};

#[test]
fn test_divergence_at_depth_0() {
    // First difference at the very first level (immediate divergence)
    let scenario = create_divergence_at_depth(100, 50, 30, 0);

    // Verify divergence is at expected depth
    let first_diff = (0..DEPTH)
        .find(|&i| scenario.index_bits_s[i] != scenario.index_bits_r[i])
        .unwrap();
    assert_eq!(first_diff, 0, "Expected divergence at depth 0");

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
        "Transfer with divergence at depth 0 should succeed"
    );

    println!("✓ Divergence at depth 0 works correctly");
}

#[test]
fn test_divergence_at_depth_3() {
    // First difference at middle of tree
    let divergence_depth = 3;
    assert!(divergence_depth < DEPTH, "Test requires DEPTH > 3");

    let scenario = create_divergence_at_depth(100, 50, 30, divergence_depth);

    // Verify divergence is at expected depth
    let first_diff = (0..DEPTH)
        .find(|&i| scenario.index_bits_s[i] != scenario.index_bits_r[i])
        .unwrap();
    assert_eq!(
        first_diff, divergence_depth,
        "Expected divergence at depth 3"
    );

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
        "Transfer with divergence at depth 3 should succeed"
    );

    println!("✓ Divergence at depth 3 works correctly");
}

#[test]
fn test_divergence_at_depth_minus_2() {
    // First difference near the top of tree (DEPTH - 2)
    let divergence_depth = DEPTH - 2;

    let scenario = create_divergence_at_depth(100, 50, 30, divergence_depth);

    // Verify divergence is at expected depth
    let first_diff = (0..DEPTH)
        .find(|&i| scenario.index_bits_s[i] != scenario.index_bits_r[i])
        .unwrap();
    assert_eq!(
        first_diff, divergence_depth,
        "Expected divergence at DEPTH-2"
    );

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
        "Transfer with divergence at DEPTH-2 should succeed"
    );

    println!(
        "✓ Divergence at depth {} (DEPTH-2) works correctly",
        divergence_depth
    );
}

#[test]
fn test_divergence_at_depth_minus_1() {
    // First difference at the very top of tree (DEPTH - 1)
    // This is the latest possible divergence - paths share almost everything
    let divergence_depth = DEPTH - 1;

    let scenario = create_divergence_at_depth(100, 50, 30, divergence_depth);

    // Verify divergence is at expected depth
    let first_diff = (0..DEPTH)
        .find(|&i| scenario.index_bits_s[i] != scenario.index_bits_r[i])
        .unwrap();
    assert_eq!(
        first_diff, divergence_depth,
        "Expected divergence at DEPTH-1"
    );

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
        "Transfer with divergence at DEPTH-1 should succeed"
    );

    println!(
        "✓ Divergence at depth {} (DEPTH-1) works correctly",
        divergence_depth
    );
}

#[test]
fn test_divergence_depths_comprehensive() {
    // Run transfers for ALL possible divergence depths
    // This provides complete coverage of the spine/patching logic

    for divergence_depth in 0..DEPTH {
        let scenario = create_divergence_at_depth(100, 50, 30, divergence_depth);

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
            "Divergence at depth {} should succeed",
            divergence_depth
        );
    }

    println!("✓ All {} divergence depths work correctly", DEPTH);
}

#[test]
fn test_wrong_divergence_slot_rejected() {
    let sender_balance = 100u64;
    let receiver_balance = 50u64;
    let amount = 30u64;

    let (leaf_s, leaf_r, path_s, path_r_initial, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; DEPTH];
    let mut index_bits_r = [Fr::ZERO; DEPTH];
    index_bits_r[0] = Fr::ONE;

    let leaf_s_updated = Fr::from(sender_balance - amount);
    let leaf_r_updated = Fr::from(receiver_balance + amount);

    let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

    let first_diff_idx = (0..DEPTH)
        .find(|&i| index_bits_s[i] != index_bits_r[i])
        .unwrap();

    // Malicious: patch wrong slot
    let wrong_idx = if first_diff_idx == 0 {
        1
    } else {
        first_diff_idx - 1
    };
    let mut wrong_path_r = path_r_initial;
    wrong_path_r[wrong_idx] = spine[first_diff_idx];

    let malicious_new_root = compute_native_root(leaf_r_updated, &wrong_path_r, &index_bits_r);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r_initial),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(malicious_new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject wrong divergence slot"
    );

    println!("✓ Wrong divergence slot correctly rejected");
}

#[test]
fn test_wrong_divergence_at_various_depths() {
    // For each valid divergence depth, verify that patching the WRONG
    // slot is rejected

    for divergence_depth in 1..DEPTH {
        // Create valid scenario
        let scenario = create_divergence_at_depth(100, 50, 30, divergence_depth);

        // Compute what the circuit would compute
        let leaf_s_updated = scenario.leaf_s - scenario.amount;
        let leaf_r_updated = scenario.leaf_r + scenario.amount;
        let spine = compute_spine(leaf_s_updated, &scenario.path_s, &scenario.index_bits_s);

        // Patch the WRONG slot (one before the correct one)
        let wrong_slot = divergence_depth - 1;
        let mut wrong_path_r = scenario.path_r;
        wrong_path_r[wrong_slot] = spine[divergence_depth]; // Wrong slot!

        let malicious_new_root =
            compute_native_root(leaf_r_updated, &wrong_path_r, &scenario.index_bits_r);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(scenario.leaf_s),
            leaf_r: Some(scenario.leaf_r),
            path_s: Some(scenario.path_s),
            path_r: Some(scenario.path_r),
            index_bits_s: Some(scenario.index_bits_s),
            index_bits_r: Some(scenario.index_bits_r),
            amount: Some(scenario.amount),
            old_root: Some(scenario.old_root),
            new_root: Some(malicious_new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Wrong patch slot at divergence depth {} should be rejected",
            divergence_depth
        );
    }

    println!("✓ Wrong patch slot rejected at all divergence depths");
}

#[test]
fn test_wrong_spine_value_rejected() {
    let sender_balance = 100u64;
    let receiver_balance = 50u64;
    let amount = 30u64;

    let (leaf_s, leaf_r, path_s, path_r_initial, old_root) =
        create_two_leaf_tree(sender_balance, receiver_balance);

    let index_bits_s = [Fr::ZERO; DEPTH];
    let mut index_bits_r = [Fr::ZERO; DEPTH];
    index_bits_r[0] = Fr::ONE;

    let leaf_s_updated = Fr::from(sender_balance - amount);
    let leaf_r_updated = Fr::from(receiver_balance + amount);

    let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

    let first_diff_idx = (0..DEPTH)
        .find(|&i| index_bits_s[i] != index_bits_r[i])
        .unwrap();

    // Malicious: correct slot but wrong value
    let mut wrong_path_r = path_r_initial;
    wrong_path_r[first_diff_idx] = spine[first_diff_idx] + Fr::ONE;

    let malicious_new_root = compute_native_root(leaf_r_updated, &wrong_path_r, &index_bits_r);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(leaf_s),
        leaf_r: Some(leaf_r),
        path_s: Some(path_s),
        path_r: Some(path_r_initial),
        index_bits_s: Some(index_bits_s),
        index_bits_r: Some(index_bits_r),
        amount: Some(Fr::from(amount)),
        old_root: Some(old_root),
        new_root: Some(malicious_new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Should reject wrong spine value"
    );

    println!("✓ Wrong spine value correctly rejected");
}
