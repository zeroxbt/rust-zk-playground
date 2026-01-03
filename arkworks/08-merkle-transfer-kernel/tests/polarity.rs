use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use merkle_transfer_kernel::circuit::MerkleTransferKernelCircuit;

#[path = "common/mod.rs"]
mod common;
use crate::common::create_transfer_scenario;

#[test]
fn test_polarity_single_bit_flip_rejected() {
    // Create a valid transfer, then flip one index bit without updating paths
    // This should be rejected because the Merkle path computation will be wrong

    let mut scenario = create_transfer_scenario(100, 50, 30);

    // Flip just one bit in sender's index (breaks left/right ordering)
    // Find a bit that's currently 0 and flip it to 1 (or vice versa)
    let flip_idx = 0;
    scenario.index_bits_s[flip_idx] = if scenario.index_bits_s[flip_idx] == Fr::ZERO {
        Fr::ONE
    } else {
        Fr::ZERO
    };

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
        "Single bit flip in sender index should be rejected (polarity check)"
    );

    println!("✓ Polarity: single bit flip in sender index correctly rejected");
}

#[test]
fn test_polarity_invert_all_sender_bits_rejected() {
    // Invert ALL bits in sender's index without updating anything else
    // This simulates a complete polarity inversion

    let scenario = create_transfer_scenario(100, 50, 30);

    // Invert all sender bits
    let inverted_index_bits_s: [Fr; 8] = scenario
        .index_bits_s
        .iter()
        .map(|&b| if b == Fr::ZERO { Fr::ONE } else { Fr::ZERO })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(inverted_index_bits_s),
        index_bits_r: Some(scenario.index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Inverting all sender bits should be rejected (polarity check)"
    );

    println!("✓ Polarity: all bits inverted correctly rejected");
}

#[test]
fn test_polarity_swap_sender_receiver_indices_rejected() {
    // Swap sender and receiver indices (but not leaves/paths)
    // This tests that index bits are correctly bound to their leaves

    let scenario = create_transfer_scenario(100, 50, 30);

    // Swap the indices (but keep leaves in original position)
    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_r), // Swapped!
        index_bits_r: Some(scenario.index_bits_s), // Swapped!
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Swapping sender/receiver indices should be rejected"
    );

    println!("✓ Polarity: swapped indices correctly rejected");
}

#[test]
fn test_polarity_receiver_bit_flip_rejected() {
    // Flip one bit in receiver's index without updating paths

    let mut scenario = create_transfer_scenario(100, 50, 30);

    // Flip a bit in receiver's index (choose one that won't make it equal to sender)
    let flip_idx = 1; // Flip second bit
    scenario.index_bits_r[flip_idx] = if scenario.index_bits_r[flip_idx] == Fr::ZERO {
        Fr::ONE
    } else {
        Fr::ZERO
    };

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
        "Bit flip in receiver index should be rejected"
    );

    println!("✓ Polarity: receiver bit flip correctly rejected");
}

#[test]
fn test_polarity_invert_all_receiver_bits_rejected() {
    // Invert all receiver bits

    let scenario = create_transfer_scenario(100, 50, 30);

    let inverted_index_bits_r: [Fr; 8] = scenario
        .index_bits_r
        .iter()
        .map(|&b| if b == Fr::ZERO { Fr::ONE } else { Fr::ZERO })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_s),
        path_r: Some(scenario.path_r),
        index_bits_s: Some(scenario.index_bits_s),
        index_bits_r: Some(inverted_index_bits_r),
        amount: Some(scenario.amount),
        old_root: Some(scenario.old_root),
        new_root: Some(scenario.new_root),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "Inverting all receiver bits should be rejected"
    );

    println!("✓ Polarity: all receiver bits inverted correctly rejected");
}

#[test]
fn test_polarity_swap_paths_rejected() {
    // Swap sender and receiver paths (but keep indices correct)

    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_s),
        leaf_r: Some(scenario.leaf_r),
        path_s: Some(scenario.path_r), // Swapped!
        path_r: Some(scenario.path_s), // Swapped!
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
        "Swapping paths should be rejected"
    );

    println!("✓ Polarity: swapped paths correctly rejected");
}

#[test]
fn test_polarity_swap_leaves_rejected() {
    // Swap sender and receiver leaves (but keep paths/indices correct)

    let scenario = create_transfer_scenario(100, 50, 30);

    let circuit = MerkleTransferKernelCircuit {
        leaf_s: Some(scenario.leaf_r), // Swapped!
        leaf_r: Some(scenario.leaf_s), // Swapped!
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
        "Swapping leaves should be rejected"
    );

    println!("✓ Polarity: swapped leaves correctly rejected");
}

#[test]
fn test_polarity_flip_multiple_bits_rejected() {
    // Flip multiple (but not all) bits in sender index

    let mut scenario = create_transfer_scenario(100, 50, 30);

    // Flip bits at positions 0, 2, 4
    for i in [0, 2, 4] {
        scenario.index_bits_s[i] = if scenario.index_bits_s[i] == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        };
    }

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
        "Multiple bit flips should be rejected"
    );

    println!("✓ Polarity: multiple bit flips correctly rejected");
}
