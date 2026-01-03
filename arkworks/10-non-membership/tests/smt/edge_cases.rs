use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};

use non_membership::smt::{native::verify_non_membership, tree::SparseMerkleTree};

const TEST_DEPTH: usize = 16;

#[test]
fn nullifier_zero() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::ZERO;

    // Before insert: non-membership should pass
    let proof_before = tree.prove(nullifier);
    let root_before = tree.root();
    assert!(verify_non_membership(root_before, nullifier, &proof_before));

    // After insert: non-membership should fail
    tree.insert(nullifier);
    assert!(tree.contains(nullifier));

    let proof_after = tree.prove(nullifier);
    let root_after = tree.root();
    assert!(!verify_non_membership(root_after, nullifier, &proof_after));
}

#[test]
fn nullifier_one() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::ONE;

    let proof_before = tree.prove(nullifier);
    let root_before = tree.root();
    assert!(verify_non_membership(root_before, nullifier, &proof_before));

    tree.insert(nullifier);
    assert!(tree.contains(nullifier));

    let proof_after = tree.prove(nullifier);
    let root_after = tree.root();
    assert!(!verify_non_membership(root_after, nullifier, &proof_after));
}

#[test]
fn nullifier_minus_one() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = -Fr::ONE; // p - 1, largest field element

    tree.insert(nullifier);
    assert!(tree.contains(nullifier));

    let proof = tree.prove(nullifier);
    assert!(!verify_non_membership(tree.root(), nullifier, &proof));
}

#[test]
fn two_nullifiers_differ_only_in_first_bit() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let n1 = Fr::from(0b0u64); // bit 0 = 0
    let n2 = Fr::from(0b1u64); // bit 0 = 1

    tree.insert(n1);

    assert!(tree.contains(n1));
    assert!(!tree.contains(n2));

    let proof = tree.prove(n2);
    assert!(verify_non_membership(tree.root(), n2, &proof));
}

#[test]
fn two_nullifiers_differ_only_in_last_bit() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let n1 = Fr::from(0u64);
    let n2 = Fr::from(1u64 << (TEST_DEPTH - 1));

    tree.insert(n1);

    assert!(tree.contains(n1));
    assert!(!tree.contains(n2));

    let proof = tree.prove(n2);
    assert!(verify_non_membership(tree.root(), n2, &proof));
}

#[test]
fn two_nullifiers_share_all_but_one_bit() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    // All bits set except bit 0
    let n1 = Fr::from(((1u64 << TEST_DEPTH) - 1) & !1u64);
    // All bits set
    let n2 = Fr::from((1u64 << TEST_DEPTH) - 1);

    tree.insert(n1);
    tree.insert(n2);

    assert!(tree.contains(n1));
    assert!(tree.contains(n2));
}

#[test]
fn insert_all_single_bit_nullifiers() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..TEST_DEPTH {
        let nullifier = Fr::from(1u64 << i);
        tree.insert(nullifier);
    }

    for i in 0..TEST_DEPTH {
        let nullifier = Fr::from(1u64 << i);
        assert!(tree.contains(nullifier), "should contain 2^{}", i);
    }

    // Zero should not be contained
    assert!(!tree.contains(Fr::ZERO));
    let proof = tree.prove(Fr::ZERO);
    assert!(verify_non_membership(tree.root(), Fr::ZERO, &proof));
}

#[test]
fn dense_insertion_low_indices() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    // Insert 0, 1, 2, ..., 63 (dense at low end)
    for i in 0..64 {
        tree.insert(Fr::from(i as u64));
    }

    for i in 0..64 {
        assert!(tree.contains(Fr::from(i as u64)));
    }

    let absent = Fr::from(64u64);
    let proof = tree.prove(absent);
    assert!(verify_non_membership(tree.root(), absent, &proof));
}

#[test]
fn sparse_insertion_powers_of_two() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..TEST_DEPTH {
        tree.insert(Fr::from(1u64 << i));
    }

    // Check something in between isn't contained
    let absent = Fr::from(3u64); // 2^0 + 2^1, but we only inserted 2^0 and 2^1 separately
    // Wait, 3 is not a power of 2, so it shouldn't be there
    assert!(!tree.contains(absent));

    let proof = tree.prove(absent);
    assert!(verify_non_membership(tree.root(), absent, &proof));
}

#[test]
fn alternating_bit_patterns() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let pattern_0101 = Fr::from(0b0101010101010101u64);
    let pattern_1010 = Fr::from(0b1010101010101010u64);

    tree.insert(pattern_0101);

    assert!(tree.contains(pattern_0101));
    assert!(!tree.contains(pattern_1010));

    let proof = tree.prove(pattern_1010);
    assert!(verify_non_membership(tree.root(), pattern_1010, &proof));
}

#[test]
fn max_value_for_depth() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let max_index = Fr::from((1u64 << TEST_DEPTH) - 1); // all D bits set

    tree.insert(max_index);
    assert!(tree.contains(max_index));

    let proof = tree.prove(max_index);
    assert!(!verify_non_membership(tree.root(), max_index, &proof));
}

#[test]
fn siblings_at_boundaries() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    // Insert 0 and max
    let min_val = Fr::ZERO;
    let max_val = Fr::from((1u64 << TEST_DEPTH) - 1);

    tree.insert(min_val);
    tree.insert(max_val);

    // Something in the middle should have non-membership provable
    let mid = Fr::from(1u64 << (TEST_DEPTH / 2));
    if !tree.contains(mid) {
        let proof = tree.prove(mid);
        assert!(verify_non_membership(tree.root(), mid, &proof));
    }
}

#[test]
fn consecutive_nullifiers() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    tree.insert(Fr::from(100u64));
    tree.insert(Fr::from(101u64));
    tree.insert(Fr::from(102u64));

    assert!(tree.contains(Fr::from(100u64)));
    assert!(tree.contains(Fr::from(101u64)));
    assert!(tree.contains(Fr::from(102u64)));

    assert!(!tree.contains(Fr::from(99u64)));
    assert!(!tree.contains(Fr::from(103u64)));

    let proof_99 = tree.prove(Fr::from(99u64));
    let proof_103 = tree.prove(Fr::from(103u64));

    assert!(verify_non_membership(
        tree.root(),
        Fr::from(99u64),
        &proof_99
    ));
    assert!(verify_non_membership(
        tree.root(),
        Fr::from(103u64),
        &proof_103
    ));
}
