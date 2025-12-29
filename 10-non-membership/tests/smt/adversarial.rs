use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::thread_rng;

use non_membership::smt::{
    native::verify_non_membership, spec::NonMembershipProof, tree::SparseMerkleTree,
};

const TEST_DEPTH: usize = 16;

#[test]
fn non_membership_fails_for_present_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    tree.insert(nullifier);

    let proof = tree.prove(nullifier);
    let root = tree.root();

    assert!(
        !verify_non_membership(root, nullifier, &proof),
        "non-membership should FAIL for present nullifier"
    );
}

#[test]
fn non_membership_fails_with_wrong_root() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let wrong_root = Fr::from(99999u64);

    assert!(
        !verify_non_membership(wrong_root, nullifier, &proof),
        "verification should fail with wrong root"
    );
}

#[test]
fn non_membership_fails_with_stale_root() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let old_root = tree.root();

    // Insert something, changing the root
    tree.insert(Fr::from(100u64));

    // Proof was valid for old root, not new root
    assert!(verify_non_membership(old_root, nullifier, &proof));
    assert!(
        !verify_non_membership(tree.root(), nullifier, &proof),
        "verification should fail with stale root"
    );
}

#[test]
fn non_membership_fails_with_corrupted_first_sibling() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = tree.root();

    let mut bad_siblings = proof.path();
    bad_siblings[0] = Fr::from(123456u64);
    let bad_proof = NonMembershipProof::new(bad_siblings, nullifier);

    assert!(
        !verify_non_membership(root, nullifier, &bad_proof),
        "verification should fail with corrupted first sibling"
    );
}

#[test]
fn non_membership_fails_with_corrupted_middle_sibling() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = tree.root();

    let mut bad_siblings = proof.path();
    bad_siblings[TEST_DEPTH / 2] = Fr::from(123456u64);
    let bad_proof = NonMembershipProof::new(bad_siblings, nullifier);

    assert!(
        !verify_non_membership(root, nullifier, &bad_proof),
        "verification should fail with corrupted middle sibling"
    );
}

#[test]
fn non_membership_fails_with_corrupted_last_sibling() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = tree.root();

    let mut bad_siblings = proof.path();
    bad_siblings[TEST_DEPTH - 1] = Fr::from(123456u64);
    let bad_proof = NonMembershipProof::new(bad_siblings, nullifier);

    assert!(
        !verify_non_membership(root, nullifier, &bad_proof),
        "verification should fail with corrupted last sibling"
    );
}

#[test]
fn non_membership_fails_with_wrong_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let nullifier1 = Fr::from(0u64);

    tree.insert(Fr::from(1u64));

    let root = tree.root();

    let nullifier2 = Fr::from(3u64);

    let proof = tree.prove(nullifier1);

    assert!(
        !verify_non_membership(root, nullifier2, &proof),
        "verification should fail with mismatched nullifier"
    );
}

#[test]
fn non_membership_fails_with_swapped_siblings() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);
    let root = tree.root();

    let mut bad_siblings = proof.path();
    bad_siblings.swap(0, 1);
    let bad_proof = NonMembershipProof::new(bad_siblings, absent);

    assert!(
        !verify_non_membership(root, absent, &bad_proof),
        "verification should fail with swapped siblings"
    );
}

#[test]
fn non_membership_fails_with_reversed_siblings() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);
    let root = tree.root();

    let mut bad_siblings = proof.path();
    bad_siblings.reverse();
    let bad_proof = NonMembershipProof::new(bad_siblings, absent);

    assert!(
        !verify_non_membership(root, absent, &bad_proof),
        "verification should fail with reversed siblings"
    );
}

#[test]
fn non_membership_fails_with_all_zero_siblings() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let root = tree.root();

    let bad_siblings = [Fr::from(0u64); TEST_DEPTH];
    let bad_proof = NonMembershipProof::new(bad_siblings, absent);

    assert!(
        !verify_non_membership(root, absent, &bad_proof),
        "verification should fail with all-zero siblings after insert"
    );
}

#[test]
fn non_membership_fails_proof_from_different_tree() {
    let mut tree1 = SparseMerkleTree::<TEST_DEPTH>::default();
    let mut tree2 = SparseMerkleTree::<TEST_DEPTH>::default();

    tree1.insert(Fr::from(1u64));
    tree2.insert(Fr::from(2u64));

    let nullifier = Fr::from(999u64);
    let proof_from_tree1 = tree1.prove(nullifier);
    let root_of_tree2 = tree2.root();

    assert!(
        !verify_non_membership(root_of_tree2, nullifier, &proof_from_tree1),
        "verification should fail with proof from different tree"
    );
}

#[test]
fn non_membership_fails_random_siblings() {
    let mut rng = thread_rng();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..10 {
        tree.insert(Fr::from(i as u64));
    }

    let root = tree.root();
    let nullifier = Fr::from(999u64);

    let random_siblings: [Fr; TEST_DEPTH] = std::array::from_fn(|_| Fr::rand(&mut rng));
    let bad_proof = NonMembershipProof::new(random_siblings, nullifier);

    assert!(
        !verify_non_membership(root, nullifier, &bad_proof),
        "verification should fail with random siblings"
    );
}
