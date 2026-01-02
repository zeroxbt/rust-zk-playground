use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use hash_preimage::sponge::gadget::State;

use non_membership::smt::{
    gadget::verify_non_membership, spec::SmtNonMembershipProofVar, tree::SparseMerkleTree,
};

const TEST_DEPTH: usize = 16;

fn setup_cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

// ============================================================================
// ADVERSARIAL - SHOULD NOT SATISFY
// ============================================================================

#[test]
fn fails_for_present_nullifier() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    tree.insert(nullifier);

    let proof = tree.prove(nullifier);
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, nullifier).unwrap();

    verify_non_membership(&cs, root, &SmtNonMembershipProofVar::new(path, nullifier)).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied for present nullifier"
    );
}

#[test]
fn fails_with_wrong_root() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();
    let wrong_root = State::witness(&cs, Fr::from(99999u64)).unwrap();
    let nullifier = State::witness(&cs, nullifier).unwrap();

    verify_non_membership(
        &cs,
        wrong_root,
        &SmtNonMembershipProofVar::new(path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with wrong root"
    );
}

#[test]
fn fails_with_wrong_nullifier() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    tree.insert(Fr::from(1u64));

    let nullifier1 = Fr::from(0u64);
    let nullifier2 = Fr::from(3u64);

    let proof = tree.prove(nullifier1);
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, nullifier2).unwrap();

    verify_non_membership(&cs, root, &SmtNonMembershipProofVar::new(path, nullifier)).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with mismatched nullifier"
    );
}

#[test]
fn fails_with_corrupted_first_sibling() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let mut bad_path = *proof.path();
    bad_path[0] = Fr::from(123456u64);
    let bad_path: [State; TEST_DEPTH] = State::witness_array(&cs, &bad_path).unwrap();

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, absent).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(bad_path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with corrupted sibling"
    );
}

#[test]
fn fails_with_corrupted_middle_sibling() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let mut bad_path = *proof.path();
    bad_path[TEST_DEPTH / 2] = Fr::from(123456u64);
    let bad_path: [State; TEST_DEPTH] = State::witness_array(&cs, &bad_path).unwrap();

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, absent).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(bad_path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with corrupted middle sibling"
    );
}

#[test]
fn fails_with_corrupted_last_sibling() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let mut bad_path = *proof.path();
    bad_path[TEST_DEPTH - 1] = Fr::from(123456u64);
    let bad_path: [State; TEST_DEPTH] = State::witness_array(&cs, &bad_path).unwrap();

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, absent).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(bad_path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with corrupted last sibling"
    );
}

#[test]
fn fails_with_swapped_siblings() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let mut bad_path = *proof.path();
    bad_path.swap(0, 1);
    let bad_path: [State; TEST_DEPTH] = State::witness_array(&cs, &bad_path).unwrap();

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, absent).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(bad_path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with swapped siblings"
    );
}

#[test]
fn fails_with_all_zero_siblings() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let bad_path: [State; TEST_DEPTH] = State::witness_array(&cs, &[Fr::ZERO; TEST_DEPTH]).unwrap();

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier = State::witness(&cs, absent).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(bad_path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with all-zero siblings"
    );
}

#[test]
fn fails_with_proof_from_different_tree() {
    let cs = setup_cs();
    let mut tree1 = SparseMerkleTree::<TEST_DEPTH>::default();
    let mut tree2 = SparseMerkleTree::<TEST_DEPTH>::default();

    tree1.insert(Fr::from(1u64));
    tree2.insert(Fr::from(2u64));

    let nullifier = Fr::from(999u64);
    let proof_from_tree1 = tree1.prove(nullifier);

    let root_of_tree2 = State::witness(&cs, tree2.root()).unwrap();
    let nullifier = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof_from_tree1.path()).unwrap();

    verify_non_membership(
        &cs,
        root_of_tree2,
        &SmtNonMembershipProofVar::new(path, nullifier),
    )
    .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with proof from different tree"
    );
}

#[test]
fn fails_with_stale_root() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let old_root = tree.root();

    tree.insert(Fr::from(100u64));

    let new_root_state = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();

    // Proof was valid for old root
    let cs_old = setup_cs();
    let old_root_state2 = State::witness(&cs_old, old_root).unwrap();
    let nullifier_state2 = State::witness(&cs_old, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs_old, proof.path()).unwrap();

    verify_non_membership(
        &cs_old,
        old_root_state2,
        &SmtNonMembershipProofVar::new(path, nullifier_state2),
    )
    .unwrap();
    assert!(
        cs_old.is_satisfied().unwrap(),
        "should satisfy for old root"
    );

    // But not for new root
    verify_non_membership(
        &cs,
        new_root_state,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should NOT be satisfied with stale root"
    );
}
