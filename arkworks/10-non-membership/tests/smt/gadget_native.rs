use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use hash_preimage::sponge::gadget::State;
use rand::{Rng, thread_rng};

use non_membership::smt::{
    gadget::verify_non_membership, native::verify_non_membership as native_verify,
    spec::SmtNonMembershipProofVar, tree::SparseMerkleTree,
};

const TEST_DEPTH: usize = 16;

fn setup_cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

// ============================================================================
// CONSTRAINT SATISFACTION
// ============================================================================

#[test]
fn satisfies_empty_tree() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "constraints should be satisfied for empty tree"
    );
}

#[test]
fn satisfies_absent_nullifier() {
    let cs = setup_cs();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    tree.insert(Fr::from(1u64));
    tree.insert(Fr::from(2u64));
    tree.insert(Fr::from(3u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, absent).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "constraints should be satisfied for absent nullifier"
    );
}

#[test]
fn satisfies_multiple_absent() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..5 {
        tree.insert(Fr::from(i * 100u64));
    }

    for i in 0..5 {
        let cs = setup_cs();
        let absent = Fr::from(i * 100u64 + 50);
        let proof = tree.prove(absent);

        let root = State::witness(&cs, tree.root()).unwrap();
        let nullifier_state = State::witness(&cs, absent).unwrap();
        let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

        verify_non_membership(
            &cs,
            root,
            &SmtNonMembershipProofVar::new(path, nullifier_state),
        )
        .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "constraints should be satisfied for absent nullifier {}",
            i
        );
    }
}

#[test]
fn satisfies_random_absent() {
    let mut rng = thread_rng();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for _ in 0..10 {
        let val = Fr::from(rng.r#gen::<u16>() as u64);
        tree.insert(val);
    }

    for _ in 0..5 {
        let absent = Fr::from(rng.r#gen::<u16>() as u64);
        if !tree.contains(absent) {
            let cs = setup_cs();
            let proof = tree.prove(absent);

            let root = State::witness(&cs, tree.root()).unwrap();
            let nullifier_state = State::witness(&cs, absent).unwrap();
            let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

            verify_non_membership(
                &cs,
                root,
                &SmtNonMembershipProofVar::new(path, nullifier_state),
            )
            .unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "constraints should be satisfied for random absent nullifier"
            );
        }
    }
}

// ============================================================================
// CONSISTENCY WITH NATIVE
// ============================================================================

#[test]
fn consistent_with_native_empty_tree() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);
    let proof = tree.prove(nullifier);
    let root = tree.root();

    let native_result = native_verify(root, nullifier, &proof);

    let cs = setup_cs();
    let root_state = State::witness(&cs, root).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root_state,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();
    let gadget_result = cs.is_satisfied().unwrap();

    assert_eq!(
        native_result, gadget_result,
        "native and gadget should agree"
    );
}

#[test]
fn consistent_with_native_non_empty_tree() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));
    tree.insert(Fr::from(200u64));

    let absent = Fr::from(150u64);
    let proof = tree.prove(absent);
    let root = tree.root();

    let native_result = native_verify(root, absent, &proof);

    let cs = setup_cs();
    let root_state = State::witness(&cs, root).unwrap();
    let nullifier_state = State::witness(&cs, absent).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root_state,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();
    let gadget_result = cs.is_satisfied().unwrap();

    assert_eq!(
        native_result, gadget_result,
        "native and gadget should agree"
    );
    assert!(native_result, "both should pass for absent nullifier");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn nullifier_zero() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::ZERO;

    let proof = tree.prove(nullifier);
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "should work with zero nullifier"
    );
}

#[test]
fn nullifier_one() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::ONE;

    let proof = tree.prove(nullifier);
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    assert!(cs.is_satisfied().unwrap(), "should work with one nullifier");
}

#[test]
fn nullifier_max_for_depth() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from((1u64 << TEST_DEPTH) - 1);

    let proof = tree.prove(nullifier);
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "should work with max nullifier for depth"
    );
}

// ============================================================================
// CONSTRAINT COUNT
// ============================================================================

#[test]
fn constraint_count() {
    let cs = setup_cs();
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = State::witness(&cs, tree.root()).unwrap();
    let nullifier_state = State::witness(&cs, nullifier).unwrap();
    let path: [State; TEST_DEPTH] = State::witness_array(&cs, proof.path()).unwrap();

    verify_non_membership(
        &cs,
        root,
        &SmtNonMembershipProofVar::new(path, nullifier_state),
    )
    .unwrap();

    let num_constraints = cs.num_constraints();
    println!(
        "Non-membership gadget constraints (D={}): {}",
        TEST_DEPTH, num_constraints
    );

    assert!(num_constraints > 0);
    assert!(num_constraints < 50000, "constraint count seems too high");
}
