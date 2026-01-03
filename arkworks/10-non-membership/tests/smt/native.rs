use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::thread_rng;

use non_membership::smt::{native::verify_non_membership, tree::SparseMerkleTree};

const TEST_DEPTH: usize = 16;

#[test]
fn non_membership_empty_tree() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let root = tree.root();

    assert!(
        verify_non_membership(root, nullifier, &proof),
        "non-membership should verify in empty tree"
    );
}

#[test]
fn non_membership_absent_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    tree.insert(Fr::from(1u64));
    tree.insert(Fr::from(2u64));
    tree.insert(Fr::from(3u64));

    let absent = Fr::from(999u64);
    assert!(!tree.contains(absent));

    let proof = tree.prove(absent);
    let root = tree.root();

    assert!(
        verify_non_membership(root, absent, &proof),
        "non-membership should verify for absent nullifier"
    );
}

#[test]
fn non_membership_multiple_absent() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..5 {
        tree.insert(Fr::from(i * 100u64));
    }

    let root = tree.root();

    for i in 0..5 {
        let absent = Fr::from(i * 100u64 + 50);
        let proof = tree.prove(absent);

        assert!(
            verify_non_membership(root, absent, &proof),
            "non-membership should verify for absent nullifier {}",
            i
        );
    }
}

#[test]
fn non_membership_random_absent() {
    let mut rng = thread_rng();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for _ in 0..10 {
        tree.insert(Fr::rand(&mut rng));
    }

    let root = tree.root();

    for _ in 0..10 {
        let absent = Fr::rand(&mut rng);
        if !tree.contains(absent) {
            let proof = tree.prove(absent);
            assert!(
                verify_non_membership(root, absent, &proof),
                "non-membership should verify for random absent nullifier"
            );
        }
    }
}

#[test]
fn non_membership_after_many_inserts() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    for i in 0..100 {
        tree.insert(Fr::from(i as u64));
    }

    let root = tree.root();
    let absent = Fr::from(1000u64);
    let proof = tree.prove(absent);

    assert!(verify_non_membership(root, absent, &proof));
}
