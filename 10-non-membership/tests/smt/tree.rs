use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, UniformRand};
use rand::thread_rng;

use non_membership::smt::{spec::index_bits, tree::SparseMerkleTree};

const TEST_DEPTH: usize = 16;

#[test]
fn empty_tree_has_consistent_root() {
    let tree1 = SparseMerkleTree::<TEST_DEPTH>::default();
    let tree2 = SparseMerkleTree::<TEST_DEPTH>::default();

    assert_eq!(
        tree1.root(),
        tree2.root(),
        "empty trees should have same root"
    );
}

#[test]
fn empty_tree_contains_nothing() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(12345u64);

    assert!(!tree.contains(nullifier));
}

#[test]
fn insert_single_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let empty_root = tree.root();
    let nullifier = Fr::from(42u64);

    tree.insert(nullifier);

    assert!(
        tree.contains(nullifier),
        "inserted nullifier should be contained"
    );
    assert_ne!(tree.root(), empty_root, "root should change after insert");
}

#[test]
fn insert_does_not_affect_other_nullifiers() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier1 = Fr::from(100u64);
    let nullifier2 = Fr::from(200u64);

    tree.insert(nullifier1);

    assert!(tree.contains(nullifier1));
    assert!(
        !tree.contains(nullifier2),
        "uninserted nullifier should not be contained"
    );
}

#[test]
fn insert_multiple_nullifiers() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifiers: Vec<Fr> = (0..10).map(|i| Fr::from(i * 1000u64)).collect();

    for n in &nullifiers {
        tree.insert(*n);
    }

    for n in &nullifiers {
        assert!(
            tree.contains(*n),
            "all inserted nullifiers should be contained"
        );
    }
}

#[test]
fn root_changes_with_each_insert() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let mut roots = vec![tree.root()];

    for i in 0..5 {
        tree.insert(Fr::from(i as u64));
        roots.push(tree.root());
    }

    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "roots at step {} and {} should differ",
                i, j
            );
        }
    }
}

#[test]
fn insert_order_does_not_affect_final_root() {
    let nullifiers = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];

    let mut tree1 = SparseMerkleTree::<TEST_DEPTH>::default();
    for n in &nullifiers {
        tree1.insert(*n);
    }

    let mut tree2 = SparseMerkleTree::<TEST_DEPTH>::default();
    for n in nullifiers.iter().rev() {
        tree2.insert(*n);
    }

    assert_eq!(
        tree1.root(),
        tree2.root(),
        "insertion order should not affect root"
    );
}

#[test]
fn duplicate_insert_is_idempotent() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(999u64);

    tree.insert(nullifier);
    let root_after_first = tree.root();

    tree.insert(nullifier);
    let root_after_second = tree.root();

    assert_eq!(
        root_after_first, root_after_second,
        "duplicate insert should not change root"
    );
}

#[test]
fn proof_has_correct_number_of_siblings() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);

    assert_eq!(proof.path().len(), TEST_DEPTH);
}

#[test]
fn empty_tree_proof_siblings_are_defaults() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let proof = tree.prove(nullifier);
    let siblings = proof.path();

    assert_eq!(
        siblings[0],
        Fr::ZERO,
        "first sibling should be default leaf"
    );
}

#[test]
fn index_bits_deterministic() {
    let nullifier = Fr::from(12345u64);

    let bits1 = index_bits::<TEST_DEPTH>(nullifier);
    let bits2 = index_bits::<TEST_DEPTH>(nullifier);

    assert_eq!(bits1, bits2);
}

#[test]
fn index_bits_different_for_different_nullifiers() {
    let n1 = Fr::from(1u64);
    let n2 = Fr::from(2u64);

    let bits1 = index_bits::<TEST_DEPTH>(n1);
    let bits2 = index_bits::<TEST_DEPTH>(n2);

    assert_ne!(bits1, bits2);
}

#[test]
fn index_bits_zero() {
    let bits = index_bits::<TEST_DEPTH>(Fr::ZERO);

    assert!(bits.iter().all(|&b| !b), "zero should have all false bits");
}

#[test]
fn random_nullifiers() {
    let mut rng = thread_rng();
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();

    let nullifiers: Vec<Fr> = (0..20).map(|_| Fr::rand(&mut rng)).collect();

    for n in &nullifiers {
        tree.insert(*n);
    }

    for n in &nullifiers {
        assert!(tree.contains(*n));
    }
}
