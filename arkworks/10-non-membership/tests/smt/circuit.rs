use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::AdditiveGroup;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::test_rng;

use non_membership::smt::{circuit::NonMembershipCircuit, tree::SparseMerkleTree};

const TEST_DEPTH: usize = 16;

fn setup(
    circuit: NonMembershipCircuit<TEST_DEPTH>,
) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
    let mut rng = test_rng();
    let pk =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let vk = prepare_verifying_key(&pk.vk);
    (pk, vk)
}

fn prove(
    pk: &ProvingKey<Bls12_381>,
    circuit: NonMembershipCircuit<TEST_DEPTH>,
) -> ark_groth16::Proof<Bls12_381> {
    Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, pk, &mut test_rng()).unwrap()
}

fn setup_circuit() -> NonMembershipCircuit<TEST_DEPTH> {
    NonMembershipCircuit {
        root: None,
        nullifier: None,
        path: None,
    }
}

// ============================================================================
// PROOF GENERATION AND VERIFICATION
// ============================================================================

#[test]
fn proof_verifies_empty_tree() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let public_inputs = &[tree.root()];

    let proof = prove(&pk, prove_circuit);
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
}

#[test]
fn proof_verifies_absent_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(1u64));
    tree.insert(Fr::from(2u64));
    tree.insert(Fr::from(3u64));

    let absent = Fr::from(999u64);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, absent);
    let public_inputs = &[tree.root()];

    let proof = prove(&pk, prove_circuit);
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
}

#[test]
fn proof_verifies_multiple_absent() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    for i in 0..5 {
        tree.insert(Fr::from(i * 100u64));
    }

    let (pk, vk) = setup(setup_circuit());
    let public_inputs = &[tree.root()];

    for i in 0..5 {
        let absent = Fr::from(i * 100u64 + 50);
        let prove_circuit = NonMembershipCircuit::new(&tree, absent);

        let proof = prove(&pk, prove_circuit);
        assert!(
            Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap(),
            "proof should verify for absent nullifier {}",
            i
        );
    }
}

// ============================================================================
// VERIFICATION FAILURES
// ============================================================================

#[test]
fn verification_fails_with_wrong_root() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let wrong_public_inputs = &[Fr::from(99999u64)];

    let proof = prove(&pk, prove_circuit);
    assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
}

#[test]
fn verification_fails_with_stale_root() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let old_root = tree.root();

    let proof = prove(&pk, prove_circuit);

    // Verify with old root works
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, &[old_root]).unwrap());

    // Insert something, changing the root
    tree.insert(Fr::from(100u64));
    let new_root = tree.root();

    // Verify with new root fails
    assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &[new_root]).unwrap());
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn proof_verifies_nullifier_zero() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::ZERO;

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let public_inputs = &[tree.root()];

    let proof = prove(&pk, prove_circuit);
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
}

#[test]
fn proof_verifies_nullifier_max_for_depth() {
    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from((1u64 << TEST_DEPTH) - 1);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let public_inputs = &[tree.root()];

    let proof = prove(&pk, prove_circuit);
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
}

#[test]
fn proof_verifies_after_many_inserts() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    for i in 0..50 {
        tree.insert(Fr::from(i as u64));
    }

    let absent = Fr::from(1000u64);

    let (pk, vk) = setup(setup_circuit());
    let prove_circuit = NonMembershipCircuit::new(&tree, absent);
    let public_inputs = &[tree.root()];

    let proof = prove(&pk, prove_circuit);
    assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
}

// ============================================================================
// SOUNDNESS - WRONG WITNESSES DON'T SATISFY CONSTRAINTS
// ============================================================================

#[test]
fn wrong_witness_present_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    tree.insert(nullifier);

    // Try to create circuit for present nullifier
    let circuit = NonMembershipCircuit::new(&tree, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should not be satisfied for present nullifier"
    );
}

#[test]
fn wrong_witness_corrupted_path() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(100u64));

    let absent = Fr::from(999u64);
    let proof = tree.prove(absent);

    let mut bad_path = *proof.path();
    bad_path[0] = Fr::from(123456u64);

    let circuit = NonMembershipCircuit {
        root: Some(tree.root()),
        nullifier: Some(absent),
        path: Some(bad_path),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should not be satisfied with corrupted path"
    );
}

#[test]
fn wrong_witness_wrong_nullifier() {
    let mut tree = SparseMerkleTree::<TEST_DEPTH>::default();
    tree.insert(Fr::from(1u64));

    let nullifier1 = Fr::from(0u64);
    let nullifier2 = Fr::from(3u64);

    let proof = tree.prove(nullifier1);

    // Use path for nullifier1 but claim nullifier2
    let circuit = NonMembershipCircuit {
        root: Some(tree.root()),
        nullifier: Some(nullifier2),
        path: Some(*proof.path()),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should not be satisfied with wrong nullifier"
    );
}

#[test]
fn wrong_witness_proof_from_different_tree() {
    let mut tree1 = SparseMerkleTree::<TEST_DEPTH>::default();
    let mut tree2 = SparseMerkleTree::<TEST_DEPTH>::default();

    tree1.insert(Fr::from(1u64));
    tree2.insert(Fr::from(2u64));

    let nullifier = Fr::from(999u64);
    let proof_from_tree1 = tree1.prove(nullifier);

    // Use root from tree2 but path from tree1
    let circuit = NonMembershipCircuit {
        root: Some(tree2.root()),
        nullifier: Some(nullifier),
        path: Some(*proof_from_tree1.path()),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "constraints should not be satisfied with proof from different tree"
    );
}

// ============================================================================
// METRICS
// ============================================================================

#[test]
fn print_circuit_metrics() {
    use std::time::Instant;

    let tree = SparseMerkleTree::<TEST_DEPTH>::default();
    let nullifier = Fr::from(42u64);

    // Constraint count
    let circuit = NonMembershipCircuit::new(&tree, nullifier);
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    // Setup timing
    let setup_start = Instant::now();
    let (pk, vk) = setup(setup_circuit());
    let setup_time = setup_start.elapsed();

    // Prove timing
    let prove_circuit = NonMembershipCircuit::new(&tree, nullifier);
    let prove_start = Instant::now();
    let proof = prove(&pk, prove_circuit);
    let prove_time = prove_start.elapsed();

    // Verify timing
    let public_inputs = &[tree.root()];
    let verify_start = Instant::now();
    let _ = Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap();
    let verify_time = verify_start.elapsed();

    println!(
        "\n=== Non-membership Circuit Metrics (D={}) ===",
        TEST_DEPTH
    );
    println!("Constraints: {}", cs.num_constraints());
    println!("Setup time:  {:?}", setup_time);
    println!("Prove time:  {:?}", prove_time);
    println!("Verify time: {:?}", verify_time);
}
