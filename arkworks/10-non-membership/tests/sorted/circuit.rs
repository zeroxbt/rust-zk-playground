use std::panic::catch_unwind;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::AdditiveGroup;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::test_rng;
use non_membership::sorted::{
    circuit::SortedNonMembershipCircuit, native::verify_sorted_non_membership as native_verify,
};

const NUM_BITS: usize = 254;

type Circuit = SortedNonMembershipCircuit<NUM_BITS>;

fn setup_circuit() -> Circuit {
    Circuit::new(None, None, None)
}

fn setup() -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
    let mut rng = test_rng();
    let circuit = setup_circuit();
    let pk =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let vk = prepare_verifying_key(&pk.vk);
    (pk, vk)
}

fn prove(pk: &ProvingKey<Bls12_381>, circuit: Circuit) -> Option<ark_groth16::Proof<Bls12_381>> {
    Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, pk, &mut test_rng()).ok()
}

// ============================================================================
// VALID PROOFS
// ============================================================================

#[test]
fn proof_verifies_valid_range() {
    let (pk, vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    assert!(native_verify(nullifier, lower, upper), "native should pass");

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    let proof = prove(&pk, circuit).expect("proof generation should succeed");

    let public_inputs = &[nullifier];
    assert!(
        Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap(),
        "valid proof should verify"
    );
}

#[test]
fn proof_verifies_tight_range() {
    let (pk, vk) = setup();

    let lower = Fr::from(100u64);
    let nullifier = Fr::from(101u64);
    let upper = Fr::from(102u64);

    assert!(native_verify(nullifier, lower, upper), "native should pass");

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    let proof = prove(&pk, circuit).expect("proof generation should succeed");

    let public_inputs = &[nullifier];
    assert!(
        Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap(),
        "tight range proof should verify"
    );
}

#[test]
fn proof_verifies_zero_lower() {
    let (pk, vk) = setup();

    let lower = Fr::ZERO;
    let nullifier = Fr::from(50u64);
    let upper = Fr::from(100u64);

    assert!(native_verify(nullifier, lower, upper), "native should pass");

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    let proof = prove(&pk, circuit).expect("proof generation should succeed");

    let public_inputs = &[nullifier];
    assert!(
        Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap(),
        "zero lower bound proof should verify"
    );
}

#[test]
fn proof_verifies_large_values() {
    let (pk, vk) = setup();

    let lower = Fr::from(1_000_000u64);
    let nullifier = Fr::from(1_000_500u64);
    let upper = Fr::from(1_001_000u64);

    assert!(native_verify(nullifier, lower, upper), "native should pass");

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    let proof = prove(&pk, circuit).expect("proof generation should succeed");

    let public_inputs = &[nullifier];
    assert!(
        Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap(),
        "large values proof should verify"
    );
}

// ============================================================================
// PROOF GENERATION FAILURES
// ============================================================================

#[test]
fn proof_fails_nullifier_equals_lower() {
    let (pk, _vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(10u64);
    let upper = Fr::from(20u64);

    assert!(
        !native_verify(nullifier, lower, upper),
        "native should fail"
    );

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

    let result = catch_unwind(|| prove(&pk, circuit));

    assert!(
        result.is_err(),
        "proof generation should panic when nullifier == lower"
    );
}

#[test]
fn proof_fails_nullifier_equals_upper() {
    let (pk, _vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(20u64);
    let upper = Fr::from(20u64);

    assert!(
        !native_verify(nullifier, lower, upper),
        "native should fail"
    );

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

    let result = catch_unwind(|| prove(&pk, circuit));

    assert!(
        result.is_err(),
        "proof generation should panic when nullifier == upper"
    );
}

#[test]
fn proof_fails_nullifier_below_lower() {
    let (pk, _vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(5u64);
    let upper = Fr::from(20u64);

    assert!(
        !native_verify(nullifier, lower, upper),
        "native should fail"
    );

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

    let result = catch_unwind(|| prove(&pk, circuit));

    assert!(
        result.is_err(),
        "proof generation should panic when nullifier < lower"
    );
}

#[test]
fn proof_fails_nullifier_above_upper() {
    let (pk, _vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(25u64);
    let upper = Fr::from(20u64);

    assert!(
        !native_verify(nullifier, lower, upper),
        "native should fail"
    );

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

    let result = catch_unwind(|| prove(&pk, circuit));

    assert!(
        result.is_err(),
        "proof generation should panic when nullifier > upper"
    );
}

#[test]
fn proof_fails_swapped_bounds() {
    let (pk, _vk) = setup();

    let lower = Fr::from(20u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(10u64);

    assert!(
        !native_verify(nullifier, lower, upper),
        "native should fail"
    );

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

    let result = catch_unwind(|| prove(&pk, circuit));

    assert!(
        result.is_err(),
        "proof generation should panic with swapped bounds"
    );
}

// ============================================================================
// VERIFICATION FAILURES
// ============================================================================

#[test]
fn verification_fails_wrong_public_nullifier() {
    let (pk, vk) = setup();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    let proof = prove(&pk, circuit).expect("proof generation should succeed");

    let wrong_nullifier = Fr::from(16u64);
    let wrong_public_inputs = &[wrong_nullifier];

    assert!(
        !Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap(),
        "verification should fail with wrong public nullifier"
    );
}

// ============================================================================
// CONSTRAINT COUNT
// ============================================================================

#[test]
fn circuit_constraint_count() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let lower = Fr::from(10u64);
    let nullifier = Fr::from(15u64);
    let upper = Fr::from(20u64);

    let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));
    circuit.generate_constraints(cs.clone()).unwrap();

    let num_constraints = cs.num_constraints();
    println!(
        "SortedNonMembershipCircuit constraints (NUM_BITS={}): {}",
        NUM_BITS, num_constraints
    );

    assert!(cs.is_satisfied().unwrap(), "valid circuit should satisfy");
    assert!(num_constraints > 0);
    assert!(num_constraints < 10000, "constraint count seems too high");
}

// ============================================================================
// CONSISTENCY WITH NATIVE
// ============================================================================
#[test]
fn circuit_consistent_with_native() {
    let (pk, vk) = setup();

    let test_cases = vec![
        (Fr::from(10u64), Fr::from(15u64), Fr::from(20u64), true),
        (Fr::from(0u64), Fr::from(1u64), Fr::from(2u64), true),
        (Fr::from(100u64), Fr::from(150u64), Fr::from(200u64), true),
        (Fr::from(10u64), Fr::from(10u64), Fr::from(20u64), false),
        (Fr::from(10u64), Fr::from(20u64), Fr::from(20u64), false),
        (Fr::from(10u64), Fr::from(5u64), Fr::from(20u64), false),
    ];

    for (lower, nullifier, upper, should_pass) in test_cases {
        let native_result = native_verify(nullifier, lower, upper);
        assert_eq!(native_result, should_pass, "native mismatch");

        let circuit = Circuit::new(Some(nullifier), Some(lower), Some(upper));

        if should_pass {
            let proof = prove(&pk, circuit).expect("proof should succeed for valid case");
            let public_inputs = &[nullifier];
            let verified = Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap();
            assert!(verified, "circuit should verify for valid case");
        } else {
            let result = catch_unwind(|| prove(&pk, circuit));
            assert!(result.is_err(), "proof should panic for invalid case");
        }
    }
}
