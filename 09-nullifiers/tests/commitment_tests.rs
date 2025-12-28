use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, UniformRand};
use ark_std::test_rng;
use hash_preimage::sponge::gadget::State;
use nullifiers::commitment::spec::LeafState;
use nullifiers::commitment::{native::create_commitment, spec::LeafData};
use rand::seq::SliceRandom;

// ============================================
// Native tests
// ============================================

#[test]
fn determinism() {
    let mut rng = test_rng();
    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let balance = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);
        let leaf = LeafData::new(secret, balance, salt);

        assert_eq!(create_commitment(&leaf), create_commitment(&leaf.clone()));
    }
}

#[test]
fn sensitivity() {
    let mut rng = test_rng();
    for _ in 0..50 {
        let mut deltas = [Fr::rand(&mut rng), Fr::ZERO, Fr::ZERO];
        deltas.shuffle(&mut rng);

        let secret = Fr::rand(&mut rng);
        let balance = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);

        let secret2 = secret + deltas[0];
        let balance2 = balance + deltas[1];
        let salt2 = salt + deltas[2];

        let leaf = LeafData::new(secret, balance, salt);
        let leaf2 = LeafData::new(secret2, balance2, salt2);

        assert_ne!(create_commitment(&leaf), create_commitment(&leaf2));
    }
}

#[test]
fn non_zero_output() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let balance = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);
        let leaf = LeafData::new(secret, balance, salt);

        assert_ne!(create_commitment(&leaf), Fr::ZERO);
    }
}

// ============================================
// Gadget tests
// ============================================

use ark_relations::r1cs::ConstraintSystem;
use nullifiers::commitment::gadget::create_commitment as create_commitment_gadget;
use nullifiers::commitment::native::create_commitment as create_commitment_native;

#[test]
fn gadget_consistency_with_native() {
    let mut rng = test_rng();

    for _ in 0..10 {
        let secret = Fr::rand(&mut rng);
        let balance = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);
        let leaf = LeafData::new(secret, balance, salt);

        let native_result = create_commitment_native(&leaf);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let gadget_result = create_commitment_gadget(
            &cs,
            &LeafState::new(
                State::witness(&cs, leaf.secret()).unwrap(),
                State::witness(&cs, leaf.balance()).unwrap(),
                State::witness(&cs, leaf.salt()).unwrap(),
            ),
        )
        .unwrap();

        assert_eq!(gadget_result.val(), native_result);
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
fn gadget_constraints_satisfied() {
    let mut rng = test_rng();
    let leaf = LeafData::new(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));

    let cs = ConstraintSystem::<Fr>::new_ref();
    let _commitment = create_commitment_gadget(
        &cs,
        &LeafState::new(
            State::witness(&cs, leaf.secret()).unwrap(),
            State::witness(&cs, leaf.balance()).unwrap(),
            State::witness(&cs, leaf.salt()).unwrap(),
        ),
    )
    .unwrap();

    assert!(cs.is_satisfied().unwrap());
    println!("Commitment circuit constraints: {}", cs.num_constraints());
}

#[test]
fn gadget_zero_balance() {
    let mut rng = test_rng();
    let leaf = LeafData::new(Fr::rand(&mut rng), Fr::ZERO, Fr::rand(&mut rng));

    let cs = ConstraintSystem::<Fr>::new_ref();
    let gadget_result = create_commitment_gadget(
        &cs,
        &LeafState::new(
            State::witness(&cs, leaf.secret()).unwrap(),
            State::witness(&cs, leaf.balance()).unwrap(),
            State::witness(&cs, leaf.salt()).unwrap(),
        ),
    )
    .unwrap();
    let native_result = create_commitment_native(&leaf);

    assert_eq!(gadget_result.val(), native_result);
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn gadget_all_zero_inputs() {
    let leaf = LeafData::new(Fr::ZERO, Fr::ZERO, Fr::ZERO);

    let cs = ConstraintSystem::<Fr>::new_ref();
    let gadget_result = create_commitment_gadget(
        &cs,
        &LeafState::new(
            State::witness(&cs, leaf.secret()).unwrap(),
            State::witness(&cs, leaf.balance()).unwrap(),
            State::witness(&cs, leaf.salt()).unwrap(),
        ),
    )
    .unwrap();
    let native_result = create_commitment_native(&leaf);

    assert_eq!(gadget_result.val(), native_result);
    assert!(cs.is_satisfied().unwrap());
}
