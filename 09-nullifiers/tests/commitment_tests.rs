use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_std::test_rng;
use nullifiers::commitment::{native::create_commitment, spec::LeafData};
use rand::seq::SliceRandom;

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
