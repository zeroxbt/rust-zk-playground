use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use nullifiers::nullifier::native::{bits_to_field, derive_nullifier};
use rand::RngCore;

const DEPTH: usize = 16;

#[test]
fn bits_to_field_correctness() {
    // 5 = 0b101 = [1, 0, 1] in little-endian
    let bits = [true, false, true];
    let result: Fr = bits_to_field(&bits);
    assert_eq!(result, Fr::from(5u64));

    // 0 = [0, 0, 0]
    let bits = [false, false, false];
    let result: Fr = bits_to_field(&bits);
    assert_eq!(result, Fr::from(0u64));

    // 7 = 0b111 = [1, 1, 1]
    let bits = [true, true, true];
    let result: Fr = bits_to_field(&bits);
    assert_eq!(result, Fr::from(7u64));
}

fn random_index_bits<const T: usize>(rng: &mut impl RngCore) -> [bool; T] {
    [0; T].map(|_| (rng.next_u32() & 1) == 1)
}

#[test]
fn determinism() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let index_bits = random_index_bits::<DEPTH>(&mut rng);

        assert_eq!(
            derive_nullifier(secret, &index_bits),
            derive_nullifier(secret, &index_bits)
        );
    }
}

#[test]
fn sensitivity_to_secret() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret1 = Fr::rand(&mut rng);
        let secret2 = Fr::rand(&mut rng);
        let index_bits = random_index_bits::<DEPTH>(&mut rng);

        assert_ne!(
            derive_nullifier(secret1, &index_bits),
            derive_nullifier(secret2, &index_bits)
        );
    }
}

#[test]
fn sensitivity_to_index() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let index_bits1 = random_index_bits::<DEPTH>(&mut rng);
        let mut index_bits2 = index_bits1;

        let flip_pos = (rng.next_u32() as usize) % DEPTH;
        index_bits2[flip_pos] = !index_bits2[flip_pos];

        assert_ne!(
            derive_nullifier(secret, &index_bits1),
            derive_nullifier(secret, &index_bits2)
        );
    }
}

#[test]
fn same_secret_different_index_produces_different_nullifiers() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let index_bits1 = random_index_bits::<DEPTH>(&mut rng);
        let index_bits2 = random_index_bits::<DEPTH>(&mut rng);

        if index_bits1 == index_bits2 {
            continue;
        }

        assert_ne!(
            derive_nullifier(secret, &index_bits1),
            derive_nullifier(secret, &index_bits2)
        );
    }
}

#[test]
fn different_secret_same_index_produces_different_nullifiers() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret1 = Fr::rand(&mut rng);
        let secret2 = Fr::rand(&mut rng);
        let index_bits = random_index_bits::<DEPTH>(&mut rng);

        if secret1 == secret2 {
            continue;
        }

        assert_ne!(
            derive_nullifier(secret1, &index_bits),
            derive_nullifier(secret2, &index_bits)
        );
    }
}

#[test]
fn non_zero_output() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let index_bits = random_index_bits::<DEPTH>(&mut rng);

        assert_ne!(derive_nullifier(secret, &index_bits), Fr::from(0u64));
    }
}

#[test]
fn all_zero_index_works() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let index_bits = [false; DEPTH];

    let nullifier = derive_nullifier(secret, &index_bits);
    assert_ne!(nullifier, Fr::from(0u64));
}

#[test]
fn all_one_index_works() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let index_bits = [true; DEPTH];

    let nullifier = derive_nullifier(secret, &index_bits);
    assert_ne!(nullifier, Fr::from(0u64));
}
