use ::nullifiers::nullifier::gadget;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_relations::r1cs::ConstraintSystem;
use ark_std::test_rng;
use hash_preimage::sponge::gadget::State;
use nullifiers::nullifier::native;
use rand::RngCore;

const DEPTH: usize = 16;

#[test]
fn bits_to_field_correctness() {
    let bits = [true, false, true];
    let result: Fr = native::bits_to_field(&bits);
    assert_eq!(result, Fr::from(5u64));

    let bits = [false, false, false];
    let result: Fr = native::bits_to_field(&bits);
    assert_eq!(result, Fr::from(0u64));

    let bits = [true, true, true];
    let result: Fr = native::bits_to_field(&bits);
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
            native::derive_nullifier(secret, &index_bits),
            native::derive_nullifier(secret, &index_bits)
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
            native::derive_nullifier(secret1, &index_bits),
            native::derive_nullifier(secret2, &index_bits)
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
            native::derive_nullifier(secret, &index_bits1),
            native::derive_nullifier(secret, &index_bits2)
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
            native::derive_nullifier(secret, &index_bits1),
            native::derive_nullifier(secret, &index_bits2)
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
            native::derive_nullifier(secret1, &index_bits),
            native::derive_nullifier(secret2, &index_bits)
        );
    }
}

#[test]
fn non_zero_output() {
    let mut rng = test_rng();

    for _ in 0..50 {
        let secret = Fr::rand(&mut rng);
        let index_bits = random_index_bits::<DEPTH>(&mut rng);

        assert_ne!(
            native::derive_nullifier(secret, &index_bits),
            Fr::from(0u64)
        );
    }
}

#[test]
fn all_zero_index_works() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let index_bits = [false; DEPTH];

    let nullifier = native::derive_nullifier(secret, &index_bits);
    assert_ne!(nullifier, Fr::from(0u64));
}

#[test]
fn all_one_index_works() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let index_bits = [true; DEPTH];

    let nullifier = native::derive_nullifier(secret, &index_bits);
    assert_ne!(nullifier, Fr::from(0u64));
}

#[test]
fn bits_to_field_consistency_with_native() {
    let mut rng = test_rng();

    for _ in 0..20 {
        let bits = random_index_bits::<DEPTH>(&mut rng);
        let native_result = native::bits_to_field(&bits);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let bit_states: [State; DEPTH] = std::array::from_fn(|i| {
            State::witness(
                &cs,
                if bits[i] {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                },
            )
            .unwrap()
        });

        let gadget_result = gadget::bits_to_field(&cs, &bit_states).unwrap();

        assert_eq!(gadget_result.val(), native_result);
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
fn derive_nullifier_consistency_with_native() {
    let mut rng = test_rng();

    for _ in 0..10 {
        let secret = Fr::rand(&mut rng);
        let bits = random_index_bits::<DEPTH>(&mut rng);

        let native_result = native::derive_nullifier(secret, &bits);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let secret_state = State::witness(&cs, secret).unwrap();
        let bit_states: [State; DEPTH] = std::array::from_fn(|i| {
            State::witness(
                &cs,
                if bits[i] {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                },
            )
            .unwrap()
        });

        let gadget_result = gadget::derive_nullifier(&cs, secret_state, &bit_states).unwrap();

        assert_eq!(gadget_result.val(), native_result);
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
fn derive_nullifier_constraints_satisfied() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let bits = random_index_bits::<DEPTH>(&mut rng);

    let cs = ConstraintSystem::<Fr>::new_ref();
    let secret_state = State::witness(&cs, secret).unwrap();
    let bit_states: [State; DEPTH] = std::array::from_fn(|i| {
        State::witness(
            &cs,
            if bits[i] {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            },
        )
        .unwrap()
    });

    let _nullifier = gadget::derive_nullifier(&cs, secret_state, &bit_states).unwrap();

    assert!(cs.is_satisfied().unwrap());
    println!("Nullifier circuit constraints: {}", cs.num_constraints());
}

#[test]
fn bits_to_field_all_zeros() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let bit_states: [State; DEPTH] =
        std::array::from_fn(|_| State::witness(&cs, Fr::from(0u64)).unwrap());

    let result = gadget::bits_to_field(&cs, &bit_states).unwrap();

    assert_eq!(result.val(), Fr::from(0u64));
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn bits_to_field_all_ones() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let bit_states: [State; DEPTH] =
        std::array::from_fn(|_| State::witness(&cs, Fr::from(1u64)).unwrap());

    let result = gadget::bits_to_field(&cs, &bit_states).unwrap();

    let expected = Fr::from((1u64 << DEPTH) - 1);
    assert_eq!(result.val(), expected);
    assert!(cs.is_satisfied().unwrap());
}
