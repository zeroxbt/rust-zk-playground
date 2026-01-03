use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::test_rng;

use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
use merkle_membership::merkle::native::compute_root as compute_root_native;
use nullifiers::{
    circuit::NullifierCircuit,
    commitment::{native::create_commitment, spec::LeafData},
    nullifier::native::derive_nullifier,
};
use rand::RngCore;

const DEPTH: usize = 16;

fn index_to_bits<const T: usize>(index: usize) -> [bool; T] {
    std::array::from_fn(|i| (index >> i) & 1 == 1)
}

fn bits_to_field_array<const T: usize>(bits: &[bool; T]) -> [Fr; T] {
    std::array::from_fn(|i| {
        if bits[i] {
            Fr::from(1u64)
        } else {
            Fr::from(0u64)
        }
    })
}

struct TestData<const T: usize> {
    secret: Fr,
    balance: Fr,
    salt: Fr,
    nonce: Fr,
    leaf: LeafData,
    index_bits: [Fr; T],
    path: [Fr; T],
    root: Fr,
    nullifier: Fr,
}

fn generate_test_data<const T: usize>(rng: &mut impl RngCore) -> TestData<T> {
    let secret = Fr::rand(rng);
    let balance = Fr::rand(rng);
    let salt = Fr::rand(rng);
    let nonce = Fr::rand(rng);

    let leaf_data = LeafData::new(secret, balance, salt, nonce);
    let leaf = create_commitment(&leaf_data);

    let index = (rng.next_u64() as usize) % (1 << T);
    let index_bits_bool = index_to_bits::<T>(index);
    let index_bits = bits_to_field_array(&index_bits_bool);

    let path: [Fr; T] = std::array::from_fn(|_| Fr::rand(rng));

    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    let root = compute_root_native(&sponge, leaf, &path, &index_bits_bool);

    let nullifier = derive_nullifier(secret, nonce, &index_bits_bool);

    TestData {
        secret,
        balance,
        salt,
        nonce,
        leaf: leaf_data,
        index_bits,
        path,
        root,
        nullifier,
    }
}

#[test]
fn valid_spend_satisfies_constraints() {
    let TestData {
        leaf,
        index_bits,
        path,
        root,
        nullifier,
        ..
    } = generate_test_data::<DEPTH>(&mut test_rng());

    let circuit = NullifierCircuit::<DEPTH>::new(leaf, index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
    println!("Spend circuit constraints: {}", cs.num_constraints());
}

#[test]
fn wrong_root_fails() {
    let mut rng = test_rng();
    let TestData {
        leaf,
        index_bits,
        path,
        root: _,
        nullifier,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let circuit =
        NullifierCircuit::<DEPTH>::new(leaf, index_bits, path, Fr::rand(&mut rng), nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_nullifier_fails() {
    let mut rng = test_rng();
    let TestData {
        leaf,
        index_bits,
        path,
        root,
        nullifier: _,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let circuit = NullifierCircuit::<DEPTH>::new(leaf, index_bits, path, root, Fr::rand(&mut rng));

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_secret_fails() {
    let mut rng = test_rng();
    let TestData {
        balance,
        salt,
        nonce,
        index_bits,
        path,
        root,
        nullifier,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let wrong_leaf = LeafData::new(Fr::rand(&mut rng), balance, salt, nonce);

    let circuit = NullifierCircuit::<DEPTH>::new(wrong_leaf, index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    println!("Constraints: {}", cs.num_constraints());
    println!("Satisfied: {}", cs.is_satisfied().unwrap());
    println!("Which unsatisfied: {:?}", cs.which_is_unsatisfied());

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_path_fails() {
    let mut rng = test_rng();
    let TestData {
        leaf,
        index_bits,
        path,
        root,
        nullifier,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let mut bad_path = path;
    bad_path[0] = Fr::rand(&mut rng);

    let circuit = NullifierCircuit::<DEPTH>::new(leaf, index_bits, bad_path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn non_binary_index_bit_fails() {
    let TestData {
        leaf,
        index_bits,
        path,
        root,
        nullifier,
        ..
    } = generate_test_data::<DEPTH>(&mut test_rng());

    let mut bad_index_bits = index_bits;
    bad_index_bits[0] = Fr::from(2u64); // not binary

    let circuit = NullifierCircuit::<DEPTH>::new(leaf, bad_index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_balance_fails() {
    let mut rng = test_rng();
    let TestData {
        leaf,
        balance: _,
        index_bits,
        path,
        root,
        nullifier,
        nonce,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let circuit = NullifierCircuit::<DEPTH>::new(
        LeafData::new(leaf.secret(), Fr::rand(&mut rng), leaf.salt(), nonce),
        index_bits,
        path,
        root,
        nullifier,
    );

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_salt_fails() {
    let mut rng = test_rng();
    let TestData {
        leaf,
        balance,
        salt: _,
        index_bits,
        path,
        root,
        nullifier,
        nonce,
        ..
    } = generate_test_data::<DEPTH>(&mut rng);

    let circuit = NullifierCircuit::<DEPTH>::new(
        LeafData::new(leaf.secret(), balance, Fr::rand(&mut rng), nonce),
        index_bits,
        path,
        root,
        nullifier,
    );

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn wrong_index_bits_fails() {
    let mut rng = test_rng();
    let data = generate_test_data::<DEPTH>(&mut rng);

    // Flip one bit
    let mut bad_index_bits = data.index_bits;
    let flip_pos = (rng.next_u64() as usize) % DEPTH;
    bad_index_bits[flip_pos] = if bad_index_bits[flip_pos] == Fr::from(1u64) {
        Fr::from(0u64)
    } else {
        Fr::from(1u64)
    };

    let circuit = NullifierCircuit::<DEPTH>::new(
        data.leaf,
        bad_index_bits,
        data.path,
        data.root,
        data.nullifier,
    );

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn same_leaf_produces_same_nullifier() {
    let mut rng = test_rng();
    let data1 = generate_test_data::<DEPTH>(&mut rng);

    // Rebuild with same secret and index
    let index_bits_bool: [bool; DEPTH] =
        std::array::from_fn(|i| data1.index_bits[i] == Fr::from(1u64));
    let nullifier_again = derive_nullifier(data1.secret, data1.nonce, &index_bits_bool);

    assert_eq!(data1.nullifier, nullifier_again);
}

#[test]
fn different_index_produces_different_nullifier() {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let nonce = Fr::rand(&mut rng);

    let index1 = index_to_bits::<DEPTH>(0);
    let index2 = index_to_bits::<DEPTH>(1);

    let nullifier1 = derive_nullifier(secret, nonce, &index1);
    let nullifier2 = derive_nullifier(secret, nonce, &index2);

    assert_ne!(nullifier1, nullifier2);
}

#[test]
fn valid_spend_leftmost_leaf() {
    let mut rng = test_rng();

    let secret = Fr::rand(&mut rng);
    let balance = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let nonce = Fr::rand(&mut rng);

    let leaf_data = LeafData::new(secret, balance, salt, nonce);
    let leaf = create_commitment(&leaf_data);

    let index_bits_bool = [false; DEPTH]; // index 0
    let index_bits = bits_to_field_array(&index_bits_bool);
    let path: [Fr; DEPTH] = std::array::from_fn(|_| Fr::rand(&mut rng));

    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    let root = compute_root_native(&sponge, leaf, &path, &index_bits_bool);
    let nullifier = derive_nullifier(secret, nonce, &index_bits_bool);

    let circuit = NullifierCircuit::<DEPTH>::new(leaf_data, index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn valid_spend_rightmost_leaf() {
    let mut rng = test_rng();

    let secret = Fr::rand(&mut rng);
    let balance = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let nonce = Fr::rand(&mut rng);

    let leaf_data = LeafData::new(secret, balance, salt, nonce);
    let leaf = create_commitment(&leaf_data);

    let index_bits_bool = [true; DEPTH]; // max index
    let index_bits = bits_to_field_array(&index_bits_bool);
    let path: [Fr; DEPTH] = std::array::from_fn(|_| Fr::rand(&mut rng));

    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    let root = compute_root_native(&sponge, leaf, &path, &index_bits_bool);
    let nullifier = derive_nullifier(secret, nonce, &index_bits_bool);

    let circuit = NullifierCircuit::<DEPTH>::new(leaf_data, index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn valid_spend_zero_balance() {
    let mut rng = test_rng();

    let secret = Fr::rand(&mut rng);
    let balance = Fr::from(0u64);
    let salt = Fr::rand(&mut rng);
    let nonce = Fr::rand(&mut rng);

    let leaf_data = LeafData::new(secret, balance, salt, nonce);
    let leaf = create_commitment(&leaf_data);

    let index_bits_bool = index_to_bits::<DEPTH>(42);
    let index_bits = bits_to_field_array(&index_bits_bool);
    let path: [Fr; DEPTH] = std::array::from_fn(|_| Fr::rand(&mut rng));

    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    let root = compute_root_native(&sponge, leaf, &path, &index_bits_bool);
    let nullifier = derive_nullifier(secret, nonce, &index_bits_bool);

    let circuit = NullifierCircuit::<DEPTH>::new(leaf_data, index_bits, path, root, nullifier);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
}
