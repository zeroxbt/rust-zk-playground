use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use batch_transfers::{
    circuit::BatchTransferCircuit,
    spec::{AccountProof, MembershipProof, TransferStep},
};
use rand::thread_rng;

mod common;
use common::*;

#[test]
fn single_transfer_valid() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);

    let sender_new = sender.with_balance(900).increment_nonce();
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_nonce_updates() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);

    let sender_new = sender.with_balance(900).increment_nonce();
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_full_balance() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(2, 1000);
    let receiver = TestAccount::random(3, 0);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 1000, &tree);

    let sender_new = sender.with_balance(0).increment_nonce();
    let receiver_new = receiver.with_balance(1000);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_zero_amount_nonce_still_changes() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(4, 500);
    let receiver = TestAccount::random(5, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 0, &tree);

    let sender_new = sender.increment_nonce();
    let receiver_new = receiver.with_balance(500);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_wrong_root_out_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);
    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out: root_in,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_wrong_nonce_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);
    // Balance updated but nonce not incremented for expected root
    let sender_new = sender.with_balance(900);
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_insufficient_balance_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 50);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);

    let sender_new = TestAccount {
        secret: sender.secret,
        balance: Fr::from(50u64) - Fr::from(100u64),
        salt: sender.salt,
        nonce: sender.nonce + Fr::ONE,
        index: sender.index,
    };
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_wrong_paths_fail() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    // Wrong sender path
    let wrong_path = [Fr::ZERO; DEPTH];
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(TestTree::<DEPTH>::index_to_bits(sender.index), wrong_path),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

    let sender_new = sender.with_balance(900).increment_nonce();
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_wrong_receiver_path_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let wrong_path = [Fr::ZERO; DEPTH];
    let sender_proof = build_account_proof(&sender, &tree);
    let receiver_proof = AccountProof::new(
        receiver.to_leaf_data(),
        MembershipProof::new(TestTree::<DEPTH>::index_to_bits(receiver.index), wrong_path),
    );
    let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

    let sender_new = sender.with_balance(900).increment_nonce();
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_same_index_rejected() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount {
        secret: Fr::rand(&mut thread_rng()),
        balance: Fr::from(500u64),
        salt: Fr::rand(&mut thread_rng()),
        nonce: Fr::ZERO,
        index: 0,
    };
    tree.insert(sender.index, sender.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);
    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out: root_in,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_wrong_index_bits() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let wrong_index_bits = TestTree::<DEPTH>::index_to_bits(1);
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(wrong_index_bits, tree.get_path(sender.index)),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

    let sender_new = sender.with_balance(900).increment_nonce();
    let receiver_new = receiver.with_balance(600);
    tree.insert(sender.index, sender_new.commitment());
    tree.insert(receiver.index, receiver_new.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn single_transfer_non_boolean_bit_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let mut bad_index_bits = TestTree::<DEPTH>::index_to_bits(sender.index);
    bad_index_bits[0] = Fr::from(2u64);
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(bad_index_bits, tree.get_path(sender.index)),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

    let circuit = BatchTransferCircuit::<1, DEPTH> {
        steps: [step],
        root_in,
        root_out: root_in,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}
