use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use rand::thread_rng;

use batch_transfers::circuit::BatchTransferCircuit;
use batch_transfers::spec::{AccountProof, MembershipProof, TransferStep};

mod common;
use common::*;

#[test]
fn single_transfer_wrong_nonce_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);

    // Nonce not incremented in expected root_out
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
fn single_transfer_wrong_root_out() {
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
fn single_transfer_insufficient_balance() {
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
fn wrong_paths_and_index_bits_fail() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(1, 500);
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let wrong_path = [Fr::ZERO; DEPTH];
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(TestTree::<DEPTH>::index_to_bits(sender.index), wrong_path),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step_wrong_sender = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

    let circuit_sender = BatchTransferCircuit::<1, DEPTH> {
        steps: [step_wrong_sender],
        root_in,
        root_out: root_in,
    };
    let cs1 = ConstraintSystem::<Fr>::new_ref();
    circuit_sender.generate_constraints(cs1.clone()).unwrap();
    assert!(!cs1.is_satisfied().unwrap());

    let wrong_index_bits = TestTree::<DEPTH>::index_to_bits(1);
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(wrong_index_bits, tree.get_path(sender.index)),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step_wrong_index = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));
    let circuit_index = BatchTransferCircuit::<1, DEPTH> {
        steps: [step_wrong_index],
        root_in,
        root_out: root_in,
    };
    let cs2 = ConstraintSystem::<Fr>::new_ref();
    circuit_index.generate_constraints(cs2.clone()).unwrap();
    assert!(!cs2.is_satisfied().unwrap());

    let mut bad_bits = TestTree::<DEPTH>::index_to_bits(sender.index);
    bad_bits[0] = Fr::from(2u64);
    let sender_proof = AccountProof::new(
        sender.to_leaf_data(),
        MembershipProof::new(bad_bits, tree.get_path(sender.index)),
    );
    let receiver_proof = build_account_proof(&receiver, &tree);
    let step_non_boolean = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));
    let circuit_non_bool = BatchTransferCircuit::<1, DEPTH> {
        steps: [step_non_boolean],
        root_in,
        root_out: root_in,
    };
    let cs3 = ConstraintSystem::<Fr>::new_ref();
    circuit_non_bool.generate_constraints(cs3.clone()).unwrap();
    assert!(!cs3.is_satisfied().unwrap());
}

#[test]
fn receiver_balance_overflow_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let sender = TestAccount::random(0, 100);
    let receiver = TestAccount {
        secret: Fr::rand(&mut thread_rng()),
        balance: Fr::from(u64::MAX - 50),
        salt: Fr::rand(&mut thread_rng()),
        nonce: Fr::ZERO,
        index: 1,
    };
    tree.insert(sender.index, sender.commitment());
    tree.insert(receiver.index, receiver.commitment());
    let root_in = tree.compute_root();

    let step = build_transfer_step(&sender, &receiver, 100, &tree);

    let sender_new = sender.with_balance(0).increment_nonce();
    let receiver_new = TestAccount {
        secret: receiver.secret,
        balance: Fr::from(u64::MAX - 50) + Fr::from(100u64),
        salt: receiver.salt,
        nonce: receiver.nonce,
        index: receiver.index,
    };
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
fn stale_nonce_across_steps_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let alice = TestAccount::random(0, 1000);
    let bob = TestAccount::random(1, 500);
    let carol = TestAccount::random(2, 300);
    tree.insert(alice.index, alice.commitment());
    tree.insert(bob.index, bob.commitment());
    tree.insert(carol.index, carol.commitment());
    let root_in = tree.compute_root();

    let step1 = build_transfer_step(&alice, &bob, 200, &tree);
    let alice_after_1_stale = alice.with_balance(800); // nonce not incremented
    let bob_after_1 = bob.with_balance(700);
    tree.insert(alice.index, alice_after_1_stale.commitment());
    tree.insert(bob.index, bob_after_1.commitment());

    let step2 = build_transfer_step(&alice_after_1_stale, &carol, 300, &tree);

    let alice_after_2_stale = alice_after_1_stale.with_balance(500);
    let carol_after_2 = carol.with_balance(600);
    tree.insert(alice.index, alice_after_2_stale.commitment());
    tree.insert(carol.index, carol_after_2.commitment());
    let root_out = tree.compute_root();

    let circuit = BatchTransferCircuit::<2, DEPTH> {
        steps: [step1, step2],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}
