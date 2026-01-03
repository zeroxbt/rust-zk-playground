use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use batch_transfers::circuit::BatchTransferCircuit;

mod common;
use common::*;

#[test]
fn two_independent_transfers() {
    let mut tree = TestTree::<DEPTH>::default();
    let alice = TestAccount::random(0, 1000);
    let bob = TestAccount::random(1, 500);
    let carol = TestAccount::random(2, 800);
    let dave = TestAccount::random(3, 200);
    tree.insert(alice.index, alice.commitment());
    tree.insert(bob.index, bob.commitment());
    tree.insert(carol.index, carol.commitment());
    tree.insert(dave.index, dave.commitment());
    let root_in = tree.compute_root();

    let step1 = build_transfer_step(&alice, &bob, 100, &tree);
    let alice_new = alice.with_balance(900).increment_nonce();
    let bob_new = bob.with_balance(600);
    tree.insert(alice.index, alice_new.commitment());
    tree.insert(bob.index, bob_new.commitment());

    let step2 = build_transfer_step(&carol, &dave, 300, &tree);
    let carol_new = carol.with_balance(500).increment_nonce();
    let dave_new = dave.with_balance(500);
    tree.insert(carol.index, carol_new.commitment());
    tree.insert(dave.index, dave_new.commitment());

    let root_out = tree.compute_root();
    let circuit = BatchTransferCircuit::<2, DEPTH> {
        steps: [step1, step2],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn chained_transfers() {
    let mut tree = TestTree::<DEPTH>::default();
    let alice = TestAccount::random(0, 1000);
    let bob = TestAccount::random(1, 500);
    let carol = TestAccount::random(2, 200);
    tree.insert(alice.index, alice.commitment());
    tree.insert(bob.index, bob.commitment());
    tree.insert(carol.index, carol.commitment());
    let root_in = tree.compute_root();

    let step1 = build_transfer_step(&alice, &bob, 300, &tree);
    let alice_after_1 = alice.with_balance(700).increment_nonce();
    let bob_after_1 = bob.with_balance(800);
    tree.insert(alice.index, alice_after_1.commitment());
    tree.insert(bob.index, bob_after_1.commitment());

    let step2 = build_transfer_step(&bob_after_1, &carol, 400, &tree);
    let bob_after_2 = bob_after_1.with_balance(400).increment_nonce();
    let carol_after_2 = carol.with_balance(600);
    tree.insert(bob.index, bob_after_2.commitment());
    tree.insert(carol.index, carol_after_2.commitment());

    let root_out = tree.compute_root();
    let circuit = BatchTransferCircuit::<2, DEPTH> {
        steps: [step1, step2],
        root_in,
        root_out,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn stale_balance_in_chain_fails() {
    let mut tree = TestTree::<DEPTH>::default();
    let alice = TestAccount::random(0, 1000);
    let bob = TestAccount::random(1, 100);
    let carol = TestAccount::random(2, 200);
    tree.insert(alice.index, alice.commitment());
    tree.insert(bob.index, bob.commitment());
    tree.insert(carol.index, carol.commitment());
    let root_in = tree.compute_root();

    let step1 = build_transfer_step(&alice, &bob, 500, &tree);
    let alice_after_1 = alice.with_balance(500);
    let bob_after_1 = bob.with_balance(600);
    tree.insert(alice.index, alice_after_1.commitment());
    tree.insert(bob.index, bob_after_1.commitment());

    let step2 = build_transfer_step(&bob, &carol, 400, &tree); // stale bob witness
    let bob_after_2 = bob.with_balance(200).increment_nonce();
    let carol_after_2 = carol.with_balance(600);
    tree.insert(bob.index, bob_after_2.commitment());
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

#[test]
fn constraint_count_scaling_linear() {
    let constraints_1 = {
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
        cs.num_constraints()
    };

    let constraints_2 = {
        let mut tree = TestTree::<DEPTH>::default();
        let a1 = TestAccount::random(0, 1000);
        let a2 = TestAccount::random(1, 500);
        let a3 = TestAccount::random(2, 800);
        let a4 = TestAccount::random(3, 200);
        tree.insert(a1.index, a1.commitment());
        tree.insert(a2.index, a2.commitment());
        tree.insert(a3.index, a3.commitment());
        tree.insert(a4.index, a4.commitment());
        let root_in = tree.compute_root();

        let step1 = build_transfer_step(&a1, &a2, 100, &tree);
        let a1_new = a1.with_balance(900).increment_nonce();
        let a2_new = a2.with_balance(600);
        tree.insert(a1.index, a1_new.commitment());
        tree.insert(a2.index, a2_new.commitment());

        let step2 = build_transfer_step(&a3, &a4, 100, &tree);
        let a3_new = a3.with_balance(700).increment_nonce();
        let a4_new = a4.with_balance(300);
        tree.insert(a3.index, a3_new.commitment());
        tree.insert(a4.index, a4_new.commitment());
        let root_out = tree.compute_root();

        let circuit = BatchTransferCircuit::<2, DEPTH> {
            steps: [step1, step2],
            root_in,
            root_out,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.num_constraints()
    };

    let constraints_3 = {
        let mut tree = TestTree::<DEPTH>::default();
        let accounts: Vec<TestAccount> = (0..6).map(|i| TestAccount::random(i, 1000)).collect();
        for a in &accounts {
            tree.insert(a.index, a.commitment());
        }
        let root_in = tree.compute_root();

        let step1 = build_transfer_step(&accounts[0], &accounts[1], 100, &tree);
        let a0_new = accounts[0].with_balance(900).increment_nonce();
        let a1_new = accounts[1].with_balance(1100);
        tree.insert(accounts[0].index, a0_new.commitment());
        tree.insert(accounts[1].index, a1_new.commitment());

        let step2 = build_transfer_step(&accounts[2], &accounts[3], 100, &tree);
        let a2_new = accounts[2].with_balance(900).increment_nonce();
        let a3_new = accounts[3].with_balance(1100);
        tree.insert(accounts[2].index, a2_new.commitment());
        tree.insert(accounts[3].index, a3_new.commitment());

        let step3 = build_transfer_step(&accounts[4], &accounts[5], 100, &tree);
        let a4_new = accounts[4].with_balance(900).increment_nonce();
        let a5_new = accounts[5].with_balance(1100);
        tree.insert(accounts[4].index, a4_new.commitment());
        tree.insert(accounts[5].index, a5_new.commitment());
        let root_out = tree.compute_root();

        let circuit = BatchTransferCircuit::<3, DEPTH> {
            steps: [step1, step2, step3],
            root_in,
            root_out,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.num_constraints()
    };

    let per_transfer_1_to_2 = constraints_2 - constraints_1;
    let per_transfer_2_to_3 = constraints_3 - constraints_2;
    let diff = (per_transfer_1_to_2 as i64 - per_transfer_2_to_3 as i64).abs();
    let avg = (per_transfer_1_to_2 + per_transfer_2_to_3) / 2;
    assert!(diff < (avg as i64 / 20));
}

#[test]
fn edge_indices_work() {
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

    let max_index = (1 << DEPTH) - 1;
    let sender = TestAccount::random(0, 1000);
    let receiver = TestAccount::random(max_index, 500);
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
