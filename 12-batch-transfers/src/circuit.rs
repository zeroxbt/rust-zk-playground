use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Variable,
};
use hash_preimage::sponge::gadget::{SpongeGadget, State};
use merkle_transfer_kernel::gadget::{
    compute_root_with_spine, enforce_bit_array, enforce_one_hot, first_difference_selectors,
    range_check, select_from_array, update_one_slot,
};
use nullifiers::commitment::{gadget::create_commitment, spec::LeafState};

use crate::spec::{AccountProofVar, MembershipProofVar, TransferStep, TransferStepVar};

pub struct BatchTransferCircuit<const N: usize, const D: usize> {
    steps: [TransferStep<D>; N],
    root_in: Fr,
    root_out: Fr,
}

impl<const N: usize, const D: usize> ConstraintSynthesizer<Fr> for BatchTransferCircuit<N, D> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let mut tx_vars = Vec::<TransferStepVar<D>>::with_capacity(N);
        for tx in self.steps {
            let sender = AccountProofVar::<D>::new(
                LeafState::new(
                    State::witness(&cs, tx.sender().account().secret())?,
                    State::witness(&cs, tx.sender().account().balance())?,
                    State::witness(&cs, tx.sender().account().salt())?,
                ),
                MembershipProofVar::new(
                    State::witness_array(&cs, tx.sender().membership().index_bits())?,
                    State::witness_array(&cs, tx.sender().membership().path())?,
                ),
            );

            let receiver = AccountProofVar::<D>::new(
                LeafState::new(
                    State::witness(&cs, tx.receiver().account().secret())?,
                    State::witness(&cs, tx.receiver().account().balance())?,
                    State::witness(&cs, tx.receiver().account().salt())?,
                ),
                MembershipProofVar::new(
                    State::witness_array(&cs, tx.receiver().membership().index_bits())?,
                    State::witness_array(&cs, tx.receiver().membership().path())?,
                ),
            );

            let tx_var = TransferStepVar::new(sender, receiver, State::witness(&cs, tx.amount())?);

            range_check::<64>(&cs, tx_var.amount())?;

            enforce_bit_array(&cs, tx_var.sender().membership().index_bits())?;
            enforce_bit_array(&cs, tx_var.receiver().membership().index_bits())?;

            tx_vars.push(tx_var);
        }
        let mut root_in = State::input(&cs, self.root_in)?;
        let root_out = State::input(&cs, self.root_out)?;

        for tx_var in tx_vars.iter_mut() {
            root_in = transfer(&cs, tx_var, root_in)?;
        }

        cs.enforce_constraint(
            LinearCombination::from(root_in.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(root_out.var()),
        )?;
        Ok(())
    }
}

fn transfer<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    tx_var: &mut TransferStepVar<D>,
    root_in: State,
) -> ark_relations::r1cs::Result<State> {
    let sponge = SpongeGadget::default();

    let mut sender_commitment = create_commitment(cs, tx_var.sender().account())?;
    let (mut computed_root, _) = compute_root_with_spine(
        cs,
        &sponge,
        sender_commitment,
        tx_var.sender().membership().path(),
        tx_var.sender().membership().index_bits(),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(computed_root.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(root_in.var()),
    )?;
    let mut receiver_commitment = create_commitment(cs, tx_var.receiver().account())?;
    (computed_root, _) = compute_root_with_spine(
        cs,
        &sponge,
        receiver_commitment,
        tx_var.receiver().membership().path(),
        tx_var.receiver().membership().index_bits(),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(computed_root.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(root_in.var()),
    )?;

    let sender_balance_new = State::witness(
        cs,
        tx_var.sender().account().balance().val() - tx_var.amount().val(),
    )?;
    range_check::<64>(cs, sender_balance_new)?;
    cs.enforce_constraint(
        LinearCombination::from(sender_balance_new.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(tx_var.sender().account().balance().var())
            + (-Fr::ONE, tx_var.amount().var()),
    )?;

    tx_var.sender_mut().set_balance(sender_balance_new);
    sender_commitment = create_commitment(cs, tx_var.sender().account())?;
    let (computed_root_sender, spine) = compute_root_with_spine(
        cs,
        &sponge,
        sender_commitment,
        tx_var.sender().membership().path(),
        tx_var.sender().membership().index_bits(),
    )?;

    let (selectors, found) = first_difference_selectors(
        cs,
        tx_var.sender().membership().index_bits(),
        tx_var.receiver().membership().index_bits(),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(found.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(Variable::One),
    )?;
    enforce_one_hot(cs, &selectors)?;
    let new_val = select_from_array(cs, &selectors, &spine)?;
    let receiver_path = *tx_var.receiver().membership().path();
    tx_var
        .receiver_mut()
        .set_path(update_one_slot(cs, &selectors, &receiver_path, new_val)?);

    let (computed_root_receiver, _) = compute_root_with_spine(
        cs,
        &sponge,
        receiver_commitment,
        tx_var.receiver().membership().path(),
        tx_var.receiver().membership().index_bits(),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(computed_root_receiver.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(computed_root_sender.var()),
    )?;

    let receiver_balance_new = State::witness(
        cs,
        tx_var.receiver().account().balance().val() + tx_var.amount().val(),
    )?;
    range_check::<64>(cs, receiver_balance_new)?;
    cs.enforce_constraint(
        LinearCombination::from(receiver_balance_new.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(tx_var.receiver().account().balance().var())
            + (Fr::ONE, tx_var.amount().var()),
    )?;
    tx_var.receiver_mut().set_balance(receiver_balance_new);
    receiver_commitment = create_commitment(cs, tx_var.receiver().account())?;

    (computed_root, _) = compute_root_with_spine(
        cs,
        &sponge,
        receiver_commitment,
        tx_var.receiver().membership().path(),
        tx_var.receiver().membership().index_bits(),
    )?;

    Ok(computed_root)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use rand::thread_rng;

    use hash_preimage::poseidon::native::PoseidonPermutation;
    use hash_preimage::sponge::native::SpongeNative;
    use merkle_membership::merkle::spec::MERKLE_NODE_DST;
    use nullifiers::commitment::native::create_commitment;
    use nullifiers::commitment::spec::LeafData;

    use crate::circuit::BatchTransferCircuit;
    use crate::spec::{AccountProof, MembershipProof, TransferStep};

    const DEPTH: usize = 4;

    // ============================================================
    // Test Tree Infrastructure
    // ============================================================

    /// A simple sparse Merkle tree for test setup
    struct TestTree<const D: usize> {
        leaves: Vec<(usize, Fr)>, // (index, commitment)
        empty_leaf: Fr,
    }

    impl<const D: usize> TestTree<D> {
        fn new() -> Self {
            Self {
                leaves: Vec::new(),
                empty_leaf: Fr::ZERO,
            }
        }

        fn insert(&mut self, index: usize, commitment: Fr) {
            // Remove if exists, then add
            self.leaves.retain(|(i, _)| *i != index);
            self.leaves.push((index, commitment));
        }

        fn get_leaf(&self, index: usize) -> Fr {
            self.leaves
                .iter()
                .find(|(i, _)| *i == index)
                .map(|(_, c)| *c)
                .unwrap_or(self.empty_leaf)
        }

        fn index_to_bits(index: usize) -> [Fr; D] {
            let mut bits = [Fr::ZERO; D];
            for (i, b) in bits.iter_mut().enumerate().take(D) {
                if (index >> i) & 1 == 1 {
                    *b = Fr::ONE;
                }
            }
            bits
        }

        fn compute_root(&self) -> Fr {
            self.compute_node(0, D)
        }

        fn compute_node(&self, node_index: usize, level: usize) -> Fr {
            if level == 0 {
                return self.get_leaf(node_index);
            }

            let left = self.compute_node(node_index * 2, level - 1);
            let right = self.compute_node(node_index * 2 + 1, level - 1);
            hash_pair(left, right)
        }

        fn get_path(&self, index: usize) -> [Fr; D] {
            let mut path = [Fr::ZERO; D];
            let mut current_index = index;

            for (level, p) in path.iter_mut().enumerate().take(D) {
                let sibling_index = current_index ^ 1;
                *p = self.compute_node_at_level(sibling_index, level);
                current_index >>= 1;
            }

            path
        }

        fn compute_node_at_level(&self, node_index: usize, level: usize) -> Fr {
            if level == 0 {
                return self.get_leaf(node_index);
            }

            let left = self.compute_node_at_level(node_index * 2, level - 1);
            let right = self.compute_node_at_level(node_index * 2 + 1, level - 1);
            hash_pair(left, right)
        }
    }

    fn hash_pair(left: Fr, right: Fr) -> Fr {
        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
        sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST))
    }

    // ============================================================
    // Test Account Helpers
    // ============================================================

    struct TestAccount {
        secret: Fr,
        balance: Fr,
        salt: Fr,
        index: usize,
    }

    impl TestAccount {
        fn random(index: usize, balance: u64) -> Self {
            let mut rng = thread_rng();
            Self {
                secret: Fr::rand(&mut rng),
                balance: Fr::from(balance),
                salt: Fr::rand(&mut rng),
                index,
            }
        }

        fn commitment(&self) -> Fr {
            create_commitment(&self.to_leaf_data())
        }

        fn to_leaf_data(&self) -> LeafData {
            LeafData::new(self.secret, self.balance, self.salt)
        }

        fn with_balance(&self, new_balance: u64) -> Self {
            Self {
                secret: self.secret,
                balance: Fr::from(new_balance),
                salt: self.salt,
                index: self.index,
            }
        }
    }

    fn build_account_proof<const D: usize>(
        account: &TestAccount,
        tree: &TestTree<D>,
    ) -> AccountProof<D> {
        AccountProof::new(
            account.to_leaf_data(),
            MembershipProof::new(
                TestTree::<D>::index_to_bits(account.index),
                tree.get_path(account.index),
            ),
        )
    }

    fn build_transfer_step<const D: usize>(
        sender: &TestAccount,
        receiver: &TestAccount,
        amount: u64,
        tree: &TestTree<D>,
    ) -> TransferStep<D> {
        TransferStep::new(
            build_account_proof(sender, tree),
            build_account_proof(receiver, tree),
            Fr::from(amount),
        )
    }

    // ============================================================
    // Single Transfer Tests (N=1)
    // ============================================================

    #[test]
    fn test_single_transfer_valid() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64;
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // Update tree to compute expected root_out
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

        assert!(
            cs.is_satisfied().unwrap(),
            "Valid single transfer should satisfy constraints"
        );
        println!("Single transfer constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_single_transfer_full_balance() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(2, 1000);
        let receiver = TestAccount::random(3, 0);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 1000u64; // Full balance
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        let sender_new = sender.with_balance(0);
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

        assert!(
            cs.is_satisfied().unwrap(),
            "Full balance transfer should work"
        );
    }

    #[test]
    fn test_single_transfer_zero_amount() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(4, 500);
        let receiver = TestAccount::random(5, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 0u64;
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // Balances unchanged, but commitments might still change if we recreate them
        // Actually with zero transfer, the tree state is identical
        let root_out = root_in; // No change

        let circuit = BatchTransferCircuit::<1, DEPTH> {
            steps: [step],
            root_in,
            root_out,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Zero amount transfer should work"
        );
    }

    // ============================================================
    // Adversarial Single Transfer Tests
    // ============================================================

    #[test]
    fn test_single_transfer_wrong_root_out() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64;
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // Wrong root_out (use root_in instead of correct updated root)
        let root_out = root_in;

        let circuit = BatchTransferCircuit::<1, DEPTH> {
            steps: [step],
            root_in,
            root_out,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Wrong root_out should fail");
    }

    #[test]
    fn test_single_transfer_insufficient_balance() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 50); // Only 50
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64; // Trying to send 100, but only has 50
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // Compute what root_out "would be" if this were valid
        // The circuit should reject due to range check on sender's new balance
        let sender_new = TestAccount {
            secret: sender.secret,
            balance: Fr::from(50u64) - Fr::from(100u64), // Underflow in field!
            salt: sender.salt,
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

        assert!(
            !cs.is_satisfied().unwrap(),
            "Insufficient balance should fail range check"
        );
    }

    #[test]
    fn test_single_transfer_wrong_sender_path() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64;

        // Build step with wrong sender path
        let wrong_path = [Fr::ZERO; DEPTH]; // Invalid path
        let sender_proof = AccountProof::new(
            sender.to_leaf_data(),
            MembershipProof::new(TestTree::<DEPTH>::index_to_bits(sender.index), wrong_path),
        );
        let receiver_proof = build_account_proof(&receiver, &tree);
        let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(amount));

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

        assert!(!cs.is_satisfied().unwrap(), "Wrong sender path should fail");
    }

    #[test]
    fn test_single_transfer_wrong_receiver_path() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64;

        // Build step with wrong receiver path
        let wrong_path = [Fr::ZERO; DEPTH];
        let sender_proof = build_account_proof(&sender, &tree);
        let receiver_proof = AccountProof::new(
            receiver.to_leaf_data(),
            MembershipProof::new(TestTree::<DEPTH>::index_to_bits(receiver.index), wrong_path),
        );
        let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(amount));

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

        assert!(
            !cs.is_satisfied().unwrap(),
            "Wrong receiver path should fail"
        );
    }

    #[test]
    fn test_single_transfer_same_index_rejected() {
        let mut tree = TestTree::<DEPTH>::new();

        // Sender and receiver at same index (invalid)
        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount {
            secret: Fr::rand(&mut thread_rng()),
            balance: Fr::from(500u64),
            salt: Fr::rand(&mut thread_rng()),
            index: 0, // Same index as sender!
        };

        tree.insert(sender.index, sender.commitment());

        let root_in = tree.compute_root();

        let amount = 100u64;
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // This should fail because first_difference_selectors won't find a difference
        let circuit = BatchTransferCircuit::<1, DEPTH> {
            steps: [step],
            root_in,
            root_out: root_in, // Doesn't matter, should fail earlier
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Same sender/receiver index should fail"
        );
    }

    // ============================================================
    // Multiple Independent Transfers (N=2, disjoint accounts)
    // ============================================================

    #[test]
    fn test_two_independent_transfers() {
        let mut tree = TestTree::<DEPTH>::new();

        // Four distinct accounts
        let alice = TestAccount::random(0, 1000);
        let bob = TestAccount::random(1, 500);
        let carol = TestAccount::random(2, 800);
        let dave = TestAccount::random(3, 200);

        tree.insert(alice.index, alice.commitment());
        tree.insert(bob.index, bob.commitment());
        tree.insert(carol.index, carol.commitment());
        tree.insert(dave.index, dave.commitment());

        let root_in = tree.compute_root();

        // Transfer 1: Alice -> Bob, 100
        let step1 = build_transfer_step(&alice, &bob, 100, &tree);

        // Apply transfer 1 to tree
        let alice_new = alice.with_balance(900);
        let bob_new = bob.with_balance(600);
        tree.insert(alice.index, alice_new.commitment());
        tree.insert(bob.index, bob_new.commitment());

        // Transfer 2: Carol -> Dave, 300 (using updated tree state)
        let step2 = build_transfer_step(&carol, &dave, 300, &tree);

        // Apply transfer 2 to tree
        let carol_new = carol.with_balance(500);
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

        assert!(
            cs.is_satisfied().unwrap(),
            "Two independent transfers should work"
        );
        println!(
            "Two independent transfers constraints: {}",
            cs.num_constraints()
        );
    }

    // ============================================================
    // Dependent/Chained Transfers (output feeds into next)
    // ============================================================

    #[test]
    fn test_chained_transfers_alice_bob_carol() {
        let mut tree = TestTree::<DEPTH>::new();

        // Alice -> Bob -> Carol chain
        let alice = TestAccount::random(0, 1000);
        let bob = TestAccount::random(1, 500);
        let carol = TestAccount::random(2, 200);

        tree.insert(alice.index, alice.commitment());
        tree.insert(bob.index, bob.commitment());
        tree.insert(carol.index, carol.commitment());

        let root_in = tree.compute_root();

        // Transfer 1: Alice -> Bob, 300
        let step1 = build_transfer_step(&alice, &bob, 300, &tree);

        // Apply transfer 1
        let alice_after_1 = alice.with_balance(700);
        let bob_after_1 = bob.with_balance(800);
        tree.insert(alice.index, alice_after_1.commitment());
        tree.insert(bob.index, bob_after_1.commitment());

        // Transfer 2: Bob -> Carol, 400 (Bob now has 800)
        // Need to use Bob's NEW state
        let step2 = build_transfer_step(&bob_after_1, &carol, 400, &tree);

        // Apply transfer 2
        let bob_after_2 = bob_after_1.with_balance(400);
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

        assert!(cs.is_satisfied().unwrap(), "Chained transfers should work");
    }

    #[test]
    fn test_chained_transfer_uses_stale_balance_fails() {
        let mut tree = TestTree::<DEPTH>::new();

        let alice = TestAccount::random(0, 1000);
        let bob = TestAccount::random(1, 100); // Bob starts with only 100
        let carol = TestAccount::random(2, 200);

        tree.insert(alice.index, alice.commitment());
        tree.insert(bob.index, bob.commitment());
        tree.insert(carol.index, carol.commitment());

        let root_in = tree.compute_root();

        // Transfer 1: Alice -> Bob, 500 (Bob will have 600 after)
        let step1 = build_transfer_step(&alice, &bob, 500, &tree);

        // Apply transfer 1
        let alice_after_1 = alice.with_balance(500);
        let bob_after_1 = bob.with_balance(600);
        tree.insert(alice.index, alice_after_1.commitment());
        tree.insert(bob.index, bob_after_1.commitment());

        // WRONG: Use Bob's OLD balance (100) for transfer 2, trying to send 400
        // This should fail because the witness has wrong balance
        let step2 = build_transfer_step(&bob, &carol, 400, &tree); // bob has balance 100 in witness!

        // Compute what final root "would be"
        let bob_after_2 = bob.with_balance(600 - 400); // Would be 200 if correct
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

        // This should fail because step2's sender commitment won't match the intermediate root
        assert!(
            !cs.is_satisfied().unwrap(),
            "Using stale balance should fail membership check"
        );
    }

    // ============================================================
    // Receiver Overflow Attack
    // ============================================================

    #[test]
    fn test_receiver_balance_overflow() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 100);
        // Receiver has balance near u64::MAX
        let receiver = TestAccount {
            secret: Fr::rand(&mut thread_rng()),
            balance: Fr::from(u64::MAX - 50),
            salt: Fr::rand(&mut thread_rng()),
            index: 1,
        };

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        // Try to send 100, which would overflow receiver's balance past u64::MAX
        let amount = 100u64;
        let step = build_transfer_step(&sender, &receiver, amount, &tree);

        // Compute the "overflowed" state
        let sender_new = sender.with_balance(0);
        let receiver_new = TestAccount {
            secret: receiver.secret,
            balance: Fr::from(u64::MAX - 50) + Fr::from(100u64),
            salt: receiver.salt,
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

        // Should fail range check on receiver's new balance
        assert!(
            !cs.is_satisfied().unwrap(),
            "Receiver balance overflow should fail range check"
        );
    }

    // ============================================================
    // Constraint Scaling Analysis
    // ============================================================

    #[test]
    fn test_constraint_count_scaling() {
        // Test N=1
        let constraints_1 = {
            let mut tree = TestTree::<DEPTH>::new();
            let sender = TestAccount::random(0, 1000);
            let receiver = TestAccount::random(1, 500);
            tree.insert(sender.index, sender.commitment());
            tree.insert(receiver.index, receiver.commitment());
            let root_in = tree.compute_root();
            let step = build_transfer_step(&sender, &receiver, 100, &tree);
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
            cs.num_constraints()
        };

        // Test N=2
        let constraints_2 = {
            let mut tree = TestTree::<DEPTH>::new();
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
            let a1_new = a1.with_balance(900);
            let a2_new = a2.with_balance(600);
            tree.insert(a1.index, a1_new.commitment());
            tree.insert(a2.index, a2_new.commitment());

            let step2 = build_transfer_step(&a3, &a4, 100, &tree);
            let a3_new = a3.with_balance(700);
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

        // Test N=3
        let constraints_3 = {
            let mut tree = TestTree::<DEPTH>::new();
            let accounts: Vec<TestAccount> = (0..6).map(|i| TestAccount::random(i, 1000)).collect();
            for a in &accounts {
                tree.insert(a.index, a.commitment());
            }
            let root_in = tree.compute_root();

            let step1 = build_transfer_step(&accounts[0], &accounts[1], 100, &tree);
            let a0_new = accounts[0].with_balance(900);
            let a1_new = accounts[1].with_balance(1100);
            tree.insert(accounts[0].index, a0_new.commitment());
            tree.insert(accounts[1].index, a1_new.commitment());

            let step2 = build_transfer_step(&accounts[2], &accounts[3], 100, &tree);
            let a2_new = accounts[2].with_balance(900);
            let a3_new = accounts[3].with_balance(1100);
            tree.insert(accounts[2].index, a2_new.commitment());
            tree.insert(accounts[3].index, a3_new.commitment());

            let step3 = build_transfer_step(&accounts[4], &accounts[5], 100, &tree);
            let a4_new = accounts[4].with_balance(900);
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

        println!("Constraint counts:");
        println!("  N=1: {}", constraints_1);
        println!("  N=2: {}", constraints_2);
        println!("  N=3: {}", constraints_3);
        println!(
            "  Per-transfer (N=2 - N=1): {}",
            constraints_2 - constraints_1
        );
        println!(
            "  Per-transfer (N=3 - N=2): {}",
            constraints_3 - constraints_2
        );

        // Verify roughly linear scaling
        let per_transfer_1_to_2 = constraints_2 - constraints_1;
        let per_transfer_2_to_3 = constraints_3 - constraints_2;

        // Should be approximately equal (within 5%)
        let diff = (per_transfer_1_to_2 as i64 - per_transfer_2_to_3 as i64).abs();
        let avg = (per_transfer_1_to_2 + per_transfer_2_to_3) / 2;
        assert!(
            diff < (avg as i64 / 20),
            "Constraint growth should be approximately linear"
        );
    }

    // ============================================================
    // Edge Cases
    // ============================================================

    #[test]
    fn test_adjacent_indices() {
        // Sender at index 0, receiver at index 1 (adjacent)
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let step = build_transfer_step(&sender, &receiver, 100, &tree);

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

        assert!(cs.is_satisfied().unwrap(), "Adjacent indices should work");
    }

    #[test]
    fn test_maximally_distant_indices() {
        // Sender at index 0, receiver at index 2^D - 1 (maximally distant)
        let mut tree = TestTree::<DEPTH>::new();

        let max_index = (1 << DEPTH) - 1;
        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(max_index, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        let step = build_transfer_step(&sender, &receiver, 100, &tree);

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

        assert!(
            cs.is_satisfied().unwrap(),
            "Maximally distant indices should work"
        );
    }

    #[test]
    fn test_wrong_index_bits() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        // Build step with wrong index bits for sender
        let wrong_index_bits = TestTree::<DEPTH>::index_to_bits(1); // Says index 1, but account is at 0
        let sender_proof = AccountProof::new(
            sender.to_leaf_data(),
            MembershipProof::new(wrong_index_bits, tree.get_path(sender.index)),
        );
        let receiver_proof = build_account_proof(&receiver, &tree);
        let step = TransferStep::new(sender_proof, receiver_proof, Fr::from(100u64));

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

        assert!(!cs.is_satisfied().unwrap(), "Wrong index bits should fail");
    }

    #[test]
    fn test_non_boolean_index_bits() {
        let mut tree = TestTree::<DEPTH>::new();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 500);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let root_in = tree.compute_root();

        // Build step with non-boolean index bit
        let mut bad_index_bits = TestTree::<DEPTH>::index_to_bits(sender.index);
        bad_index_bits[0] = Fr::from(2u64); // Not 0 or 1!

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

        assert!(
            !cs.is_satisfied().unwrap(),
            "Non-boolean index bits should fail"
        );
    }
}
