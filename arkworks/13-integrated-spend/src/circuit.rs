use ark_bls12_381::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use batch_transfers::{
    circuit::transfer,
    spec::{AccountProofVar, MembershipProofVar, TransferStepVar},
};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};
use merkle_transfer_kernel::gadget::{enforce_bit_array, range_check};
use non_membership::smt::{
    gadget::{verify_membership, verify_non_membership},
    spec::SmtNonMembershipProofVar,
};
use nullifiers::{
    commitment::{gadget::create_commitment, spec::LeafState},
    nullifier::gadget::derive_nullifier,
};
use signatures::{
    curve::gadget::{PointVar, scalar_mul},
    eddsa::{
        gadget::{to_bits_le_fixed, verify},
        spec::SignatureVar,
    },
};

use crate::spec::{SPEND_HASH_DST, SpendTransaction, SpendTransactionVar};

pub struct IntegratedSpendCircuit<const D: usize> {
    transaction: SpendTransaction<D>,
    old_state_root: Fr,
    new_state_root: Fr,
    old_nullifier_root: Fr,
    new_nullifier_root: Fr,
    nullifier: Fr,
}

impl<const D: usize> ConstraintSynthesizer<Fr> for IntegratedSpendCircuit<D> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let mut tx = allocate_transaction_witness(&cs, &self.transaction)?;
        let old_state_root = State::input(&cs, self.old_state_root)?;
        let new_state_root = State::input(&cs, self.new_state_root)?;
        let old_nullifier_root = State::input(&cs, self.old_nullifier_root)?;
        let new_nullifier_root = State::input(&cs, self.new_nullifier_root)?;
        let nullifier = State::input(&cs, self.nullifier)?;

        verify_nullifier(
            &cs,
            tx.transfer().sender(),
            tx.nullifier_proof(),
            nullifier,
            old_nullifier_root,
            new_nullifier_root,
        )?;
        verify_signature(&cs, &tx, nullifier, old_state_root, old_nullifier_root)?;

        let computed_state_root = transfer(&cs, tx.transfer_mut(), old_state_root)?;

        cs.enforce_constraint(
            LinearCombination::from(computed_state_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(new_state_root.var()),
        )?;

        Ok(())
    }
}

fn allocate_transaction_witness<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    transaction: &SpendTransaction<D>,
) -> Result<SpendTransactionVar<D>, SynthesisError> {
    let transfer = transaction.transfer();
    let signature = transaction.signature();
    let nullifier_proof = transaction.nullifier_proof();
    let sender = AccountProofVar::<D>::new(
        LeafState::new(
            State::witness(cs, transfer.sender().account().secret())?,
            State::witness(cs, transfer.sender().account().balance())?,
            State::witness(cs, transfer.sender().account().salt())?,
            State::witness(cs, transfer.sender().account().nonce())?,
        ),
        MembershipProofVar::new(
            State::witness_array(cs, transfer.sender().membership().index_bits())?,
            State::witness_array(cs, transfer.sender().membership().path())?,
        ),
    );

    let receiver = AccountProofVar::<D>::new(
        LeafState::new(
            State::witness(cs, transfer.receiver().account().secret())?,
            State::witness(cs, transfer.receiver().account().balance())?,
            State::witness(cs, transfer.receiver().account().salt())?,
            State::witness(cs, transfer.receiver().account().nonce())?,
        ),
        MembershipProofVar::new(
            State::witness_array(cs, transfer.receiver().membership().index_bits())?,
            State::witness_array(cs, transfer.receiver().membership().path())?,
        ),
    );
    let transfer = TransferStepVar::new(sender, receiver, State::witness(cs, transfer.amount())?);
    let signature = SignatureVar::witness_from_signature(cs, signature)?;
    let nullifier_proof = SmtNonMembershipProofVar::new(
        State::witness_array(cs, nullifier_proof.path())?,
        State::witness(cs, nullifier_proof.nullifier())?,
    );

    range_check::<64>(cs, transfer.amount())?;

    enforce_bit_array(cs, transfer.sender().membership().index_bits())?;
    enforce_bit_array(cs, transfer.receiver().membership().index_bits())?;
    enforce_bit_array(cs, signature.s())?;

    let transaction = SpendTransactionVar::<D>::new(transfer, signature, nullifier_proof);

    Ok(transaction)
}

fn verify_nullifier<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    account_proof: &AccountProofVar<D>,
    nullifier_proof: &SmtNonMembershipProofVar<D>,
    input_nullifier: State,
    old_nullifier_root: State,
    new_nullifier_root: State,
) -> Result<(), SynthesisError> {
    let derived_nullifier = derive_nullifier(
        cs,
        account_proof.account().secret(),
        account_proof.account().nonce(),
        account_proof.index_bits(),
    )?;

    cs.enforce_constraint(
        LinearCombination::from(derived_nullifier.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(input_nullifier.var()),
    )?;

    cs.enforce_constraint(
        LinearCombination::from(nullifier_proof.nullifier().var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(derived_nullifier.var()),
    )?;

    verify_non_membership(cs, old_nullifier_root, nullifier_proof)?;
    verify_membership(cs, new_nullifier_root, nullifier_proof)
}

fn verify_signature<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    tx: &SpendTransactionVar<D>,
    input_nullifier: State,
    old_state_root: State,
    old_nullifier_root: State,
) -> Result<(), SynthesisError> {
    let transfer = tx.transfer();
    let mut sk_bits = to_bits_le_fixed(cs, transfer.sender().account().secret())?;
    sk_bits.reverse();
    let pk = scalar_mul(cs, &sk_bits, &PointVar::generator(cs)?)?;
    let sponge = SpongeGadget::<PoseidonPermutation, 3, 2>::default();
    let receiver_commitment = create_commitment(cs, transfer.receiver().account())?;
    let msg = sponge.hash_with_dst(
        cs,
        &[
            input_nullifier,
            receiver_commitment,
            transfer.amount(),
            old_state_root,
            old_nullifier_root,
        ],
        Some(SPEND_HASH_DST),
        1,
    )?;

    verify(cs, &pk, msg, tx.signature())
}

#[cfg(test)]
mod integrated_spend_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::test_rng;
    use batch_transfers::spec::{AccountProof, MembershipProof, TransferStep};
    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
    use merkle_membership::merkle::spec::MERKLE_NODE_DST;
    use non_membership::smt::tree::SparseMerkleTree;
    use nullifiers::{
        commitment::{native::create_commitment, spec::LeafData},
        nullifier::native as nullifier_native,
    };
    use rand::thread_rng;
    use signatures::eddsa::native as eddsa_native;

    use super::*;
    use crate::spec::SpendTransaction;

    pub const DEPTH: usize = 4;

    #[derive(Default)]
    /// Simple sparse Merkle tree for tests
    pub struct TestTree<const D: usize> {
        leaves: Vec<(usize, Fr)>, // (index, commitment)
        empty_leaf: Fr,
    }

    impl<const D: usize> TestTree<D> {
        pub fn insert(&mut self, index: usize, commitment: Fr) {
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

        pub fn index_to_bits(index: usize) -> [Fr; D] {
            let mut bits = [Fr::ZERO; D];
            for (i, b) in bits.iter_mut().enumerate().take(D) {
                if (index >> i) & 1 == 1 {
                    *b = Fr::ONE;
                }
            }
            bits
        }

        pub fn compute_root(&self) -> Fr {
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

        pub fn get_path(&self, index: usize) -> [Fr; D] {
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

    #[derive(Clone, Debug)]
    pub struct TestAccount {
        pub secret: Fr,
        pub balance: Fr,
        pub salt: Fr,
        pub nonce: Fr,
        pub index: usize,
    }

    impl TestAccount {
        pub fn random(index: usize, balance: u64) -> Self {
            let mut rng = thread_rng();
            Self {
                secret: Fr::rand(&mut rng),
                balance: Fr::from(balance),
                salt: Fr::rand(&mut rng),
                nonce: Fr::ZERO,
                index,
            }
        }

        pub fn commitment(&self) -> Fr {
            create_commitment(&self.to_leaf_data())
        }

        pub fn to_leaf_data(&self) -> LeafData {
            LeafData::new(self.secret, self.balance, self.salt, self.nonce)
        }

        pub fn with_balance(&self, new_balance: u64) -> Self {
            Self {
                secret: self.secret,
                balance: Fr::from(new_balance),
                salt: self.salt,
                nonce: self.nonce,
                index: self.index,
            }
        }

        pub fn increment_nonce(&self) -> Self {
            Self {
                secret: self.secret,
                balance: self.balance,
                salt: self.salt,
                nonce: self.nonce + Fr::ONE,
                index: self.index,
            }
        }
    }

    pub fn build_account_proof<const D: usize>(
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

    pub fn build_transfer_step<const D: usize>(
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

    /// Convert your [Fr; D] index bits (0/1) into [bool; D] for native nullifier derivation.
    fn fr_bits_to_bool<const D: usize>(bits: &[Fr; D]) -> [bool; D] {
        let mut out = [false; D];
        for i in 0..D {
            // You enforce bits elsewhere; here we just interpret 0/1.
            out[i] = bits[i] != Fr::ZERO;
        }
        out
    }

    fn spend_msg(
        nullifier: Fr,
        receiver_commitment: Fr,
        amount: Fr,
        old_state_root: Fr,
        old_nullifier_root: Fr,
    ) -> Fr {
        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
        sponge.hash_with_dst(
            &[
                nullifier,
                receiver_commitment,
                amount,
                old_state_root,
                old_nullifier_root,
            ],
            Some(SPEND_HASH_DST),
        )
    }

    /// Sign message using your native EdDSA.
    /// If your API is different, change only this function.
    fn sign_msg(secret: Fr, msg: Fr) -> signatures::eddsa::spec::Signature {
        // Assumed API:
        //   eddsa_native::sign(sk, msg) -> Signature
        eddsa_native::sign(secret, msg)
    }

    #[derive(Clone)]
    struct Fixture<const D: usize> {
        tx: SpendTransaction<D>,
        old_state_root: Fr,
        new_state_root: Fr,
        old_null_root: Fr,
        new_null_root: Fr,
        nullifier: Fr,
    }

    fn build_fixture<const D: usize>(amount_u64: u64) -> Fixture<D> {
        // ---- Build state tree with 2 accounts ----
        let mut tree = TestTree::<D>::default();

        let sender = TestAccount::random(0, 1000);
        let receiver = TestAccount::random(1, 100);

        tree.insert(sender.index, sender.commitment());
        tree.insert(receiver.index, receiver.commitment());

        let old_state_root = tree.compute_root();

        // Witness transfer step uses old sender/receiver leaf data + membership proofs
        let transfer = build_transfer_step(&sender, &receiver, amount_u64, &tree);

        // ---- Compute nullifier + SMT roots/proof ----
        let mut smt = SparseMerkleTree::<D>::default();
        let old_null_root = smt.root();

        let sender_bits_fr: [Fr; D] = *transfer.sender().membership().index_bits();
        let sender_bits_bool = fr_bits_to_bool(&sender_bits_fr);

        let nullifier =
            nullifier_native::derive_nullifier(sender.secret, sender.nonce, &sender_bits_bool);

        let nullifier_proof = smt.prove(nullifier);

        assert!(
            smt.insert(nullifier),
            "fixture bug: inserting fresh nullifier should succeed"
        );

        let new_null_root = smt.root();

        // ---- Apply native state update to get new_state_root ----
        // Your circuit's transfer() now increments sender nonce and updates balances.
        // Model the same thing natively and compute new root.
        let sender_after = sender.increment_nonce().with_balance(
            (1000u64)
                .checked_sub(amount_u64)
                .expect("underflow in fixture"),
        );

        let receiver_after = receiver.with_balance(100u64 + amount_u64);

        // Update tree commitments
        tree.insert(sender_after.index, sender_after.commitment());
        tree.insert(receiver_after.index, receiver_after.commitment());

        let new_state_root = tree.compute_root();

        // ---- Signature over (nullifier, receiver_commitment, amount) ----
        // receiver_commitment is commitment of receiver leaf as seen in the *transfer witness*
        // (i.e., pre-transfer receiver leaf).
        let receiver_commitment = create_commitment(&receiver.to_leaf_data());
        let msg = spend_msg(
            nullifier,
            receiver_commitment,
            Fr::from(amount_u64),
            old_state_root,
            old_null_root,
        );
        let signature = sign_msg(sender.secret, msg);

        // ---- Assemble SpendTransaction ----
        let tx = SpendTransaction::<D>::new(transfer, signature, nullifier_proof);

        Fixture {
            tx,
            old_state_root,
            new_state_root,
            old_null_root,
            new_null_root,
            nullifier,
        }
    }

    fn run<const D: usize>(fx: Fixture<D>) -> (bool, usize) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = IntegratedSpendCircuit::<D> {
            transaction: fx.tx,
            old_state_root: fx.old_state_root,
            new_state_root: fx.new_state_root,
            old_nullifier_root: fx.old_null_root,
            new_nullifier_root: fx.new_null_root,
            nullifier: fx.nullifier,
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        (cs.is_satisfied().unwrap(), cs.num_constraints())
    }

    // =========================
    // Positive test
    // =========================

    #[test]
    fn integrated_spend_valid_satisfies() {
        let fx = build_fixture::<DEPTH>(25);
        let (ok, n) = run::<DEPTH>(fx);
        assert!(ok, "valid spend should satisfy");
        println!("IntegratedSpendCircuit constraints: {}", n);
    }

    // =========================
    // State root binding tests
    // =========================

    #[test]
    fn integrated_spend_rejects_wrong_new_state_root() {
        let mut fx = build_fixture::<DEPTH>(25);
        fx.new_state_root += Fr::ONE;
        let (ok, _) = run::<DEPTH>(fx);
        assert!(!ok, "should fail if new_state_root is wrong");
    }

    #[test]
    fn integrated_spend_rejects_wrong_old_state_root() {
        let mut fx = build_fixture::<DEPTH>(25);
        fx.old_state_root += Fr::ONE;
        let (ok, _) = run::<DEPTH>(fx);
        assert!(!ok, "should fail if old_state_root is wrong");
    }

    // =========================
    // Nullifier / SMT tests
    // =========================

    #[test]
    fn integrated_spend_rejects_wrong_public_nullifier() {
        let mut fx = build_fixture::<DEPTH>(25);
        fx.nullifier += Fr::ONE;
        let (ok, _) = run::<DEPTH>(fx);
        assert!(
            !ok,
            "should fail if public nullifier mismatches derived nullifier"
        );
    }

    #[test]
    fn integrated_spend_rejects_nullifier_already_spent() {
        let mut fx = build_fixture::<DEPTH>(25);

        // Make non-membership fail: claim the old root is already the spent root.
        fx.old_null_root = fx.new_null_root;

        let (ok, _) = run::<DEPTH>(fx);
        assert!(
            !ok,
            "should fail if nullifier already present in old_nullifier_root"
        );
    }

    #[test]
    fn integrated_spend_rejects_if_new_null_root_does_not_mark_nullifier() {
        let mut fx = build_fixture::<DEPTH>(25);

        // Make membership fail: claim new root equals old root (no insertion happened).
        fx.new_null_root = fx.old_null_root;

        let (ok, _) = run::<DEPTH>(fx);
        assert!(
            !ok,
            "should fail if new_nullifier_root does not include marker at nullifier key"
        );
    }

    // =========================
    // Signature binding tests
    // =========================

    #[test]
    fn integrated_spend_rejects_amount_tampered_after_signing() {
        // Build a valid spend for amount=25 (includes correct roots and signature for 25)
        let fx_good = build_fixture::<DEPTH>(25);

        // Now build a *different* correct state transition for amount=26 (roots updated),
        // but reuse the signature from the amount=25 spend.
        //
        // This isolates the signature check: the circuit should fail because signature msg
        // includes amount.
        let mut fx_tampered = build_fixture::<DEPTH>(26);

        // Reuse signature and nullifier proof from the 25-amount transaction.
        // Nullifier is independent of amount (depends on secret, nonce, index).
        // SMT roots are also independent of amount (still inserts the same nullifier).
        // We keep *the correct roots* for amount=26 so the only failure is signature.
        let sig = fx_good.tx.signature().clone();
        let null_proof = fx_good.tx.nullifier_proof().clone();
        let transfer = fx_tampered.tx.transfer().clone();

        fx_tampered.tx = SpendTransaction::<DEPTH>::new(transfer, sig, null_proof);

        let (ok, _) = run::<DEPTH>(fx_tampered);
        assert!(
            !ok,
            "should fail if amount changes but signature is not updated"
        );
    }

    // =========================
    // SMT gadget sanity (optional but very useful)
    // =========================

    #[test]
    fn smt_membership_and_non_membership_disagree_on_empty_root() {
        use hash_preimage::sponge::gadget::State as GState;
        use non_membership::smt::{
            gadget::{verify_membership, verify_non_membership},
            spec::SmtNonMembershipProofVar,
        };

        let mut rng = test_rng();
        let key = Fr::rand(&mut rng);

        let smt = SparseMerkleTree::<DEPTH>::default();
        let root = smt.root();
        let proof = smt.prove(key);

        // Non-membership should satisfy on empty tree
        let cs1 = ConstraintSystem::<Fr>::new_ref();
        let root1 = GState::input(&cs1, root).unwrap();
        let path1 = GState::witness_array(&cs1, proof.path()).unwrap();
        let key1 = GState::witness(&cs1, proof.nullifier()).unwrap();
        let pv1 = SmtNonMembershipProofVar::<DEPTH>::new(path1, key1);

        verify_non_membership(&cs1, root1, &pv1).unwrap();
        assert!(
            cs1.is_satisfied().unwrap(),
            "non-membership must hold on empty tree"
        );

        // Membership should not satisfy on empty tree for same key/path/root
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let root2 = GState::input(&cs2, root).unwrap();
        let path2 = GState::witness_array(&cs2, proof.path()).unwrap();
        let key2 = GState::witness(&cs2, proof.nullifier()).unwrap();
        let pv2 = SmtNonMembershipProofVar::<DEPTH>::new(path2, key2);

        verify_membership(&cs2, root2, &pv2).unwrap();
        assert!(
            !cs2.is_satisfied().unwrap(),
            "membership must not hold on empty tree for same key"
        );
    }
}
