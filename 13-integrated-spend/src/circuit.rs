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
