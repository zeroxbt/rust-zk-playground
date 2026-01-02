use ark_bls12_381::Fr;
use ark_relations::r1cs::ConstraintSynthesizer;
use batch_transfers::spec::{AccountProofVar, MembershipProofVar, TransferStepVar};
use hash_preimage::sponge::gadget::State;
use merkle_transfer_kernel::gadget::{enforce_bit_array, range_check};
use non_membership::smt::spec::SmtNonMembershipProofVar;
use nullifiers::commitment::spec::LeafState;
use signatures::eddsa::spec::SignatureVar;

use crate::spec::{SpendTransaction, SpendTransactionVar};

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
        let transaction = self.transaction;
        let transfer = transaction.transfer();
        let signature = transaction.signature();
        let nullifier_proof = transaction.nullifier_proof();
        let sender = AccountProofVar::<D>::new(
            LeafState::new(
                State::witness(&cs, transfer.sender().account().secret())?,
                State::witness(&cs, transfer.sender().account().balance())?,
                State::witness(&cs, transfer.sender().account().salt())?,
                State::witness(&cs, transfer.sender().account().nonce())?,
            ),
            MembershipProofVar::new(
                State::witness_array(&cs, transfer.sender().membership().index_bits())?,
                State::witness_array(&cs, transfer.sender().membership().path())?,
            ),
        );

        let receiver = AccountProofVar::<D>::new(
            LeafState::new(
                State::witness(&cs, transfer.receiver().account().secret())?,
                State::witness(&cs, transfer.receiver().account().balance())?,
                State::witness(&cs, transfer.receiver().account().salt())?,
                State::witness(&cs, transfer.receiver().account().nonce())?,
            ),
            MembershipProofVar::new(
                State::witness_array(&cs, transfer.receiver().membership().index_bits())?,
                State::witness_array(&cs, transfer.receiver().membership().path())?,
            ),
        );
        let transfer =
            TransferStepVar::new(sender, receiver, State::witness(&cs, transfer.amount())?);
        let signature = SignatureVar::witness_from_signature(&cs, signature)?;
        let nullifier_proof = SmtNonMembershipProofVar::new(
            State::witness_array(&cs, nullifier_proof.path())?,
            State::witness(&cs, nullifier_proof.nullifier())?,
        );

        range_check::<64>(&cs, transfer.amount())?;

        enforce_bit_array(&cs, transfer.sender().membership().index_bits())?;
        enforce_bit_array(&cs, transfer.receiver().membership().index_bits())?;
        enforce_bit_array(&cs, signature.s())?;

        let transaction = SpendTransactionVar::<D>::new(transfer, signature, nullifier_proof);
        let old_state_root = State::input(&cs, self.old_state_root)?;
        let new_state_root = State::input(&cs, self.new_state_root)?;
        let old_nullifier_root = State::input(&cs, self.old_nullifier_root)?;
        let new_nullifier_root = State::input(&cs, self.new_nullifier_root)?;
        let nullifier = State::input(&cs, self.nullifier)?;

        Ok(())
    }
}
