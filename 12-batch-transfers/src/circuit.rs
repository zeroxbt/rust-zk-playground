use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Variable,
};
use hash_preimage::sponge::gadget::{SpongeGadget, State};
use merkle_transfer_kernel::gadget::{
    compute_root_with_spine, enforce_bit_array, patch_receiver_path, range_check,
};
use nullifiers::commitment::{gadget::create_commitment, spec::LeafState};

use crate::spec::{AccountProofVar, MembershipProofVar, TransferStep, TransferStepVar};

pub struct BatchTransferCircuit<const N: usize, const D: usize> {
    pub steps: [TransferStep<D>; N],
    pub root_in: Fr,
    pub root_out: Fr,
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
                    State::witness(&cs, tx.sender().account().nonce())?,
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
                    State::witness(&cs, tx.receiver().account().nonce())?,
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

    let sender_nonce_new = State::witness(cs, tx_var.sender().account().nonce().val() + Fr::ONE)?;
    range_check::<64>(cs, sender_nonce_new)?;
    cs.enforce_constraint(
        LinearCombination::from(sender_nonce_new.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(tx_var.sender().account().nonce().var()) + (Fr::ONE, Variable::One),
    )?;
    tx_var.sender_mut().set_nonce(sender_nonce_new);

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

    let new_receiver_path = patch_receiver_path(
        cs,
        tx_var.sender().membership().index_bits(),
        tx_var.receiver().membership().index_bits(),
        &spine,
        tx_var.receiver().membership().path(),
    )?;
    tx_var.receiver_mut().set_path(new_receiver_path);

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
