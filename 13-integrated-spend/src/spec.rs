use ark_bls12_381::Fr;
use ark_ff::MontFp;
use batch_transfers::spec::{TransferStep, TransferStepVar};
use non_membership::smt::spec::{SmtNonMembershipProof, SmtNonMembershipProofVar};
use signatures::eddsa::spec::{Signature, SignatureVar};

pub const SPEND_HASH_DST: Fr = MontFp!("701");

#[derive(Clone)]
pub struct SpendTransaction<const D: usize> {
    transfer: TransferStep<D>,
    signature: Signature,
    nullifier_proof: SmtNonMembershipProof<D>,
}

impl<const D: usize> SpendTransaction<D> {
    pub fn new(
        transfer: TransferStep<D>,
        signature: Signature,
        nullifier_proof: SmtNonMembershipProof<D>,
    ) -> Self {
        Self {
            transfer,
            signature,
            nullifier_proof,
        }
    }

    pub fn transfer(&self) -> &TransferStep<D> {
        &self.transfer
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn nullifier_proof(&self) -> &SmtNonMembershipProof<D> {
        &self.nullifier_proof
    }
}

pub struct SpendTransactionVar<const D: usize> {
    transfer: TransferStepVar<D>,
    signature: SignatureVar,
    nullifier_proof: SmtNonMembershipProofVar<D>,
}

impl<const D: usize> SpendTransactionVar<D> {
    pub fn new(
        transfer: TransferStepVar<D>,
        signature: SignatureVar,
        nullifier_proof: SmtNonMembershipProofVar<D>,
    ) -> Self {
        Self {
            transfer,
            signature,
            nullifier_proof,
        }
    }

    pub fn transfer(&self) -> &TransferStepVar<D> {
        &self.transfer
    }

    pub fn transfer_mut(&mut self) -> &mut TransferStepVar<D> {
        &mut self.transfer
    }

    pub fn signature(&self) -> &SignatureVar {
        &self.signature
    }

    pub fn nullifier_proof(&self) -> &SmtNonMembershipProofVar<D> {
        &self.nullifier_proof
    }
}
