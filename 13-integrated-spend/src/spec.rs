use batch_transfers::spec::TransferStepVar;
use non_membership::smt::spec::SmtNonMembershipProofVar;
use signatures::eddsa::spec::SignatureVar;

pub struct SpendTransaction<const D: usize> {
    transfer: TransferStepVar<D>,
    signature: SignatureVar,
    nullifier_proof: SmtNonMembershipProofVar<D>,
}

impl<const D: usize> SpendTransaction<D> {
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

    pub fn signature(&self) -> &SignatureVar {
        &self.signature
    }

    pub fn nullifier_proof(&self) -> &SmtNonMembershipProofVar<D> {
        &self.nullifier_proof
    }
}
