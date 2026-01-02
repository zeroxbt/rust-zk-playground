use batch_transfers::spec::TransferStep;
use non_membership::smt::spec::SmtNonMembershipProofVar;
use signatures::eddsa::spec::SignatureVar;

pub struct SpendTransaction<const D: usize> {
    transfer: TransferStep<D>,
    signature: SignatureVar,
    nullifier_proof: SmtNonMembershipProofVar<D>,
}

impl<const D: usize> SpendTransaction<D> {}
