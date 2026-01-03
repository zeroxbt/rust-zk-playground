use ark_bls12_381::Fr;
use hash_preimage::sponge::gadget::State;
use nullifiers::commitment::spec::{LeafData, LeafState};

#[derive(Debug, Clone)]
pub struct MembershipProof<const D: usize> {
    index_bits: [Fr; D],
    path: [Fr; D],
}

impl<const D: usize> MembershipProof<D> {
    pub fn new(index_bits: [Fr; D], path: [Fr; D]) -> Self {
        Self { index_bits, path }
    }

    pub fn index_bits(&self) -> &[Fr; D] {
        &self.index_bits
    }

    pub fn path(&self) -> &[Fr; D] {
        &self.path
    }
}

#[derive(Debug, Clone)]
pub struct AccountProof<const D: usize> {
    account: LeafData,
    membership: MembershipProof<D>,
}

impl<const D: usize> AccountProof<D> {
    pub fn new(account: LeafData, membership: MembershipProof<D>) -> Self {
        Self {
            account,
            membership,
        }
    }

    pub fn account(&self) -> &LeafData {
        &self.account
    }

    pub fn membership(&self) -> &MembershipProof<D> {
        &self.membership
    }
}

#[derive(Debug, Clone)]
pub struct TransferStep<const D: usize> {
    sender: AccountProof<D>,
    receiver: AccountProof<D>,
    amount: Fr,
}

impl<const D: usize> TransferStep<D> {
    pub fn new(sender: AccountProof<D>, receiver: AccountProof<D>, amount: Fr) -> Self {
        Self {
            sender,
            receiver,
            amount,
        }
    }

    pub fn sender(&self) -> &AccountProof<D> {
        &self.sender
    }

    pub fn receiver(&self) -> &AccountProof<D> {
        &self.receiver
    }

    pub fn amount(&self) -> Fr {
        self.amount
    }
}

#[derive(Debug, Clone)]
pub struct MembershipProofVar<const D: usize> {
    index_bits: [State; D],
    path: [State; D],
}

impl<const D: usize> MembershipProofVar<D> {
    pub fn new(index_bits: [State; D], path: [State; D]) -> Self {
        Self { index_bits, path }
    }

    pub fn index_bits(&self) -> &[State; D] {
        &self.index_bits
    }

    pub fn path(&self) -> &[State; D] {
        &self.path
    }

    pub fn index_bits_mut(&mut self) -> &mut [State; D] {
        &mut self.index_bits
    }

    pub fn path_mut(&mut self) -> &mut [State; D] {
        &mut self.path
    }

    pub fn set_path(&mut self, path: [State; D]) {
        self.path = path;
    }
}

#[derive(Clone, Debug)]
pub struct AccountProofVar<const D: usize> {
    account: LeafState,
    membership: MembershipProofVar<D>,
}

impl<const D: usize> AccountProofVar<D> {
    pub fn new(account: LeafState, membership: MembershipProofVar<D>) -> Self {
        Self {
            account,
            membership,
        }
    }

    pub fn account(&self) -> &LeafState {
        &self.account
    }

    pub fn membership(&self) -> &MembershipProofVar<D> {
        &self.membership
    }

    pub fn account_mut(&mut self) -> &mut LeafState {
        &mut self.account
    }

    pub fn membership_mut(&mut self) -> &mut MembershipProofVar<D> {
        &mut self.membership
    }

    pub fn balance(&self) -> State {
        self.account.balance()
    }

    pub fn set_balance(&mut self, new_balance: State) {
        self.account.set_balance(new_balance);
    }

    pub fn set_nonce(&mut self, new_nonce: State) {
        self.account.set_nonce(new_nonce)
    }

    pub fn index_bits(&self) -> &[State; D] {
        self.membership.index_bits()
    }

    pub fn path(&self) -> &[State; D] {
        self.membership.path()
    }

    pub fn set_path(&mut self, new_path: [State; D]) {
        self.membership.set_path(new_path);
    }
}

pub struct TransferStepVar<const D: usize> {
    sender: AccountProofVar<D>,
    receiver: AccountProofVar<D>,
    amount: State,
}

impl<const D: usize> TransferStepVar<D> {
    pub fn new(sender: AccountProofVar<D>, receiver: AccountProofVar<D>, amount: State) -> Self {
        Self {
            sender,
            receiver,
            amount,
        }
    }

    pub fn sender(&self) -> &AccountProofVar<D> {
        &self.sender
    }

    pub fn receiver(&self) -> &AccountProofVar<D> {
        &self.receiver
    }

    pub fn amount(&self) -> State {
        self.amount
    }

    pub fn sender_mut(&mut self) -> &mut AccountProofVar<D> {
        &mut self.sender
    }

    pub fn receiver_mut(&mut self) -> &mut AccountProofVar<D> {
        &mut self.receiver
    }

    pub fn amount_mut(&mut self) -> &mut State {
        &mut self.amount
    }
}
