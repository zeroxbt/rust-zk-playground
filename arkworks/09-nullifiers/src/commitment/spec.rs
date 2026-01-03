use ark_bls12_381::Fr;
use ark_ff::MontFp;
use hash_preimage::sponge::gadget::State;

pub const COMMITMENT_DST: Fr = MontFp!("23");

#[derive(Clone, Copy, Debug)]
pub struct LeafData {
    secret: Fr,
    balance: Fr,
    salt: Fr,
    nonce: Fr,
}

impl LeafData {
    pub fn new(secret: Fr, balance: Fr, salt: Fr, nonce: Fr) -> Self {
        Self {
            secret,
            balance,
            salt,
            nonce,
        }
    }

    pub fn secret(&self) -> Fr {
        self.secret
    }

    pub fn balance(&self) -> Fr {
        self.balance
    }

    pub fn salt(&self) -> Fr {
        self.salt
    }

    pub fn nonce(&self) -> Fr {
        self.nonce
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LeafState {
    secret: State,
    balance: State,
    salt: State,
    nonce: State,
}

impl LeafState {
    pub fn new(secret: State, balance: State, salt: State, nonce: State) -> Self {
        Self {
            secret,
            balance,
            salt,
            nonce,
        }
    }

    pub fn secret(&self) -> State {
        self.secret
    }

    pub fn balance(&self) -> State {
        self.balance
    }

    pub fn salt(&self) -> State {
        self.salt
    }

    pub fn nonce(&self) -> State {
        self.nonce
    }

    pub fn set_balance(&mut self, balance: State) {
        self.balance = balance;
    }

    pub fn set_nonce(&mut self, new_nonce: State) {
        self.nonce = new_nonce
    }
}
