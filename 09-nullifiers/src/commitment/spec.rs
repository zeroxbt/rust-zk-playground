use ark_bls12_381::Fr;
use ark_ff::MontFp;

pub const COMMITMENT_DST: Fr = MontFp!("23");

#[derive(Clone, Copy, Debug)]
pub struct LeafData {
    secret: Fr,
    balance: Fr,
    salt: Fr,
}

impl LeafData {
    pub fn new(secret: Fr, balance: Fr, salt: Fr) -> Self {
        Self {
            secret,
            balance,
            salt,
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
}
