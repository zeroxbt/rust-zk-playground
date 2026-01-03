use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use hash_preimage::sponge::gadget::State;

pub const DEPTH: u16 = 256;
pub const DEFAULT_LEAF: Fr = Fr::ZERO;
pub const NULLIFIER_MARKER: Fr = Fr::ONE;

#[derive(Debug, Clone)]
pub struct SmtNonMembershipProof<const D: usize> {
    path: [Fr; D],
    nullifier: Fr,
}

impl<const D: usize> SmtNonMembershipProof<D> {
    pub fn new(path: [Fr; D], nullifier: Fr) -> Self {
        Self { path, nullifier }
    }

    pub fn path(&self) -> &[Fr; D] {
        &self.path
    }

    pub fn nullifier(&self) -> Fr {
        self.nullifier
    }
}

#[derive(Debug, Clone)]
pub struct SmtNonMembershipProofVar<const D: usize> {
    path: [State; D],
    nullifier: State,
}

impl<const D: usize> SmtNonMembershipProofVar<D> {
    pub fn new(path: [State; D], nullifier: State) -> Self {
        Self { path, nullifier }
    }

    pub fn path(&self) -> &[State; D] {
        &self.path
    }

    pub fn nullifier(&self) -> State {
        self.nullifier
    }
}

pub fn index_bits<const D: usize>(leaf: Fr) -> [bool; D] {
    assert!(D <= 256);
    let bits = leaf.into_bigint().to_bits_le();
    let mut index_bits = [false; D];
    index_bits.copy_from_slice(&bits[..D]);
    index_bits
}
