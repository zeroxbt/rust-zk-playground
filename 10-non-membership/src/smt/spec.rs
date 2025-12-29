use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};

pub const DEPTH: u16 = 256;
pub const DEFAULT_LEAF: Fr = Fr::ZERO;
pub const NULLIFIER_MARKER: Fr = Fr::ONE;

#[derive(Debug, Clone)]
pub struct NonMembershipProof<const D: usize> {
    path: [Fr; D],
    leaf: Fr,
}

impl<const D: usize> NonMembershipProof<D> {
    pub fn new(path: [Fr; D], leaf: Fr) -> Self {
        Self { path, leaf }
    }

    pub fn path(&self) -> [Fr; D] {
        self.path
    }

    pub fn leaf(&self) -> Fr {
        self.leaf
    }
}

pub fn index_bits<const D: usize>(leaf: Fr) -> [bool; D] {
    assert!(D >= 256);
    let mut index_bits = [false; D];
    index_bits.copy_from_slice(&leaf.into_bigint().to_bits_be());
    index_bits
}
