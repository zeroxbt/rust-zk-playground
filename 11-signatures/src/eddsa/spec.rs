use ark_bls12_381::Fr;
use ark_ff::MontFp;
use hash_preimage::sponge::gadget::State;

use crate::curve::{gadget::PointVar, spec::Point};

pub const SIG_HASH_DST: Fr = MontFp!("857");

pub struct Signature {
    pub r: Point,
    pub s: [bool; 256],
}

pub struct SignatureVar {
    pub r: PointVar,
    pub s: [State; 256],
}
