use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use hash_preimage::sponge::gadget::State;

use crate::curve::{gadget::PointVar, spec::Point};

pub const SIG_HASH_DST: Fr = MontFp!("857");

#[derive(Clone, Debug)]
pub struct Signature {
    r: Point,
    s: [bool; 256],
}

impl Signature {
    pub fn new(r: Point, s: [bool; 256]) -> Self {
        Self { r, s }
    }

    pub fn r(&self) -> &Point {
        &self.r
    }

    pub fn s(&self) -> &[bool; 256] {
        &self.s
    }
}

#[derive(Clone, Debug)]
pub struct SignatureVar {
    r: PointVar,
    s: [State; 256],
}

impl SignatureVar {
    pub fn new(r: PointVar, s: [State; 256]) -> Self {
        Self { r, s }
    }

    pub fn r(&self) -> &PointVar {
        &self.r
    }

    pub fn s(&self) -> &[State; 256] {
        &self.s
    }

    pub fn witness_from_signature(
        cs: &ConstraintSystemRef<Fr>,
        signature: &Signature,
    ) -> Result<Self, SynthesisError> {
        let mut s = [State::zero(); 256];
        for (b, &val) in s.iter_mut().zip(signature.s()) {
            *b = State::witness(cs, if val { Fr::ONE } else { Fr::ZERO })?;
        }

        let r = PointVar::from_point(cs, signature.r())?;

        Ok(Self { r, s })
    }
}
