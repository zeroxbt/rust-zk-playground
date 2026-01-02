use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::ConstraintSynthesizer;
use hash_preimage::sponge::gadget::State;

use crate::{
    curve::{gadget::PointVar, spec::Point},
    eddsa::gadget::verify,
};

pub struct EddsaVerificationCircuit {
    r: Option<Point>,
    s: Option<[Fr; 256]>,
    pk: Option<Point>,
    msg: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EddsaVerificationCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let r = PointVar::from_point_input(&cs, &self.r.unwrap_or(Point::identity()))?;
        let pk = PointVar::from_point_input(&cs, &self.pk.unwrap_or(Point::identity()))?;
        let msg = State::input(&cs, self.msg.unwrap_or_default())?;
        let s: [State; 256] = State::input_array(&cs, &self.s.unwrap_or([Fr::ZERO; 256]))?;

        verify(&cs, &pk, msg, &s, &r)
    }
}
