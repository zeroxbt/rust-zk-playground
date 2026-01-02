use hash_preimage::sponge::gadget::State;

use crate::curve::{gadget::PointVar, spec::Point};

pub struct Signature {
    pub r: Point,
    pub s: Vec<bool>,
}

pub struct SignatureVar {
    pub r: PointVar,
    pub s: [State; 256],
}
