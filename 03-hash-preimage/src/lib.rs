pub mod circuits;
pub mod toy_hash;
use ark_bls12_381::{Bls12_381, Fr as Bls12_381Fr};

pub type Curve = Bls12_381;
pub type Fr = Bls12_381Fr;
