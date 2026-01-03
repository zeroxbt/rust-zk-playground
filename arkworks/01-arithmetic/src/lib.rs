pub mod circuits;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

pub type Curve = Bls12_381;
pub type Fr = <Curve as Pairing>::ScalarField;
