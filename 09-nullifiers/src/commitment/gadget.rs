use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::commitment::spec::{COMMITMENT_DST, LeafData};

pub fn create_commitment(
    cs: &ConstraintSystemRef<Fr>,
    leaf: &LeafData,
) -> Result<State, SynthesisError> {
    let sponge = SpongeGadget::<PoseidonPermutation, 3, 2>::default();
    let msg: [State; 3] = State::witness_array(cs, &[leaf.secret(), leaf.balance(), leaf.salt()])?;

    sponge.hash_with_dst(cs, &msg, Some(COMMITMENT_DST), 1)
}
