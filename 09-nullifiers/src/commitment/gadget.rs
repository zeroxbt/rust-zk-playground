use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::commitment::spec::{COMMITMENT_DST, LeafState};

pub fn create_commitment(
    cs: &ConstraintSystemRef<Fr>,
    leaf: &LeafState,
) -> Result<State, SynthesisError> {
    let sponge = SpongeGadget::<PoseidonPermutation, 3, 2>::default();

    sponge.hash_with_dst(
        cs,
        &[leaf.secret(), leaf.balance(), leaf.salt(), leaf.nonce()],
        Some(COMMITMENT_DST),
        1,
    )
}
