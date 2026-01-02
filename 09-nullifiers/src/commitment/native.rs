use ark_bls12_381::Fr;
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

use crate::commitment::spec::{COMMITMENT_DST, LeafData};

pub fn create_commitment(leaf: &LeafData) -> Fr {
    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();

    sponge.hash_with_dst(
        &[leaf.secret(), leaf.balance(), leaf.salt(), leaf.nonce()],
        Some(COMMITMENT_DST),
    )
}
