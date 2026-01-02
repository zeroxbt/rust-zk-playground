use ark_bls12_381::Fr;
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
use merkle_membership::merkle::native::compute_root;

use crate::smt::spec::{DEFAULT_LEAF, SmtNonMembershipProof, index_bits};

pub fn verify_non_membership<const D: usize>(
    root: Fr,
    nullifier: Fr,
    proof: &SmtNonMembershipProof<D>,
) -> bool {
    let index_bits = index_bits(nullifier);
    let computed_root = compute_root(
        &SpongeNative::<PoseidonPermutation, 3, 2>::default(),
        DEFAULT_LEAF,
        proof.path(),
        &index_bits,
    );

    root == computed_root
}
