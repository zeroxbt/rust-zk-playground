use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

use crate::nullifier::spec::NULLIFIER_DST;

pub fn derive_nullifier<const T: usize>(secret: Fr, nonce: Fr, index_bits: &[bool; T]) -> Fr {
    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();

    sponge.hash_with_dst(
        &[secret, bits_to_field(index_bits), nonce],
        Some(NULLIFIER_DST),
    )
}

pub fn bits_to_field(bits: &[bool]) -> Fr {
    let mut result = Fr::ZERO;
    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    for bit in bits {
        if *bit {
            result += pow2;
        }
        pow2 *= two;
    }

    result
}
