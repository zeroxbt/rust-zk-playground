use ark_bls12_381::Fr;
use hash_preimage::sponge::native::{PermutationNative, SpongeNative};

use crate::merkle::spec::{DEPTH, MERKLE_NODE_DST};

fn hash_node<P>(sponge: &SpongeNative<P, 3, 2>, left: Fr, right: Fr) -> Fr
where
    P: PermutationNative<3>,
{
    // Domain-separate Merkle nodes by setting the capacity lane to a fixed tag.
    sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST))
}

pub fn compute_root<P: PermutationNative<3>>(
    sponge: &SpongeNative<P, 3, 2>,
    leaf: Fr,
    path: &[Fr; DEPTH],
    index_bits: &[bool; DEPTH],
) -> Fr {
    let mut cur = leaf;
    for (&sib, &b) in path.iter().zip(index_bits.iter()) {
        let (left, right) = if b { (sib, cur) } else { (cur, sib) };
        cur = hash_node(sponge, left, right);
    }

    cur
}
