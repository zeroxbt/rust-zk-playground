use ark_bls12_381::Fr;
use hash_preimage::sponge::native::{PermutationNative, SpongeNative};

use crate::merkle::spec::{DEPTH, MERKLE_NODE_DST};

pub fn compute_root<P: PermutationNative<3>>(
    sponge: &SpongeNative<P, 3, 2>,
    leaf: Fr,
    path: &[Fr; DEPTH],
    index_bits: &[bool; DEPTH],
) -> Fr {
    let mut cur = leaf;
    for (&sib, &b) in path.iter().zip(index_bits.iter()) {
        let (left, right) = if b { (sib, cur) } else { (cur, sib) };
        cur = sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST));
    }

    cur
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
    use rand::RngCore;

    use crate::merkle::{
        native::compute_root,
        spec::{DEPTH, MERKLE_NODE_DST},
    };

    fn random_path_and_bits(rng: &mut impl rand_core::RngCore) -> ([Fr; DEPTH], [bool; DEPTH]) {
        let path = [0; DEPTH].map(|_| Fr::rand(rng));
        let bits = [0; DEPTH].map(|_| (rng.next_u32() & 1) == 1);
        (path, bits)
    }

    fn compute_root_without_dst(
        sponge: &SpongeNative<PoseidonPermutation, 3, 2>,
        leaf: Fr,
        path: &[Fr; DEPTH],
        index_bits: &[bool; DEPTH],
    ) -> Fr {
        let mut cur = leaf;
        for (&sib, &b) in path.iter().zip(index_bits.iter()) {
            let (left, right) = if b { (sib, cur) } else { (cur, sib) };
            cur = sponge.hash(&[left, right]);
        }
        cur
    }

    #[test]
    fn merkle_root_changes_if_dst_is_removed() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        // Multiple trials to make “accidental collision” negligible.
        for _ in 0..50 {
            let leaf = Fr::rand(&mut rng);
            let (path, index_bits) = random_path_and_bits(&mut rng);

            let with_dst = compute_root(&sponge, leaf, &path, &index_bits);
            let without_dst = compute_root_without_dst(&sponge, leaf, &path, &index_bits);

            assert_ne!(
                with_dst, without_dst,
                "Merkle root unexpectedly equal with vs without DST (DST={:?})",
                MERKLE_NODE_DST
            );
        }
    }

    #[test]
    fn compute_root_same_input_same_output() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        let leaf = Fr::rand(&mut rng);
        let (path, index_bits) = random_path_and_bits(&mut rng);

        let r1 = compute_root(&sponge, leaf, &path, &index_bits);
        let r2 = compute_root(&sponge, leaf, &path, &index_bits);
        assert_eq!(r1, r2);
    }

    #[test]
    fn flipping_one_index_bit_changes_root_most_of_the_time() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        for _ in 0..50 {
            let leaf = Fr::rand(&mut rng);
            let (path, mut index_bits) = random_path_and_bits(&mut rng);

            let root = compute_root(&sponge, leaf, &path, &index_bits);

            // Flip one random bit
            let j = (rng.next_u32() as usize) % DEPTH;
            index_bits[j] = !index_bits[j];

            let root_flipped = compute_root(&sponge, leaf, &path, &index_bits);

            assert_ne!(root, root_flipped);
        }
    }

    #[test]
    fn changing_one_sibling_changes_root_most_of_the_time() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        for _ in 0..50 {
            let leaf = Fr::rand(&mut rng);
            let (mut path, index_bits) = random_path_and_bits(&mut rng);

            let root = compute_root(&sponge, leaf, &path, &index_bits);

            // Change one sibling
            let j = (rng.next_u32() as usize) % DEPTH;
            path[j] += Fr::from(1u64);

            let root_changed = compute_root(&sponge, leaf, &path, &index_bits);

            assert_ne!(root, root_changed);
        }
    }

    #[test]
    fn changing_leaf_changes_root_most_of_the_time() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        for _ in 0..50 {
            let leaf = Fr::rand(&mut rng);
            let (path, index_bits) = random_path_and_bits(&mut rng);

            let root = compute_root(&sponge, leaf, &path, &index_bits);

            let leaf2 = leaf + Fr::from(1u64);
            let root2 = compute_root(&sponge, leaf2, &path, &index_bits);

            assert_ne!(root, root2);
        }
    }
}
