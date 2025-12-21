use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;

pub struct SpongeNative<P, const WIDTH: usize, const RATE: usize>
where
    P: PermutationNative<WIDTH>,
{
    perm: P,
}

pub trait PermutationNative<const T: usize> {
    fn permute_in_place(&self, state: &mut [Fr; T]);
}

impl<P, const WIDTH: usize, const RATE: usize> SpongeNative<P, WIDTH, RATE>
where
    P: PermutationNative<WIDTH>,
{
    pub fn hash(&self, x: &[Fr]) -> Fr {
        self.hash_with_dst(x, None)
    }

    pub fn hash_with_dst(&self, x: &[Fr], dst_capacity: Option<Fr>) -> Fr {
        let mut state = [Fr::ZERO; WIDTH];
        if let Some(tag) = dst_capacity {
            state[0] = tag;
        }

        for chunk in x.chunks(RATE) {
            for (lane, val) in chunk.iter().enumerate() {
                state[1 + lane] += *val;
            }
            self.perm.permute_in_place(&mut state);
        }
        state[1]
    }
}

impl<P, const WIDTH: usize, const RATE: usize> Default for SpongeNative<P, WIDTH, RATE>
where
    P: PermutationNative<WIDTH> + Default,
{
    fn default() -> Self {
        Self { perm: P::default() }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use crate::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

    #[test]
    fn hash_with_dst_differs_from_hash_without_dst() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        let dst = Fr::from(123456789u64);

        for _ in 0..50 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);

            let h_plain = sponge.hash(&[a, b]);
            let h_dst = sponge.hash_with_dst(&[a, b], Some(dst));

            assert_ne!(h_plain, h_dst);
        }
    }

    #[test]
    fn different_dsts_produce_different_hashes() {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let mut rng = test_rng();

        let dst1 = Fr::from(1u64);
        let dst2 = Fr::from(2u64);

        for _ in 0..50 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);

            let h1 = sponge.hash_with_dst(&[a, b], Some(dst1));
            let h2 = sponge.hash_with_dst(&[a, b], Some(dst2));

            assert_ne!(h1, h2);
        }
    }
}
