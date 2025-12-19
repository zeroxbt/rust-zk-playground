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
