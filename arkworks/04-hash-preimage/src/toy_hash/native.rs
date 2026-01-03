use ark_bls12_381::Fr;
use ark_ff::Field;

use crate::{
    sponge::native::PermutationNative,
    toy_hash::spec::{TOY_HASH_SPEC, ToyHashSpec},
};

pub struct ToyHashPermutation<'a> {
    spec: &'a ToyHashSpec,
}

impl ToyHashPermutation<'_> {
    pub fn spec(&self) -> &ToyHashSpec {
        self.spec
    }
}

impl Default for ToyHashPermutation<'_> {
    fn default() -> Self {
        Self {
            spec: &TOY_HASH_SPEC,
        }
    }
}

impl PermutationNative<2> for ToyHashPermutation<'_> {
    fn permute_in_place(&self, state: &mut [Fr; 2]) {
        let mut s0 = state[0];
        let mut s1 = state[1];
        for [c0, c1] in self.spec.ark {
            // add round constants
            let u0 = s0 + c0;
            let u1 = s1 + c1;

            // s-box u^alpha
            let v0 = u0.pow([self.spec.alpha]);
            let v1 = u1.pow([self.spec.alpha]);

            // linear mixing
            s0 = self.spec.mds[0][0] * v0 + self.spec.mds[0][1] * v1;
            s1 = self.spec.mds[1][0] * v0 + self.spec.mds[1][1] * v1;
        }

        state[0] = s0;
        state[1] = s1;
    }
}
