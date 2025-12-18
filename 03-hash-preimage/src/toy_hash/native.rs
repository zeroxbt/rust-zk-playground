use crate::toy_hash::spec::{MDS, ROUND_CONSTANTS};
use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;

pub fn permute(mut s0: Fr, mut s1: Fr) -> (Fr, Fr) {
    for [c0, c1] in ROUND_CONSTANTS {
        // add round constants
        let u0 = s0 + c0;
        let u1 = s1 + c1;

        // s-box u^5 (mirrors circuit)
        let u0_2 = u0 * u0;
        let u0_4 = u0_2 * u0_2;
        let v0 = u0_4 * u0;

        let u1_2 = u1 * u1;
        let u1_4 = u1_2 * u1_2;
        let v1 = u1_4 * u1;

        // linear mixing
        s0 = MDS[0][0] * v0 + MDS[0][1] * v1;
        s1 = MDS[1][0] * v0 + MDS[1][1] * v1;
    }

    (s0, s1)
}

pub fn hash(x: Fr) -> Fr {
    let mut s0 = Fr::ZERO;
    let s1 = Fr::ZERO;

    // absorb x0
    s0 += x;
    (s0, _) = permute(s0, s1);

    // squeeze
    s0
}

pub fn hash2(x0: Fr, x1: Fr) -> Fr {
    let mut s0 = Fr::ZERO;
    let mut s1 = Fr::ZERO;

    // absorb x0
    s0 += x0;
    (s0, s1) = permute(s0, s1);

    // absorb x1
    s0 += x1;
    (s0, _) = permute(s0, s1);

    // squeeze
    s0
}
