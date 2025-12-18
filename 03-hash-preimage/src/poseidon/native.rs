use crate::poseidon::spec::PoseidonSpec;
use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;

pub fn permute(spec: &PoseidonSpec, state: &mut [Fr; 3]) {
    assert!(spec.full_rounds.is_multiple_of(2));
    debug_assert!(spec.alpha == 17, "Alpha assumed to be 17.");
    assert_eq!(
        spec.round_constants.len(),
        spec.full_rounds + spec.partial_rounds
    );

    let fr2 = spec.full_rounds / 2;
    let (first_full, rest) = spec.round_constants.split_at(fr2);
    let (partial, last_full) = rest.split_at(spec.partial_rounds);

    for rc in first_full {
        full_round(spec, state, rc);
    }
    for rc in partial {
        partial_round(spec, state, rc);
    }
    for rc in last_full {
        full_round(spec, state, rc);
    }
}

fn pow17(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x8 = x4 * x4;
    let x16 = x8 * x8;
    x16 * x
}

fn full_round(spec: &PoseidonSpec, state: &mut [Fr; 3], rc: &[Fr; 3]) {
    let u0 = state[0] + rc[0];
    let u1 = state[1] + rc[1];
    let u2 = state[2] + rc[2];

    let v0 = pow17(u0);
    let v1 = pow17(u1);
    let v2 = pow17(u2);

    let n0 = spec.mds[0][0] * v0 + spec.mds[0][1] * v1 + spec.mds[0][2] * v2;
    let n1 = spec.mds[1][0] * v0 + spec.mds[1][1] * v1 + spec.mds[1][2] * v2;
    let n2 = spec.mds[2][0] * v0 + spec.mds[2][1] * v1 + spec.mds[2][2] * v2;

    state[0] = n0;
    state[1] = n1;
    state[2] = n2;
}

fn partial_round(spec: &PoseidonSpec, state: &mut [Fr; 3], rc: &[Fr; 3]) {
    let u0 = state[0] + rc[0];
    let u1 = state[1] + rc[1];
    let u2 = state[2] + rc[2];

    // partial S-box on lane 0 (verify this matches your parameterization)
    let v0 = pow17(u0);
    let v1 = u1;
    let v2 = u2;

    let n0 = spec.mds[0][0] * v0 + spec.mds[0][1] * v1 + spec.mds[0][2] * v2;
    let n1 = spec.mds[1][0] * v0 + spec.mds[1][1] * v1 + spec.mds[1][2] * v2;
    let n2 = spec.mds[2][0] * v0 + spec.mds[2][1] * v1 + spec.mds[2][2] * v2;

    state[0] = n0;
    state[1] = n1;
    state[2] = n2;
}

pub fn hash2(spec: &PoseidonSpec, x0: Fr, x1: Fr) -> Fr {
    // Sponge layout: [capacity, rate0, rate1] for WIDTH = 3, RATE = 2, CAPACITY = 1
    let mut state = [Fr::ZERO; 3];

    // absorb x0, x1
    state[1] += x0;
    state[2] += x1;
    permute(spec, &mut state);

    // squeeze first rate element
    state[1]
}

#[cfg(test)]
mod tests {
    use crate::poseidon::spec::{CAPACITY, RATE};

    use super::*;
    use ark_ff::Field;

    use ark_crypto_primitives::sponge::{
        CryptographicSponge,
        poseidon::{PoseidonConfig, PoseidonSponge},
    };

    fn poseidon_config_from_spec(spec: &PoseidonSpec) -> PoseidonConfig<Fr> {
        let ark: Vec<Vec<Fr>> = spec.round_constants.iter().map(|r| r.to_vec()).collect();
        let mds: Vec<Vec<Fr>> = spec.mds.iter().map(|r| r.to_vec()).collect();
        PoseidonConfig::new(
            spec.full_rounds,
            spec.partial_rounds,
            spec.alpha,
            mds,
            ark,
            RATE,
            CAPACITY,
        )
    }

    #[test]
    fn hash2_is_deterministic() {
        let spec = PoseidonSpec::default();
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);
        let h1 = hash2(&spec, x0, x1);
        let h2 = hash2(&spec, x0, x1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash2_changes_when_input_changes() {
        let spec = PoseidonSpec::default();
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);
        let h1 = hash2(&spec, x0, x1);
        let h2 = hash2(&spec, x0 + Fr::ONE, x1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash2_matches_arkworks() {
        let spec = PoseidonSpec::default(); // or whatever returns your PoseidonSpec
        let cfg = poseidon_config_from_spec(&spec);
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);

        let mut sponge = PoseidonSponge::new(&cfg);
        sponge.absorb(&x0);
        sponge.absorb(&x1);
        let expected = sponge.squeeze_field_elements::<Fr>(1)[0];

        assert_eq!(hash2(&spec, x0, x1), expected);
    }
}
