use crate::poseidon::spec::{PoseidonSpec, RATE, WIDTH};
use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};

pub fn permute(spec: &PoseidonSpec, state: &mut [Fr; 3]) {
    assert!(spec.full_rounds.is_multiple_of(2));
    assert_eq!(spec.ark.len(), spec.full_rounds + spec.partial_rounds);

    let (first_full, rest) = spec.ark.split_at(spec.full_rounds / 2);
    let (partial, last_full) = rest.split_at(spec.partial_rounds);

    for rc in first_full {
        apply_ark(state, rc);
        apply_s_box(spec, state, true);
        apply_mds(spec, state);
    }
    for rc in partial {
        apply_ark(state, rc);
        apply_s_box(spec, state, false);
        apply_mds(spec, state);
    }
    for rc in last_full {
        apply_ark(state, rc);
        apply_s_box(spec, state, true);
        apply_mds(spec, state);
    }
}

fn apply_ark(state: &mut [Fr; 3], rc: &[Fr; 3]) {
    for (i, state_elem) in state.iter_mut().enumerate() {
        *state_elem += rc[i];
    }
}

fn apply_s_box(spec: &PoseidonSpec, state: &mut [Fr; 3], is_full_round: bool) {
    if is_full_round {
        for state_elem in state {
            *state_elem = state_elem.pow([spec.alpha]);
        }
    } else {
        state[0] = state[0].pow([spec.alpha]);
    }
}

fn apply_mds(spec: &PoseidonSpec, state: &mut [Fr; 3]) {
    let state_snapshot = *state;
    for (i, state_elem) in state.iter_mut().enumerate() {
        let mut acc = Fr::ZERO;
        for (j, snapshot_elem) in state_snapshot.iter().enumerate() {
            acc += spec.mds[i][j] * snapshot_elem;
        }
        *state_elem = acc;
    }
}

pub fn hash(spec: &PoseidonSpec, x: Vec<Fr>) -> Fr {
    // Sponge layout: [capacity, rate0, rate1] for WIDTH = 3, RATE = 2, CAPACITY = 1
    let mut state = [Fr::ZERO; WIDTH];

    for chunk in x.chunks(RATE) {
        // absorb RATE elements
        for (lane, val) in chunk.iter().enumerate() {
            state[lane + 1] += val;
        }
        permute(spec, &mut state);
    }

    // squeeze
    state[1]
}

#[cfg(test)]
mod tests {
    use crate::poseidon::spec::{CAPACITY, POSEIDON_SPEC, RATE};

    use super::*;
    use ark_ff::Field;

    use ark_crypto_primitives::sponge::{
        CryptographicSponge,
        poseidon::{PoseidonConfig, PoseidonSponge},
    };

    fn poseidon_config_from_spec(spec: &PoseidonSpec) -> PoseidonConfig<Fr> {
        let ark: Vec<Vec<Fr>> = spec.ark.iter().map(|r| r.to_vec()).collect();
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
    fn hash_is_deterministic() {
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);
        let h1 = hash(&POSEIDON_SPEC, vec![x0, x1]);
        let h2 = hash(&POSEIDON_SPEC, vec![x0, x1]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_changes_when_input_changes() {
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);
        let h1 = hash(&POSEIDON_SPEC, vec![x0, x1]);
        let h2 = hash(&POSEIDON_SPEC, vec![x0 + Fr::ONE, x1]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_matches_arkworks() {
        // or whatever returns your PoseidonSpec
        let cfg = poseidon_config_from_spec(&POSEIDON_SPEC);
        let x0 = Fr::from(1u64);
        let x1 = Fr::from(2u64);

        let mut sponge = PoseidonSponge::new(&cfg);
        sponge.absorb(&x0);
        sponge.absorb(&x1);
        let expected = sponge.squeeze_field_elements::<Fr>(1)[0];

        assert_eq!(hash(&POSEIDON_SPEC, vec![x0, x1]), expected);
    }
}
