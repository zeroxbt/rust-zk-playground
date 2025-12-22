use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::merkle::spec::{DEPTH, MERKLE_NODE_DST};
use ark_ff::Field;

pub fn compute_root(
    cs: &ConstraintSystemRef<Fr>,
    sponge: &SpongeGadget<PoseidonPermutation, 3, 2>,
    leaf: State,
    path: &[State; DEPTH],
    index_bits: &[State; DEPTH],
) -> Result<State, SynthesisError> {
    let mut cur = leaf;
    for (&sib, &b) in path.iter().zip(index_bits.iter()) {
        enforce_bit(cs, b)?;
        let (left, right) = conditional_swap(cs, cur, sib, b)?;
        cur = sponge.hash_with_dst(cs, &[left, right], Some(MERKLE_NODE_DST), 1)?;
    }

    Ok(cur)
}
/// Enforce boolean: b * (b - 1) = 0
pub fn enforce_bit(cs: &ConstraintSystemRef<Fr>, b: State) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        LinearCombination::from(b.var()) - (Fr::ONE, Variable::One),
        LinearCombination::<Fr>::zero(),
    )?;
    Ok(())
}

/// Conditional swap using one multiplication:
///   m = b * (sib - cur)
///   left  = cur + m
///   right = sib - m
pub fn conditional_swap(
    cs: &ConstraintSystemRef<Fr>,
    cur: State,
    sib: State,
    b: State,
) -> Result<(State, State), SynthesisError> {
    // Enforce: b * (sib - cur) = m
    let t_lc = LinearCombination::from(sib.var()) + (-Fr::ONE, cur.var());
    let m = State::witness(cs, b.val() * (sib.val() - cur.val()))?;
    cs.enforce_constraint(
        LinearCombination::from(b.var()),
        t_lc,
        LinearCombination::from(m.var()),
    )?;

    // Enforce: left = cur + m
    let left = State::witness(cs, cur.val() + m.val())?;
    cs.enforce_constraint(
        LinearCombination::from(cur.var()) + (Fr::ONE, m.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(left.var()),
    )?;

    // Enforce: right = sib - m
    let right = State::witness(cs, sib.val() - m.val())?;
    cs.enforce_constraint(
        LinearCombination::from(sib.var()) + (-Fr::ONE, m.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(right.var()),
    )?;

    Ok((left, right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, UniformRand};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    #[test]
    fn conditional_swap_b0_yields_left_cur_right_sib() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        let cur_v = Fr::rand(&mut rng);
        let sib_v = Fr::rand(&mut rng);
        let b_v = Fr::ZERO;

        let cur = State::witness(&cs, cur_v).unwrap();
        let sib = State::witness(&cs, sib_v).unwrap();
        let b = State::witness(&cs, b_v).unwrap();

        enforce_bit(&cs, b).unwrap();
        let (left, right) = conditional_swap(&cs, cur, sib, b).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(left.val(), cur_v);
        assert_eq!(right.val(), sib_v);
    }

    #[test]
    fn conditional_swap_b1_yields_left_sib_right_cur() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        let cur_v = Fr::rand(&mut rng);
        let sib_v = Fr::rand(&mut rng);
        let b_v = Fr::ONE;

        let cur = State::witness(&cs, cur_v).unwrap();
        let sib = State::witness(&cs, sib_v).unwrap();
        let b = State::witness(&cs, b_v).unwrap();

        enforce_bit(&cs, b).unwrap();
        let (left, right) = conditional_swap(&cs, cur, sib, b).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(left.val(), sib_v);
        assert_eq!(right.val(), cur_v);
    }

    #[test]
    fn enforce_bit_rejects_non_boolean() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = State::witness(&cs, Fr::from(2u64)).unwrap();

        enforce_bit(&cs, b).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn conditional_swap_unsatisfied_if_b_non_boolean_even_if_values_match_formula() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        let cur_v = Fr::rand(&mut rng);
        let sib_v = Fr::rand(&mut rng);
        let b_v = Fr::from(2u64);

        let cur = State::witness(&cs, cur_v).unwrap();
        let sib = State::witness(&cs, sib_v).unwrap();
        let b = State::witness(&cs, b_v).unwrap();

        enforce_bit(&cs, b).unwrap();
        let _ = conditional_swap(&cs, cur, sib, b).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn conditional_swap_detects_inconsistent_witness_when_left_is_tampered() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        let cur_v = Fr::rand(&mut rng);
        let sib_v = Fr::rand(&mut rng);
        let b_v = Fr::ONE;

        let cur = State::witness(&cs, cur_v).unwrap();
        let sib = State::witness(&cs, sib_v).unwrap();
        let b = State::witness(&cs, b_v).unwrap();

        enforce_bit(&cs, b).unwrap();

        // Build constraints similarly to conditional_swap but sabotage left witness.
        let t_lc = LinearCombination::from(sib.var()) + (-Fr::ONE, cur.var());
        let m = State::witness(&cs, b_v * (sib_v - cur_v)).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(b.var()),
            t_lc,
            LinearCombination::from(m.var()),
        )
        .unwrap();

        let wrong_left = State::witness(&cs, Fr::rand(&mut rng)).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(cur.var()) + (Fr::ONE, m.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(wrong_left.var()),
        )
        .unwrap();

        let right = State::witness(&cs, sib_v - m.val()).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(sib.var()) + (-Fr::ONE, m.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(right.var()),
        )
        .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
