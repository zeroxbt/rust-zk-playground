use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};
use merkle_membership::merkle::gadget::compute_root;

use crate::smt::spec::{DEFAULT_LEAF, NULLIFIER_MARKER, SmtNonMembershipProofVar};

pub fn verify_non_membership<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    root: State,
    proof: &SmtNonMembershipProofVar<D>,
) -> Result<(), SynthesisError> {
    let index_bits = nullifier_to_index_bits(cs, proof.nullifier())?;
    let default_leaf = State::witness(cs, DEFAULT_LEAF)?;
    cs.enforce_constraint(
        LinearCombination::from(default_leaf.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from((DEFAULT_LEAF, Variable::One)),
    )?;

    let computed_root = compute_root(
        cs,
        &SpongeGadget::<PoseidonPermutation, 3, 2>::default(),
        default_leaf,
        proof.path(),
        &index_bits,
    )?;

    cs.enforce_constraint(
        LinearCombination::from(computed_root.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(root.var()),
    )?;

    Ok(())
}

pub fn verify_membership<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    root: State,
    proof: &SmtNonMembershipProofVar<D>,
) -> Result<(), SynthesisError> {
    let index_bits = nullifier_to_index_bits(cs, proof.nullifier())?;
    let marker_leaf = State::witness(cs, NULLIFIER_MARKER)?;
    cs.enforce_constraint(
        LinearCombination::from(marker_leaf.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from((NULLIFIER_MARKER, Variable::One)),
    )?;

    let computed_root = compute_root(
        cs,
        &SpongeGadget::<PoseidonPermutation, 3, 2>::default(),
        marker_leaf,
        proof.path(),
        &index_bits,
    )?;

    cs.enforce_constraint(
        LinearCombination::from(computed_root.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(root.var()),
    )?;

    Ok(())
}

pub fn to_bits_le_fixed(
    cs: &ConstraintSystemRef<Fr>,
    s: State,
) -> Result<[State; 256], SynthesisError> {
    let val_bigint = s.val().into_bigint();
    let bits_le = val_bigint.to_bits_le();
    // Build weighted sum Σ b_i * 2^i
    let mut acc = LinearCombination::<Fr>::zero();

    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    let mut b_states = [State::zero(); 256];

    for (i, b) in b_states.iter_mut().enumerate() {
        let &b_val = bits_le.get(i).ok_or(SynthesisError::AssignmentMissing)?;
        let b_val = if b_val { Fr::ONE } else { Fr::ZERO };
        *b = State::witness(cs, b_val)?;

        cs.enforce_constraint(
            LinearCombination::from(b.var()),
            LinearCombination::from(b.var()) - (Fr::ONE, Variable::One),
            LinearCombination::zero(),
        )?;

        acc += (pow2, b.var());
        pow2 *= two;
    }

    cs.enforce_constraint(
        acc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(s.var()),
    )?;

    Ok(b_states)
}

pub fn nullifier_to_index_bits<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    nullifier: State,
) -> Result<[State; D], SynthesisError> {
    assert!(D <= 256);

    let bits_256 = to_bits_le_fixed(cs, nullifier)?;

    let index_bits: [State; D] = std::array::from_fn(|i| bits_256[i]);

    Ok(index_bits)
}
