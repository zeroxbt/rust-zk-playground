use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};
use merkle_membership::merkle::gadget::compute_root;

use crate::smt::spec::{DEFAULT_LEAF, index_bits};

pub fn verify_non_membership<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    root: State,
    nullifier: State,
    path: &[State; D],
) -> Result<(), SynthesisError> {
    let index_bits = nullifier_to_index_bits(cs, nullifier)?;
    let default_leaf = State::witness(cs, DEFAULT_LEAF)?;
    cs.enforce_constraint(
        LinearCombination::from(default_leaf.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::zero(),
    )?;

    let computed_root = compute_root(
        cs,
        &SpongeGadget::<PoseidonPermutation, 3, 2>::default(),
        default_leaf,
        path,
        &index_bits,
    )?;

    cs.enforce_constraint(
        LinearCombination::from(computed_root.var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(root.var()),
    )?;

    Ok(())
}

pub fn nullifier_to_index_bits<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    nullifier: State,
) -> Result<[State; D], SynthesisError> {
    let index_bits = index_bits::<D>(nullifier.val()).map(|b| if b { Fr::ONE } else { Fr::ZERO });
    let index_bits: [State; D] = State::witness_array(cs, &index_bits)?;
    let mut lc = LinearCombination::zero();
    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    for bit in index_bits {
        lc += (pow2, bit.var());

        pow2 *= two;
    }

    cs.enforce_constraint(
        lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(nullifier.var()),
    )?;

    Ok(index_bits)
}
