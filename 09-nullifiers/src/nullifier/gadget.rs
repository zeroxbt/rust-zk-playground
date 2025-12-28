use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::nullifier::spec::NULLIFIER_DST;

pub fn derive_nullifier<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    secret: State,
    index_bits: &[State; T],
) -> Result<State, SynthesisError> {
    let sponge = SpongeGadget::<PoseidonPermutation, 3, 2>::default();

    sponge.hash_with_dst(
        cs,
        &[secret, bits_to_field(cs, index_bits)?],
        Some(NULLIFIER_DST),
        1,
    )
}

pub fn bits_to_field(
    cs: &ConstraintSystemRef<Fr>,
    bits: &[State],
) -> Result<State, SynthesisError> {
    let mut result_val = Fr::ZERO;
    let mut result_lc = LinearCombination::zero();
    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    for bit in bits {
        result_val += pow2 * bit.val();
        result_lc += (pow2, bit.var());

        pow2 *= two;
    }

    let result = State::witness(cs, result_val)?;
    cs.enforce_constraint(
        result_lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(result.var()),
    )?;

    Ok(result)
}
