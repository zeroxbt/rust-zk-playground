use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Variable,
};
use hash_preimage::sponge::gadget::State;

use crate::sorted::gadget::verify_sorted_non_membership;

pub struct SortedNonMembershipCircuit<const T: usize> {
    nullifier: Option<Fr>,
    lower: Option<Fr>,
    upper: Option<Fr>,
}

impl<const T: usize> SortedNonMembershipCircuit<T> {
    pub fn new(nullifier: Option<Fr>, lower: Option<Fr>, upper: Option<Fr>) -> Self {
        Self {
            nullifier,
            lower,
            upper,
        }
    }
}

impl<const T: usize> ConstraintSynthesizer<Fr> for SortedNonMembershipCircuit<T> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let nullifier = State::input(&cs, self.nullifier.unwrap_or_default())?;
        let lower = State::witness(&cs, self.lower.unwrap_or_default())?;
        let upper = State::witness(&cs, self.upper.unwrap_or_default())?;

        let nullifier_bits: [State; T] = state_to_index_bits(&cs, nullifier)?;
        let lower_bits = state_to_index_bits(&cs, lower)?;
        let upper_bits = state_to_index_bits(&cs, upper)?;

        verify_sorted_non_membership(&cs, &nullifier_bits, &lower_bits, &upper_bits)
    }
}

pub fn state_to_index_bits<const D: usize>(
    cs: &ConstraintSystemRef<Fr>,
    state: State,
) -> ark_relations::r1cs::Result<[State; D]> {
    let bits = state.val().into_bigint().to_bits_le();
    let mut index_bits = [false; D];
    index_bits.copy_from_slice(&bits[..D]);
    let index_bits = index_bits.map(|b| if b { Fr::ONE } else { Fr::ZERO });
    let mut index_bits: [State; D] = State::witness_array(cs, &index_bits)?;
    let mut lc = LinearCombination::zero();
    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    for bit in index_bits {
        // bit * (1 - bit) = 0
        cs.enforce_constraint(
            LinearCombination::from(bit.var()),
            LinearCombination::from(Variable::One) + (-Fr::ONE, bit.var()),
            LinearCombination::zero(),
        )?;
        lc += (pow2, bit.var());
        pow2 *= two;
    }

    cs.enforce_constraint(
        lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(state.var()),
    )?;

    index_bits.reverse();
    Ok(index_bits)
}
