use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, Variable};
use hash_preimage::sponge::gadget::{SpongeGadget, State};
use merkle_membership::merkle::gadget::compute_root;

use crate::{
    commitment::{
        gadget::create_commitment,
        spec::{LeafData, LeafState},
    },
    nullifier::gadget::derive_nullifier,
};

pub struct NullifierCircuit<const T: usize> {
    // Witnesses
    secret: Option<Fr>,
    balance: Option<Fr>,
    salt: Option<Fr>,
    nonce: Option<Fr>,
    index_bits: Option<[Fr; T]>,
    path: Option<[Fr; T]>,
    // Public inputs
    root: Option<Fr>,
    nullifier: Option<Fr>,
}

impl<const T: usize> NullifierCircuit<T> {
    pub fn new(
        leaf: LeafData,
        index_bits: [Fr; T],
        path: [Fr; T],
        root: Fr,
        nullifier: Fr,
    ) -> Self {
        Self {
            secret: Some(leaf.secret()),
            balance: Some(leaf.balance()),
            salt: Some(leaf.salt()),
            nonce: Some(leaf.nonce()),
            index_bits: Some(index_bits),
            path: Some(path),
            root: Some(root),
            nullifier: Some(nullifier),
        }
    }
}

impl<const T: usize> ConstraintSynthesizer<Fr> for NullifierCircuit<T> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let leaf = LeafState::new(
            State::witness(&cs, self.secret.unwrap_or_default())?,
            State::witness(&cs, self.balance.unwrap_or_default())?,
            State::witness(&cs, self.salt.unwrap_or_default())?,
            State::witness(&cs, self.nonce.unwrap_or_default())?,
        );
        let index_bits: [State; T] =
            State::witness_array(&cs, &self.index_bits.unwrap_or([Fr::ZERO; T]))?;
        let path: [State; T] = State::witness_array(&cs, &self.path.unwrap_or([Fr::ZERO; T]))?;
        let input_root = State::input(&cs, self.root.unwrap_or_default())?;
        let input_nullifier = State::input(&cs, self.nullifier.unwrap_or_default())?;

        // Enforce: bits in {0, 1}
        for b in index_bits {
            cs.enforce_constraint(
                LinearCombination::from(b.var()),
                LinearCombination::from(b.var()) + (-Fr::ONE, Variable::One),
                LinearCombination::zero(),
            )?;
        }

        let commitment = create_commitment(&cs, &leaf)?;
        let sponge = SpongeGadget::default();
        let computed_root = compute_root(&cs, &sponge, commitment, &path, &index_bits)?;

        // Enforce: derived nullifier = input nullifier
        cs.enforce_constraint(
            LinearCombination::from(computed_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(input_root.var()),
        )?;

        let derived_nullifier = derive_nullifier(&cs, leaf.secret(), leaf.nonce(), &index_bits)?;

        // Enforce: derived nullifier = input nullifier
        cs.enforce_constraint(
            LinearCombination::from(derived_nullifier.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(input_nullifier.var()),
        )?;

        Ok(())
    }
}
