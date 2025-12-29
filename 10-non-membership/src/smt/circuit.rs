use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::ConstraintSynthesizer;
use hash_preimage::sponge::gadget::State;

use crate::smt::{gadget::verify_non_membership, tree::SparseMerkleTree};
pub struct NonMembershipCircuit<const D: usize> {
    // Public inputs
    pub root: Option<Fr>,
    // Private inputs
    pub nullifier: Option<Fr>,
    pub path: Option<[Fr; D]>,
}

impl<const D: usize> NonMembershipCircuit<D> {
    pub fn new(tree: &SparseMerkleTree<D>, nullifier: Fr) -> Self {
        let proof = tree.prove(nullifier);
        Self {
            root: Some(tree.root()),
            nullifier: Some(nullifier),
            path: Some(proof.path()),
        }
    }
}

impl<const D: usize> ConstraintSynthesizer<Fr> for NonMembershipCircuit<D> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let root = State::input(&cs, self.root.unwrap_or_default())?;
        let nullifier = State::witness(&cs, self.nullifier.unwrap_or_default())?;
        let path: [State; D] = State::witness_array(&cs, &self.path.unwrap_or([Fr::ZERO; D]))?;

        verify_non_membership(&cs, root, nullifier, &path)?;
        Ok(())
    }
}
