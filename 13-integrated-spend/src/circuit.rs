use ark_bls12_381::Fr;
use ark_relations::r1cs::ConstraintSynthesizer;
use hash_preimage::sponge::gadget::State;

pub struct IntegratedSpendCircuit {
    old_state_root: Fr,
    new_state_root: Fr,
    old_nullifier_root: Fr,
    new_nullifier_root: Fr,
    nullifier: Fr,
}

impl ConstraintSynthesizer<Fr> for IntegratedSpendCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let old_state_root = State::input(&cs, self.old_state_root)?;
        let new_state_root = State::input(&cs, self.new_state_root)?;
        let old_nullifier_root = State::input(&cs, self.old_nullifier_root)?;
        let new_nullifier_root = State::input(&cs, self.new_nullifier_root)?;
        let nullifier = State::input(&cs, self.nullifier)?;

        Ok(())
    }
}
