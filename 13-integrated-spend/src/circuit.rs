use ark_bls12_381::Fr;
use ark_relations::r1cs::ConstraintSynthesizer;

pub struct IntegratedSpendCircuit {}

impl ConstraintSynthesizer<Fr> for IntegratedSpendCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        Ok(())
    }
}
