use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct AddOneCircuit<F: Field> {
    pub x: Option<F>, // private
    pub y: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for AddOneCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let one = F::one();
        let left: LinearCombination<F> = LinearCombination::from(x_var) + (one, Variable::One);
        let right: LinearCombination<F> = LinearCombination::from(Variable::One);
        let output: LinearCombination<F> = LinearCombination::from(y_var);

        cs.enforce_constraint(left, right, output)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AddOneCircuit;
    use crate::{Curve, Fr};
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_std::test_rng;

    fn prove(
        x: u64,
        y: u64,
    ) -> (
        Fr,
        ark_groth16::Proof<Curve>,
        ark_groth16::PreparedVerifyingKey<Curve>,
    ) {
        let mut setup_rng = test_rng();
        let mut proof_rng = test_rng();

        let params = Groth16::<Curve>::generate_random_parameters_with_reduction(
            AddOneCircuit { x: None, y: None },
            &mut setup_rng,
        )
        .unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        let proof = Groth16::<Curve>::create_random_proof_with_reduction(
            AddOneCircuit {
                x: Some(Fr::from(x)),
                y: Some(Fr::from(y)),
            },
            &params,
            &mut proof_rng,
        )
        .unwrap();

        (Fr::from(y), proof, pvk)
    }

    #[test]
    fn add_one_succeeds() {
        let (y, proof, pvk) = prove(6, 7);
        assert!(Groth16::<Curve>::verify_proof(&pvk, &proof, &[y]).unwrap());
    }

    #[test]
    fn add_one_rejects_wrong_public_input() {
        let (_y, proof, pvk) = prove(6, 7);
        assert!(!Groth16::<Curve>::verify_proof(&pvk, &proof, &[Fr::from(8)]).unwrap());
    }
}
