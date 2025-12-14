use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};

#[derive(Clone, Debug)]
pub struct MulCircuit<F: Field> {
    pub a: Option<F>, // private
    pub b: Option<F>, // private
    pub c: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

        let left: LinearCombination<F> = LinearCombination::from(a_var);
        let right: LinearCombination<F> = LinearCombination::from(b_var);
        let output: LinearCombination<F> = LinearCombination::from(c_var);

        cs.enforce_constraint(left, right, output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MulCircuit;
    use crate::{Curve, Fr};
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_std::test_rng;

    fn prove(
        a: u64,
        b: u64,
        c: u64,
    ) -> (
        Fr,
        ark_groth16::Proof<Curve>,
        ark_groth16::PreparedVerifyingKey<Curve>,
    ) {
        let mut setup_rng = test_rng();
        let mut proof_rng = test_rng();

        let params = Groth16::<Curve>::generate_random_parameters_with_reduction(
            MulCircuit {
                a: None,
                b: None,
                c: None,
            },
            &mut setup_rng,
        )
        .unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        let proof = Groth16::<Curve>::create_random_proof_with_reduction(
            MulCircuit {
                a: Some(Fr::from(a)),
                b: Some(Fr::from(b)),
                c: Some(Fr::from(c)),
            },
            &params,
            &mut proof_rng,
        )
        .unwrap();

        (Fr::from(c), proof, pvk)
    }

    #[test]
    fn add_one_succeeds() {
        let (y, proof, pvk) = prove(6, 7, 42);
        assert!(Groth16::<Curve>::verify_proof(&pvk, &proof, &[y]).unwrap());
    }

    #[test]
    fn add_one_rejects_wrong_public_input() {
        let (_y, proof, pvk) = prove(6, 7, 42);
        assert!(!Groth16::<Curve>::verify_proof(&pvk, &proof, &[Fr::from(1)]).unwrap());
    }
}
