use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct ChainedCircuit<F: Field> {
    pub a: Option<F>, // private
    pub b: Option<F>, // private
    pub c: Option<F>, // private
    pub d: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for ChainedCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_witness_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        let d_var = cs.new_input_variable(|| self.d.ok_or(SynthesisError::AssignmentMissing))?;

        // temp = a * b
        let tmp_var = cs.new_witness_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // Enforce: a * b = tmp
        cs.enforce_constraint(
            LinearCombination::from(a_var),
            LinearCombination::from(b_var),
            LinearCombination::from(tmp_var),
        )?;

        // Enforce: tmp + c = d  => (tmp + c) * 1 = d
        let left: LinearCombination<F> =
            LinearCombination::from(tmp_var) + LinearCombination::from(c_var);
        let right: LinearCombination<F> = LinearCombination::from(Variable::One);
        let output: LinearCombination<F> = LinearCombination::from(d_var);

        cs.enforce_constraint(left, right, output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ChainedCircuit;
    use crate::{Curve, Fr};
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_std::test_rng;

    fn prove(
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> (
        Fr,
        ark_groth16::Proof<Curve>,
        ark_groth16::PreparedVerifyingKey<Curve>,
    ) {
        let mut setup_rng = test_rng();
        let mut proof_rng = test_rng();

        let params = Groth16::<Curve>::generate_random_parameters_with_reduction(
            ChainedCircuit {
                a: None,
                b: None,
                c: None,
                d: None,
            },
            &mut setup_rng,
        )
        .unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        let proof = Groth16::<Curve>::create_random_proof_with_reduction(
            ChainedCircuit {
                a: Some(Fr::from(a)),
                b: Some(Fr::from(b)),
                c: Some(Fr::from(c)),
                d: Some(Fr::from(d)),
            },
            &params,
            &mut proof_rng,
        )
        .unwrap();

        (Fr::from(d), proof, pvk)
    }

    #[test]
    fn chained_succeeds() {
        let (d, proof, pvk) = prove(6, 7, 8, 50);
        assert!(Groth16::<Curve>::verify_proof(&pvk, &proof, &[d]).unwrap());
    }

    #[test]
    fn chained_rejects_wrong_public_input() {
        let (_d, proof, pvk) = prove(6, 7, 8, 50);
        assert!(!Groth16::<Curve>::verify_proof(&pvk, &proof, &[Fr::from(49)]).unwrap());
    }
}
