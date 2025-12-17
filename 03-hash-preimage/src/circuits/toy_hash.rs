use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct ToyHashCircuit<F: PrimeField> {
    x: Option<F>,                 // private
    h: Option<F>,                 // public
    round_constants: Vec<Vec<F>>, // public
    mds: Vec<Vec<F>>,             // public
}

impl<F: PrimeField> ToyHashCircuit<F> {
    fn new(x: Option<F>, h: Option<F>) -> Self {
        Self {
            x,
            h,
            round_constants: vec![
                vec![F::from(2), F::from(7)],
                vec![F::from(4), F::from(18)],
                vec![F::from(5), F::from(6)],
            ],
            mds: vec![vec![F::from(3), F::from(8)], vec![F::from(4), F::from(5)]],
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ToyHashCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let setup = cs.is_in_setup_mode();
        let x = if setup {
            F::zero()
        } else {
            self.x.ok_or(SynthesisError::AssignmentMissing)?
        };
        let h = if setup {
            F::zero()
        } else {
            self.h.ok_or(SynthesisError::AssignmentMissing)?
        };
        let mut s0 = x;
        let mut s1 = F::zero();
        let mut s0_var = cs.new_witness_variable(|| Ok(s0))?;
        let mut s1_var = cs.new_witness_variable(|| Ok(s1))?;
        let h_var = cs.new_input_variable(|| Ok(h))?;

        if self.round_constants.len() != 3
            || self.round_constants.iter().any(|v| v.len() != 2)
            || self.mds.len() != 2
            || self.mds.iter().any(|v| v.len() != 2)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        cs.enforce_constraint(
            LinearCombination::from(s1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        for round_constants in self.round_constants {
            let c0 = round_constants[0];
            let c1 = round_constants[1];
            let u0 = s0 + c0;
            let u1 = s1 + c1;

            // add round constants
            let u0_var = cs.new_witness_variable(|| Ok(u0))?;
            let u1_var = cs.new_witness_variable(|| Ok(u1))?;
            cs.enforce_constraint(
                LinearCombination::from(s0_var) + (c0, Variable::One),
                LinearCombination::from(Variable::One),
                LinearCombination::from(u0_var),
            )?;
            cs.enforce_constraint(
                LinearCombination::from(s1_var) + (c1, Variable::One),
                LinearCombination::from(Variable::One),
                LinearCombination::from(u1_var),
            )?;

            // s-box u^5 (mirrors circuit)
            let u0_2 = u0 * u0;
            let u0_2_var = cs.new_witness_variable(|| Ok(u0_2))?;
            cs.enforce_constraint(
                LinearCombination::from(u0_var),
                LinearCombination::from(u0_var),
                LinearCombination::from(u0_2_var),
            )?;
            let u0_4 = u0_2 * u0_2;
            let u0_4_var = cs.new_witness_variable(|| Ok(u0_4))?;
            cs.enforce_constraint(
                LinearCombination::from(u0_2_var),
                LinearCombination::from(u0_2_var),
                LinearCombination::from(u0_4_var),
            )?;
            let v0 = u0_4 * u0;
            let v0_var = cs.new_witness_variable(|| Ok(v0))?;
            cs.enforce_constraint(
                LinearCombination::from(u0_4_var),
                LinearCombination::from(u0_var),
                LinearCombination::from(v0_var),
            )?;

            let u1_2 = u1 * u1;
            let u1_2_var = cs.new_witness_variable(|| Ok(u1_2))?;
            cs.enforce_constraint(
                LinearCombination::from(u1_var),
                LinearCombination::from(u1_var),
                LinearCombination::from(u1_2_var),
            )?;
            let u1_4 = u1_2 * u1_2;
            let u1_4_var = cs.new_witness_variable(|| Ok(u1_4))?;
            cs.enforce_constraint(
                LinearCombination::from(u1_2_var),
                LinearCombination::from(u1_2_var),
                LinearCombination::from(u1_4_var),
            )?;
            let v1 = u1_4 * u1;
            let v1_var = cs.new_witness_variable(|| Ok(v1))?;
            cs.enforce_constraint(
                LinearCombination::from(u1_4_var),
                LinearCombination::from(u1_var),
                LinearCombination::from(v1_var),
            )?;

            // linear mixing
            s0 = self.mds[0][0] * v0 + self.mds[0][1] * v1;
            s1 = self.mds[1][0] * v0 + self.mds[1][1] * v1;

            s0_var = cs.new_witness_variable(|| Ok(s0))?;
            s1_var = cs.new_witness_variable(|| Ok(s1))?;
            cs.enforce_constraint(
                LinearCombination::from((self.mds[0][0], v0_var)) + (self.mds[0][1], v1_var),
                LinearCombination::from(Variable::One),
                LinearCombination::from(s0_var),
            )?;
            cs.enforce_constraint(
                LinearCombination::from((self.mds[1][0], v0_var)) + (self.mds[1][1], v1_var),
                LinearCombination::from(Variable::One),
                LinearCombination::from(s1_var),
            )?;
        }

        cs.enforce_constraint(
            LinearCombination::from(s0_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(h_var),
        )?;

        Ok(())
    }
}

pub fn toy_hash(x: Fr) -> Fr {
    let round_constants = [
        [Fr::from(2), Fr::from(7)],
        [Fr::from(4), Fr::from(18)],
        [Fr::from(5), Fr::from(6)],
    ];
    let mds = [[Fr::from(3), Fr::from(8)], [Fr::from(4), Fr::from(5)]];

    // absorb
    let mut s0 = x;
    let mut s1 = Fr::ZERO;

    for [c0, c1] in round_constants {
        // add round constants
        let u0 = s0 + c0;
        let u1 = s1 + c1;

        // s-box u^5 (mirrors circuit)
        let u0_2 = u0 * u0;
        let u0_4 = u0_2 * u0_2;
        let v0 = u0_4 * u0;

        let u1_2 = u1 * u1;
        let u1_4 = u1_2 * u1_2;
        let v1 = u1_4 * u1;

        // linear mixing
        s0 = mds[0][0] * v0 + mds[0][1] * v1;
        s1 = mds[1][0] * v0 + mds[1][1] * v1;
    }

    // squeeze
    s0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};

    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn create_circuits() -> (ToyHashCircuit<Fr>, ToyHashCircuit<Fr>) {
        let x = Fr::from(7u64);
        let h = toy_hash(x);
        let setup_circuit = ToyHashCircuit::new(None, None);
        let prove_circuit = ToyHashCircuit::new(Some(x), Some(h));

        (setup_circuit, prove_circuit)
    }

    fn prove(
        pk: ProvingKey<Bls12_381>,
        circuit: ToyHashCircuit<Fr>,
    ) -> ark_groth16::Proof<Bls12_381> {
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut test_rng())
            .unwrap()
    }

    fn setup(
        circuit: ToyHashCircuit<Fr>,
    ) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        (pk, vk)
    }

    #[test]
    fn toy_hash_valid() {
        let (sc, pc) = create_circuits();
        let public_inputs = &[pc.h.unwrap()];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
    }

    #[test]
    fn toy_hash_wrong_public() {
        let (sc, pc) = create_circuits();
        let wrong_public_inputs = &[Fr::from(1)];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
    }

    #[test]
    fn wrong_witness() {
        let x = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = toy_hash(x);
        let prove_circuit = ToyHashCircuit::new(Some(x1), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
