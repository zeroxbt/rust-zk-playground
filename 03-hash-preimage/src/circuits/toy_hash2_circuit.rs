use crate::{circuits::toy_hash_gadget::permute_gadget, toy_hash::spec::DST_HASH2};
use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct ToyHash2Circuit {
    x0: Option<Fr>, // private
    x1: Option<Fr>, // private
    h: Option<Fr>,  // public
}

impl ToyHash2Circuit {
    fn new(x0: Option<Fr>, x1: Option<Fr>, h: Option<Fr>) -> Self {
        Self { x0, x1, h }
    }
}

impl ConstraintSynthesizer<Fr> for ToyHash2Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let setup = cs.is_in_setup_mode();
        let x0 = if setup {
            Fr::ZERO
        } else {
            self.x0.ok_or(SynthesisError::AssignmentMissing)?
        };
        let x1 = if setup {
            Fr::ZERO
        } else {
            self.x1.ok_or(SynthesisError::AssignmentMissing)?
        };
        let h = if setup {
            Fr::ZERO
        } else {
            self.h.ok_or(SynthesisError::AssignmentMissing)?
        };

        let mut s0 = Fr::ZERO;
        let mut s1 = DST_HASH2;

        let mut s0_var = cs.new_witness_variable(|| Ok(s0))?;
        let mut s1_var = cs.new_witness_variable(|| Ok(s1))?;
        let x0_var = cs.new_witness_variable(|| Ok(x0))?;
        let x1_var = cs.new_witness_variable(|| Ok(x1))?;

        // Enforce: s0 = 0
        cs.enforce_constraint(
            LinearCombination::from(s0_var),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;
        // Enforce: s1 = DST_HASH2
        cs.enforce_constraint(
            LinearCombination::from(s1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from((s1, Variable::One)),
        )?;

        let s0_old_var = s0_var;
        s0 += x0;
        s0_var = cs.new_witness_variable(|| Ok(s0))?;
        // Enforce: s0 = s0 + x0
        cs.enforce_constraint(
            LinearCombination::from(s0_old_var) + (Fr::ONE, x0_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(s0_var),
        )?;

        (s0_var, s1_var, s0, s1) = permute_gadget(&cs, s0_var, s1_var, s0, s1)?;

        let s0_old_var = s0_var;
        s0 += x1;
        s0_var = cs.new_witness_variable(|| Ok(s0))?;
        // Enforce: s0 = s0 + x1
        cs.enforce_constraint(
            LinearCombination::from(s0_old_var) + (Fr::ONE, x1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(s0_var),
        )?;

        (s0_var, _, _, _) = permute_gadget(&cs, s0_var, s1_var, s0, s1)?;

        let h_var = cs.new_input_variable(|| Ok(h))?;
        // Enforce: h = s0
        cs.enforce_constraint(
            LinearCombination::from(s0_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(h_var),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::toy_hash;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};

    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn create_circuits() -> (ToyHash2Circuit, ToyHash2Circuit) {
        let x0 = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = toy_hash::native::hash2(x0, x1);
        let setup_circuit = ToyHash2Circuit::new(None, None, None);
        let prove_circuit = ToyHash2Circuit::new(Some(x0), Some(x1), Some(h));

        (setup_circuit, prove_circuit)
    }

    fn prove(pk: ProvingKey<Bls12_381>, circuit: ToyHash2Circuit) -> ark_groth16::Proof<Bls12_381> {
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut test_rng())
            .unwrap()
    }

    fn setup(circuit: ToyHash2Circuit) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        (pk, vk)
    }

    #[test]
    fn toy_hash2_valid() {
        let (sc, pc) = create_circuits();
        let public_inputs = &[pc.h.unwrap()];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
    }

    #[test]
    fn toy_hash2_wrong_public() {
        let (sc, pc) = create_circuits();
        let wrong_public_inputs = &[Fr::from(1)];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
    }

    #[test]
    fn toy_hash2_wrong_witnesses() {
        let x0 = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = toy_hash::native::hash2(x0, x1);
        let x_wrong = Fr::from(6u64);

        let prove_circuit = ToyHash2Circuit::new(Some(x_wrong), Some(x1), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());

        let prove_circuit = ToyHash2Circuit::new(Some(x0), Some(x_wrong), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
