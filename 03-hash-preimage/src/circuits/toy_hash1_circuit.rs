use crate::circuits::toy_hash_gadget::permute_gadget;
use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct ToyHash1Circuit {
    x: Option<Fr>, // private
    h: Option<Fr>, // public
}

impl ToyHash1Circuit {
    fn new(x: Option<Fr>, h: Option<Fr>) -> Self {
        Self { x, h }
    }
}

impl ConstraintSynthesizer<Fr> for ToyHash1Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let setup = cs.is_in_setup_mode();
        let x = if setup {
            Fr::ZERO
        } else {
            self.x.ok_or(SynthesisError::AssignmentMissing)?
        };
        let h = if setup {
            Fr::ZERO
        } else {
            self.h.ok_or(SynthesisError::AssignmentMissing)?
        };
        let s0 = x;
        let s1 = Fr::ZERO;
        let mut s0_var = cs.new_witness_variable(|| Ok(s0))?;
        let s1_var = cs.new_witness_variable(|| Ok(s1))?;
        let h_var = cs.new_input_variable(|| Ok(h))?;

        cs.enforce_constraint(
            LinearCombination::from(s1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        (s0_var, _, _, _) = permute_gadget(&cs, s0_var, s1_var, s0, s1)?;

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

    fn create_circuits() -> (ToyHash1Circuit, ToyHash1Circuit) {
        let x = Fr::from(7u64);
        let h = toy_hash::native::hash(x);
        let setup_circuit = ToyHash1Circuit::new(None, None);
        let prove_circuit = ToyHash1Circuit::new(Some(x), Some(h));

        (setup_circuit, prove_circuit)
    }

    fn prove(pk: ProvingKey<Bls12_381>, circuit: ToyHash1Circuit) -> ark_groth16::Proof<Bls12_381> {
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut test_rng())
            .unwrap()
    }

    fn setup(circuit: ToyHash1Circuit) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        (pk, vk)
    }

    #[test]
    fn toy_hash1_valid() {
        let (sc, pc) = create_circuits();
        let public_inputs = &[pc.h.unwrap()];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
    }

    #[test]
    fn toy_hash1_wrong_public() {
        let (sc, pc) = create_circuits();
        let wrong_public_inputs = &[Fr::from(1)];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
    }

    #[test]
    fn toy_hash1_wrong_witness() {
        let x = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = toy_hash::native::hash(x);
        let prove_circuit = ToyHash1Circuit::new(Some(x1), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
