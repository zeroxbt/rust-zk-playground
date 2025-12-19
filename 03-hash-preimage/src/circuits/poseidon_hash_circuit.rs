use crate::{
    circuits::poseidon_hash_gadget::{State, permute_gadget},
    poseidon::spec::{POSEIDON_SPEC, RATE, WIDTH},
};
use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct PoseidonHashCircuit {
    x: Option<Vec<Fr>>, // private
    h: Option<Fr>,      // public
}

impl PoseidonHashCircuit {
    fn new(x: Option<Vec<Fr>>, h: Option<Fr>) -> Self {
        Self { x, h }
    }
}

impl ConstraintSynthesizer<Fr> for PoseidonHashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let setup = cs.is_in_setup_mode();

        let x = if setup {
            vec![Fr::ZERO; WIDTH - 1]
        } else {
            self.x.ok_or(SynthesisError::AssignmentMissing)?
        };
        let h = if setup {
            Fr::ZERO
        } else {
            self.h.ok_or(SynthesisError::AssignmentMissing)?
        };

        let mut state: [State; WIDTH] = std::array::from_fn(|_| State {
            val: Fr::ZERO,
            var: Variable::Zero, // temporary
        });

        for s in &mut state {
            s.var = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
            cs.enforce_constraint(
                LinearCombination::from(s.var),
                LinearCombination::from(Variable::One),
                LinearCombination::zero(),
            )?;
        }

        for chunk in x.chunks(RATE) {
            for (lane, val) in chunk.iter().enumerate() {
                let idx = 1 + lane; // rate lanes
                let old_var = state[idx].var;
                state[idx].val += *val;
                let x_var = cs.new_witness_variable(|| Ok(*val))?;
                state[idx].var = cs.new_witness_variable(|| Ok(state[idx].val))?;
                cs.enforce_constraint(
                    LinearCombination::from(old_var) + (Fr::ONE, x_var),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(state[idx].var),
                )?;
            }
            permute_gadget(&POSEIDON_SPEC, &cs, &mut state)?;
        }

        let h_var = cs.new_input_variable(|| Ok(h))?;
        // Enforce: h = s1
        cs.enforce_constraint(
            LinearCombination::from(state[1].var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(h_var),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::poseidon;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};

    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn create_circuits() -> (PoseidonHashCircuit, PoseidonHashCircuit) {
        let x0 = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = poseidon::native::hash(&POSEIDON_SPEC, vec![x0, x1]);
        let setup_circuit = PoseidonHashCircuit::new(None, None);
        let prove_circuit = PoseidonHashCircuit::new(Some(vec![x0, x1]), Some(h));

        (setup_circuit, prove_circuit)
    }

    fn prove(
        pk: ProvingKey<Bls12_381>,
        circuit: PoseidonHashCircuit,
    ) -> ark_groth16::Proof<Bls12_381> {
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut test_rng())
            .unwrap()
    }

    fn setup(
        circuit: PoseidonHashCircuit,
    ) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        (pk, vk)
    }

    #[test]
    fn poseidon_valid() {
        let (sc, pc) = create_circuits();
        let public_inputs = &[pc.h.unwrap()];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
    }

    #[test]
    fn poseidon_wrong_public() {
        let (sc, pc) = create_circuits();
        let wrong_public_inputs = &[Fr::from(1)];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
    }

    #[test]
    fn poseidon_wrong_witnesses() {
        let x0 = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let h = poseidon::native::hash(&POSEIDON_SPEC, vec![x0, x1]);
        let x_wrong = Fr::from(6u64);

        let prove_circuit = PoseidonHashCircuit::new(Some(vec![x_wrong, x1]), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());

        let prove_circuit = PoseidonHashCircuit::new(Some(vec![x0, x_wrong]), Some(h));
        let cs = ConstraintSystem::<Fr>::new_ref();
        prove_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
