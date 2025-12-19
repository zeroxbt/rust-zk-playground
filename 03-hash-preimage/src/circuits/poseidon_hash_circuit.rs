use crate::{
    poseidon::{
        native::PoseidonPermutation,
        spec::{RATE, WIDTH},
    },
    sponge::gadget::SpongeGadget,
};
use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct PoseidonHashCircuit {
    x: Option<Vec<Fr>>, // private
    h: Option<Fr>,      // public
}

impl PoseidonHashCircuit {
    pub fn new(x: Option<Vec<Fr>>, h: Option<Fr>) -> Self {
        Self { x, h }
    }
}

impl ConstraintSynthesizer<Fr> for PoseidonHashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let setup = cs.is_in_setup_mode();

        // fixed length for now (e.g., 2 elements)
        let msg_len = 2usize;

        let x = if setup {
            vec![Fr::ZERO; msg_len]
        } else {
            self.x.ok_or(SynthesisError::AssignmentMissing)?
        };

        let h = if setup {
            Fr::ZERO
        } else {
            self.h.ok_or(SynthesisError::AssignmentMissing)?
        };

        let perm = PoseidonPermutation::default();
        let sponge = SpongeGadget::<_, WIDTH, RATE> { perm };

        let out = sponge.hash(&cs, x.as_slice(), /*squeeze_lane=*/ 1)?;

        let h_var = cs.new_input_variable(|| Ok(h))?;
        cs.enforce_constraint(
            LinearCombination::from(out.var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(h_var),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};

    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn create_circuits() -> (PoseidonHashCircuit, PoseidonHashCircuit) {
        let x0 = Fr::from(7u64);
        let x1 = Fr::from(8u64);
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let h = sponge.hash(&[x0, x1]);
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
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let h = sponge.hash(&[x0, x1]);
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
