use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::merkle::{gadget::compute_root, spec::DEPTH};

pub struct MerkleMembershipCircuit {
    leaf: Option<Fr>,
    path: Option<[Fr; DEPTH]>,
    index_bits: Option<[Fr; DEPTH]>,
    root: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MerkleMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let is_setup = cs.is_in_setup_mode();
        let leaf = State::witness(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.leaf.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;

        let mut path = [State::zero(); DEPTH];
        if !is_setup {
            for (p, pv) in path
                .iter_mut()
                .zip(self.path.ok_or(SynthesisError::AssignmentMissing)?)
            {
                *p = State::witness(&cs, pv)?;
            }
        } else {
            for p in path.iter_mut() {
                *p = State::witness(&cs, Fr::ZERO)?;
            }
        };

        let mut index_bits = [State::zero(); DEPTH];
        if !is_setup {
            for (ib, ibv) in index_bits
                .iter_mut()
                .zip(self.index_bits.ok_or(SynthesisError::AssignmentMissing)?)
            {
                *ib = State::witness(&cs, ibv)?;
            }
        } else {
            for ib in index_bits.iter_mut() {
                *ib = State::witness(&cs, Fr::ZERO)?;
            }
        };

        let sponge: SpongeGadget<PoseidonPermutation, 3, 2> = SpongeGadget::default();
        let root = compute_root(&cs, &sponge, leaf, &path, &index_bits)?;

        let input_root = State::input(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.root.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        cs.enforce_constraint(
            LinearCombination::from(root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(input_root.var()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleMembershipCircuit;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::test_rng;

    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
    use rand::RngCore;

    use crate::merkle::{native, spec::DEPTH};

    fn random_witness() -> (Fr, [Fr; DEPTH], [Fr; DEPTH]) {
        let mut rng = test_rng();
        let leaf = Fr::rand(&mut rng);
        let path = [0; DEPTH].map(|_| Fr::rand(&mut rng));
        let bits = [0; DEPTH].map(|_| {
            if (rng.next_u32() & 1) == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        });
        (leaf, path, bits)
    }

    fn compute_root_native(leaf: Fr, path: &[Fr; DEPTH], bits: &[Fr; DEPTH]) -> Fr {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let bits_bool = bits.map(|b| b == Fr::ONE);
        native::compute_root(&sponge, leaf, path, &bits_bool)
    }

    fn setup_and_prove(
        leaf: Fr,
        path: [Fr; DEPTH],
        bits: [Fr; DEPTH],
        root: Fr,
    ) -> (
        ProvingKey<Bls12_381>,
        PreparedVerifyingKey<Bls12_381>,
        ark_groth16::Proof<Bls12_381>,
    ) {
        let mut rng = test_rng();

        let setup_circuit = MerkleMembershipCircuit {
            leaf: None,
            path: None,
            index_bits: None,
            root: None,
        };

        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            setup_circuit,
            &mut rng,
        )
        .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        let prove_circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let proof =
            Groth16::<Bls12_381>::create_random_proof_with_reduction(prove_circuit, &pk, &mut rng)
                .unwrap();

        (pk, vk, proof)
    }

    #[test]
    fn cs_satisfied_valid_membership() {
        let (leaf, path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        let circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_public_root() {
        let (leaf, path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);
        let wrong_root = root + Fr::ONE;

        let circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(wrong_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_flip_one_bit() {
        let (leaf, path, mut bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        // flip one bit in the witness
        bits[0] = if bits[0] == Fr::ONE {
            Fr::ZERO
        } else {
            Fr::ONE
        };

        let circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_non_boolean_bit() {
        let (leaf, path, mut bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        bits[0] = Fr::from(2u64);

        let circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_sibling() {
        let (leaf, mut path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        path[0] += Fr::ONE;

        let circuit = MerkleMembershipCircuit {
            leaf: Some(leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_leaf() {
        let (leaf, path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        let wrong_leaf = leaf + Fr::ONE;

        let circuit = MerkleMembershipCircuit {
            leaf: Some(wrong_leaf),
            path: Some(path),
            index_bits: Some(bits),
            root: Some(root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    // Optional Groth16 tests (slower). Keep if you want end-to-end assurance.

    #[test]
    fn groth16_valid_membership_verifies() {
        let (leaf, path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(leaf, path, bits, root);
        let public_inputs = vec![root];

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, &public_inputs).unwrap());
    }

    #[test]
    fn groth16_wrong_public_root_fails() {
        let (leaf, path, bits) = random_witness();
        let root = compute_root_native(leaf, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(leaf, path, bits, root);
        let wrong_public_inputs = vec![root + Fr::ONE];

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &wrong_public_inputs).unwrap());
    }
}
