use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use merkle_membership::merkle::{gadget::compute_root, spec::DEPTH};

pub struct MerkleUpdateCircuit {
    old_leaf: Option<Fr>,
    new_leaf: Option<Fr>,
    path: Option<[Fr; DEPTH]>,
    index_bits: Option<[Fr; DEPTH]>,
    old_root: Option<Fr>,
    new_root: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MerkleUpdateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let is_setup = cs.is_in_setup_mode();
        let old_leaf = State::witness(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.old_leaf.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        let new_leaf = State::witness(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.new_leaf.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;

        let path_vals = if is_setup {
            [Fr::ZERO; DEPTH]
        } else {
            self.path.ok_or(SynthesisError::AssignmentMissing)?
        };
        let path = State::witness_array(&cs, &path_vals)?;

        let index_bits_vals = if is_setup {
            [Fr::ZERO; DEPTH]
        } else {
            self.index_bits.ok_or(SynthesisError::AssignmentMissing)?
        };
        let index_bits = State::witness_array(&cs, &index_bits_vals)?;

        let sponge: SpongeGadget<PoseidonPermutation, 3, 2> = SpongeGadget::default();
        let old_root = compute_root(&cs, &sponge, old_leaf, &path, &index_bits)?;
        let new_root = compute_root(&cs, &sponge, new_leaf, &path, &index_bits)?;

        let old_input_root = State::input(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.old_root.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        let new_input_root = State::input(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.new_root.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        cs.enforce_constraint(
            LinearCombination::from(old_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(old_input_root.var()),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(new_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(new_input_root.var()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleUpdateCircuit;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::test_rng;
    use rand::RngCore;

    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

    // Reuse the native Merkle root from project 04
    use merkle_membership::merkle::native;

    use merkle_membership::merkle::spec::DEPTH;

    fn random_witness() -> (Fr, Fr, [Fr; DEPTH], [Fr; DEPTH]) {
        let mut rng = test_rng();
        let old_leaf = Fr::rand(&mut rng);
        let new_leaf = Fr::rand(&mut rng);

        let path = [0; DEPTH].map(|_| Fr::rand(&mut rng));
        let bits = [0; DEPTH].map(|_| {
            if (rng.next_u32() & 1) == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        });

        (old_leaf, new_leaf, path, bits)
    }

    fn compute_root_native(leaf: Fr, path: &[Fr; DEPTH], bits: &[Fr; DEPTH]) -> Fr {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let bits_bool = bits.map(|b| b == Fr::ONE);
        native::compute_root(&sponge, leaf, path, &bits_bool)
    }

    fn setup_and_prove(
        old_leaf: Fr,
        new_leaf: Fr,
        path: [Fr; DEPTH],
        bits: [Fr; DEPTH],
        old_root: Fr,
        new_root: Fr,
    ) -> (
        ProvingKey<Bls12_381>,
        PreparedVerifyingKey<Bls12_381>,
        ark_groth16::Proof<Bls12_381>,
    ) {
        let mut rng = test_rng();

        let setup_circuit = MerkleUpdateCircuit {
            old_leaf: None,
            new_leaf: None,
            path: None,
            index_bits: None,
            old_root: None,
            new_root: None,
        };

        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            setup_circuit,
            &mut rng,
        )
        .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        let prove_circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let proof =
            Groth16::<Bls12_381>::create_random_proof_with_reduction(prove_circuit, &pk, &mut rng)
                .unwrap();

        (pk, vk, proof)
    }

    #[test]
    fn cs_satisfied_valid_update() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_old_public_root() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root + Fr::ONE),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_new_public_root() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root + Fr::ONE),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_old_leaf() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf + Fr::ONE),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_new_leaf() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf + Fr::ONE),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_wrong_sibling_breaks_both() {
        let (old_leaf, new_leaf, mut path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        path[0] += Fr::ONE;

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_flip_one_bit() {
        let (old_leaf, new_leaf, path, mut bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        // flip one boolean bit in the witness
        bits[0] = if bits[0] == Fr::ONE {
            Fr::ZERO
        } else {
            Fr::ONE
        };

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cs_unsatisfied_non_boolean_bit() {
        let (old_leaf, new_leaf, path, mut bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        bits[0] = Fr::from(2u64);

        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    // This test demonstrates the *semantic* point of the update circuit:
    // it enforces that both roots are computed using the same path/bits.
    #[test]
    fn cs_unsatisfied_new_root_from_different_path_or_bits() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);

        // Create a second, different authentication path/bits for the *new* root.
        let mut rng = test_rng();
        let path2 = [0; DEPTH].map(|_| Fr::rand(&mut rng));
        let bits2 = [0; DEPTH].map(|_| {
            if (rng.next_u32() & 1) == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        });

        let new_root_wrong = compute_root_native(new_leaf, &path2, &bits2);

        // Circuit uses (path,bits) for both roots, but we give a new_root computed from (path2,bits2)
        let circuit = MerkleUpdateCircuit {
            old_leaf: Some(old_leaf),
            new_leaf: Some(new_leaf),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root_wrong),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    // Groth16 end-to-end tests (slower)
    #[test]
    fn groth16_valid_update_verifies() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(old_leaf, new_leaf, path, bits, old_root, new_root);

        // public inputs must match allocation order: [old_root, new_root]
        let public_inputs = vec![old_root, new_root];

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, &public_inputs).unwrap());
    }

    #[test]
    fn groth16_wrong_new_root_fails() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(old_leaf, new_leaf, path, bits, old_root, new_root);

        let wrong_public_inputs = vec![old_root, new_root + Fr::ONE];
        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &wrong_public_inputs).unwrap());
    }

    #[test]
    fn groth16_swapped_public_inputs_fails() {
        let (old_leaf, new_leaf, path, bits) = random_witness();
        let old_root = compute_root_native(old_leaf, &path, &bits);
        let new_root = compute_root_native(new_leaf, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(old_leaf, new_leaf, path, bits, old_root, new_root);

        // swapped order should fail
        let swapped_public_inputs = vec![new_root, old_root];
        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &swapped_public_inputs).unwrap());
    }
}
