use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, MontFp};
use ark_relations::r1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};
use merkle_membership::merkle::{gadget::compute_root, spec::DEPTH};

const STEP_DST: Fr = MontFp!("17");

pub struct MerkleOrderedUpdateCircuit<const K: usize> {
    leaf: Option<Fr>,
    deltas: Option<[Fr; K]>,
    path: Option<[Fr; DEPTH]>,
    index_bits: Option<[Fr; DEPTH]>,
    old_root: Option<Fr>, // public
    new_root: Option<Fr>, // public
}

impl<const K: usize> ConstraintSynthesizer<Fr> for MerkleOrderedUpdateCircuit<K> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let is_setup = cs.is_in_setup_mode();
        let leaf = State::witness(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.leaf.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;

        let path_vals = if is_setup {
            [Fr::ZERO; DEPTH]
        } else {
            self.path.ok_or(SynthesisError::AssignmentMissing)?
        };
        let path: [State; DEPTH] = State::witness_array(&cs, &path_vals)?;

        let index_bits_vals = if is_setup {
            [Fr::ZERO; DEPTH]
        } else {
            self.index_bits.ok_or(SynthesisError::AssignmentMissing)?
        };
        let index_bits = State::witness_array(&cs, &index_bits_vals)?;

        let deltas_vals = if is_setup {
            [Fr::ZERO; K]
        } else {
            self.deltas.ok_or(SynthesisError::AssignmentMissing)?
        };
        let deltas: [State; K] = State::witness_array(&cs, &deltas_vals)?;

        let sponge: SpongeGadget<PoseidonPermutation, 3, 2> = SpongeGadget::default();
        let old_root = compute_root(&cs, &sponge, leaf, &path, &index_bits)?;
        let old_input_root = State::input(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.old_root.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        cs.enforce_constraint(
            LinearCombination::from(old_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(old_input_root.var()),
        )?;

        let mut new_leaf = leaf;
        for delta in deltas {
            new_leaf = sponge.hash_with_dst(&cs, &[new_leaf, delta], Some(STEP_DST), 1)?;
        }

        let new_input_root = State::input(&cs, {
            if is_setup {
                Fr::ZERO
            } else {
                self.new_root.ok_or(SynthesisError::AssignmentMissing)?
            }
        })?;
        let new_root = compute_root(&cs, &sponge, new_leaf, &path, &index_bits)?;
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
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::test_rng;
    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
    use merkle_membership::merkle::{native, spec::DEPTH};
    use rand::RngCore;

    use super::MerkleOrderedUpdateCircuit;
    use crate::circuit::STEP_DST;

    const K: usize = 4;

    fn random_bits() -> [Fr; DEPTH] {
        let mut rng = test_rng();
        [0; DEPTH].map(|_| {
            if (rng.next_u32() & 1) == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        })
    }

    fn random_instance() -> (Fr, [Fr; K], [Fr; DEPTH], [Fr; DEPTH]) {
        let mut rng = test_rng();
        let leaf = Fr::rand(&mut rng);
        let deltas = [0; K].map(|_| Fr::rand(&mut rng));
        let path = [0; DEPTH].map(|_| Fr::rand(&mut rng));
        let bits = random_bits();
        (leaf, deltas, path, bits)
    }

    fn compute_root_native(leaf: Fr, path: &[Fr; DEPTH], bits: &[Fr; DEPTH]) -> Fr {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        let bits_bool = bits.map(|b| b == Fr::ONE);
        native::compute_root(&sponge, leaf, path, &bits_bool)
    }

    fn apply_deltas(mut leaf: Fr, deltas: &[Fr; K]) -> Fr {
        let sponge: SpongeNative<PoseidonPermutation, 3, 2> = SpongeNative::default();
        for &d in deltas.iter() {
            leaf = sponge.hash_with_dst(&[leaf, d], Some(STEP_DST));
        }
        leaf
    }

    fn setup_and_prove(
        leaf: Fr,
        deltas: [Fr; K],
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

        let setup_circuit = MerkleOrderedUpdateCircuit::<K> {
            leaf: None,
            deltas: None,
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

        let prove_circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_satisfied_valid_ordered_update() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_wrong_old_root() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_wrong_new_root() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_wrong_leaf() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf + Fr::ONE),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_modify_one_delta() {
        let (leaf, mut deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        deltas[0] += Fr::ONE;

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_swapped_two_deltas_order_matters() {
        let (leaf, mut deltas, path, bits) = random_instance();

        if deltas[0] == deltas[1] {
            deltas[1] += Fr::ONE;
        }

        let old_root = compute_root_native(leaf, &path, &bits);

        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        deltas.swap(0, 1);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
            path: Some(path),
            index_bits: Some(bits),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Swapping deltas should fail if the circuit enforces ordered recurrence."
        );
    }

    #[test]
    fn cs_unsatisfied_wrong_sibling_in_path() {
        let (leaf, deltas, mut path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        path[0] += Fr::ONE;

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_flip_one_index_bit() {
        let (leaf, deltas, path, mut bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        bits[0] = if bits[0] == Fr::ONE {
            Fr::ZERO
        } else {
            Fr::ONE
        };

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn cs_unsatisfied_non_boolean_index_bit() {
        let (leaf, deltas, path, mut bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        bits[0] = Fr::from(2u64);

        let circuit = MerkleOrderedUpdateCircuit {
            leaf: Some(leaf),
            deltas: Some(deltas),
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
    fn groth16_valid_ordered_update_verifies() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(leaf, deltas, path, bits, old_root, new_root);
        let public_inputs = vec![old_root, new_root];

        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, &public_inputs).unwrap());
    }

    #[test]
    fn groth16_wrong_new_root_fails() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(leaf, deltas, path, bits, old_root, new_root);
        let wrong_public_inputs = vec![old_root, new_root + Fr::ONE];

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &wrong_public_inputs).unwrap());
    }

    #[test]
    fn groth16_swapped_public_inputs_fails() {
        let (leaf, deltas, path, bits) = random_instance();

        let old_root = compute_root_native(leaf, &path, &bits);
        let leaf_end = apply_deltas(leaf, &deltas);
        let new_root = compute_root_native(leaf_end, &path, &bits);

        let (_pk, vk, proof) = setup_and_prove(leaf, deltas, path, bits, old_root, new_root);
        let swapped_public_inputs = vec![new_root, old_root];

        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, &swapped_public_inputs).unwrap());
    }
}
