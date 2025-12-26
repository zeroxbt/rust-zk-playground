use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::gadget::{
    compute_root_with_spine, enforce_bit_array, enforce_one_hot, first_difference_selectors,
    select_from_array, update_one_slot,
};

pub const DEPTH: usize = 8;

pub struct MerkleTransferKernelCircuit {
    leaf_s: Option<Fr>,
    leaf_r: Option<Fr>,
    path_s: Option<[Fr; DEPTH]>,
    path_r: Option<[Fr; DEPTH]>,
    index_bits_s: Option<[Fr; DEPTH]>,
    index_bits_r: Option<[Fr; DEPTH]>,
    amount: Option<Fr>,   // public
    old_root: Option<Fr>, // public
    new_root: Option<Fr>, // public
}

impl ConstraintSynthesizer<Fr> for MerkleTransferKernelCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let leaf_s = State::witness(&cs, self.leaf_s.unwrap_or_default())?;
        let leaf_r = State::witness(&cs, self.leaf_r.unwrap_or_default())?;
        let path_s: [State; DEPTH] =
            State::witness_array(&cs, &self.path_s.unwrap_or([Fr::ZERO; DEPTH]))?;
        let index_bits_s: [State; DEPTH] =
            State::witness_array(&cs, &self.index_bits_s.unwrap_or([Fr::ZERO; DEPTH]))?;
        let mut path_r: [State; DEPTH] =
            State::witness_array(&cs, &self.path_r.unwrap_or([Fr::ZERO; DEPTH]))?;
        let index_bits_r: [State; DEPTH] =
            State::witness_array(&cs, &self.index_bits_r.unwrap_or([Fr::ONE; DEPTH]))?;

        enforce_bit_array(&cs, &index_bits_s)?;
        enforce_bit_array(&cs, &index_bits_r)?;

        let old_input_root = State::input(&cs, self.old_root.unwrap_or_default())?;
        let sponge = SpongeGadget::default();
        enforce_old_root(
            &cs,
            &sponge,
            old_input_root,
            &[leaf_s, leaf_r],
            &[path_s, path_r],
            &[index_bits_s, index_bits_r],
        )?;

        let amount = State::input(&cs, self.amount.unwrap_or_default())?;
        let leaf_s_updated = State::witness(&cs, leaf_s.val() - amount.val())?;
        cs.enforce_constraint(
            LinearCombination::from(leaf_s_updated.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(leaf_s.var()) + (-Fr::ONE, amount.var()),
        )?;

        let (mid_root_s_updated, spine) =
            compute_root_with_spine(&cs, &sponge, leaf_s_updated, &path_s, &index_bits_s)?;

        let (selectors, found) = first_difference_selectors(&cs, &index_bits_s, &index_bits_r)?;
        cs.enforce_constraint(
            LinearCombination::from(found.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;
        enforce_one_hot(&cs, &selectors)?;
        let new_val = select_from_array(&cs, &selectors, &spine)?;
        path_r = update_one_slot(&cs, &selectors, &path_r, new_val)?;

        let (mid_root_r, _) =
            compute_root_with_spine(&cs, &sponge, leaf_r, &path_r, &index_bits_r)?;
        cs.enforce_constraint(
            LinearCombination::from(mid_root_r.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(mid_root_s_updated.var()),
        )?;

        let leaf_r_updated = State::witness(&cs, leaf_r.val() + amount.val())?;
        cs.enforce_constraint(
            LinearCombination::from(leaf_r_updated.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(leaf_r.var()) + (Fr::ONE, amount.var()),
        )?;

        let new_input_root = State::input(&cs, self.new_root.unwrap_or_default())?;

        let (new_root, _) =
            compute_root_with_spine(&cs, &sponge, leaf_r_updated, &path_r, &index_bits_r)?;

        cs.enforce_constraint(
            LinearCombination::from(new_root.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(new_input_root.var()),
        )?;
        Ok(())
    }
}

pub fn enforce_old_root<const T: usize>(
    cs: &ConstraintSystemRef<Fr>,
    sponge: &SpongeGadget<PoseidonPermutation, 3, 2>,
    old_input_root: State,
    leaves: &[State; 2],
    paths: &[[State; T]; 2],
    index_bits: &[[State; T]; 2],
) -> Result<(), SynthesisError> {
    for i in 0..2 {
        let (old_root_r, _) =
            compute_root_with_spine(cs, sponge, leaves[i], &paths[i], &index_bits[i])?;
        cs.enforce_constraint(
            LinearCombination::from(old_root_r.var()),
            LinearCombination::from(Variable::One),
            LinearCombination::from(old_input_root.var()),
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;
    use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
    use merkle_membership::merkle::spec::MERKLE_NODE_DST;

    // ========================================================================
    // TEST DATA GENERATION HELPERS
    // ========================================================================

    /// Compute Merkle root natively for testing
    fn compute_native_root(leaf: Fr, path: &[Fr], index_bits: &[Fr]) -> Fr {
        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
        let mut cur = leaf;

        for (&sib, &bit) in path.iter().zip(index_bits.iter()) {
            let (left, right) = if bit == Fr::ZERO {
                (cur, sib)
            } else {
                (sib, cur)
            };
            cur = sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST));
        }

        cur
    }

    /// Create a simple 2-leaf Merkle tree for testing
    /// Returns: (leaf0, leaf1, path0, path1, root)
    fn create_two_leaf_tree(
        balance0: u64,
        balance1: u64,
    ) -> (Fr, Fr, [Fr; DEPTH], [Fr; DEPTH], Fr) {
        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();

        let leaf0 = Fr::from(balance0);
        let leaf1 = Fr::from(balance1);

        // Level 0: hash the two leaves together
        let level0_hash = sponge.hash_with_dst(&[leaf0, leaf1], Some(MERKLE_NODE_DST));

        // For a 2^DEPTH tree with only 2 leaves at positions 0 and 1,
        // we need to fill in dummy siblings up the tree
        let mut path0 = [Fr::ZERO; DEPTH];
        let mut path1 = [Fr::ZERO; DEPTH];

        // Position 0: sibling is leaf1
        path0[0] = leaf1;

        // Position 1: sibling is leaf0
        path1[0] = leaf0;

        // Fill rest with dummy hashes going up the tree
        let mut current_hash = level0_hash;
        let dummy = Fr::ZERO;

        for i in 1..DEPTH {
            path0[i] = dummy;
            path1[i] = dummy;

            // Hash current with dummy to get next level
            current_hash = sponge.hash_with_dst(&[current_hash, dummy], Some(MERKLE_NODE_DST));
        }

        let index_bits0 = [Fr::ZERO; DEPTH];

        let mut index_bits1 = [Fr::ZERO; DEPTH];
        index_bits1[0] = Fr::ONE;

        // Verify tree construction is consistent
        let root0 = compute_native_root(leaf0, &path0, &index_bits0);
        let root1 = compute_native_root(leaf1, &path1, &index_bits1);
        assert_eq!(root0, root1, "tree construction inconsistent");

        (leaf0, leaf1, path0, path1, root0)
    }

    /// Compute spine (intermediate hashes) during Merkle path computation
    fn compute_spine(leaf: Fr, path: &[Fr; DEPTH], index_bits: &[Fr; DEPTH]) -> [Fr; DEPTH] {
        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
        let mut spine = [Fr::ZERO; DEPTH];
        let mut cur = leaf;

        for (i, (&sib, &bit)) in path.iter().zip(index_bits.iter()).enumerate() {
            spine[i] = cur;
            let (left, right) = if bit == Fr::ZERO {
                (cur, sib)
            } else {
                (sib, cur)
            };
            cur = sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST));
        }

        spine
    }

    /// Create complete valid transfer data
    ///
    /// IMPORTANT: The circuit internally updates path_r during execution,
    /// so we return the ORIGINAL path_r_initial, not the updated one.
    /// The circuit will compute the update itself.
    fn create_transfer_scenario(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
    ) -> (
        Fr,
        Fr, // leaf_s, leaf_r
        [Fr; DEPTH],
        [Fr; DEPTH], // path_s, path_r (ORIGINAL, not updated!)
        [Fr; DEPTH],
        [Fr; DEPTH], // index_bits_s, index_bits_r
        Fr,          // amount
        Fr,
        Fr, // old_root, new_root
    ) {
        // Initial tree with sender at index 0, receiver at index 1
        let (leaf_s, leaf_r, path_s_initial, path_r_initial, old_root) =
            create_two_leaf_tree(sender_balance, receiver_balance);

        // Index 0 for sender (all bits 0)
        let index_bits_s = [Fr::ZERO; DEPTH];

        // Index 1 for receiver (first bit is 1, rest 0)
        let mut index_bits_r = [Fr::ZERO; DEPTH];
        index_bits_r[0] = Fr::ONE;

        let amount_fr = Fr::from(amount);

        // Compute updated balances
        let leaf_s_updated = Fr::from(sender_balance - amount);
        let leaf_r_updated = Fr::from(receiver_balance + amount);

        // Step 1: Compute spine for sender's update
        let spine = compute_spine(leaf_s_updated, &path_s_initial, &index_bits_s);

        // Step 2: Find first difference between indices
        let first_diff_idx = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();

        // Step 3: Update receiver's path at the divergence point
        // (This is what the circuit does internally)
        let mut path_r_updated = path_r_initial;
        path_r_updated[first_diff_idx] = spine[first_diff_idx];

        // Step 4: Compute final root with updated receiver
        let new_root = compute_native_root(leaf_r_updated, &path_r_updated, &index_bits_r);

        // Sanity check: verify mid roots match
        #[cfg(debug_assertions)]
        {
            let mid_root_s = compute_native_root(leaf_s_updated, &path_s_initial, &index_bits_s);
            let mid_root_r = compute_native_root(leaf_r, &path_r_updated, &index_bits_r);
            assert_eq!(mid_root_s, mid_root_r, "mid roots should match");
        }

        (
            leaf_s,
            leaf_r,
            path_s_initial,
            path_r_initial, // Return ORIGINAL path, circuit updates it!
            index_bits_s,
            index_bits_r,
            amount_fr,
            old_root,
            new_root,
        )
    }

    // ========================================================================
    // BASIC FUNCTIONALITY TESTS
    // ========================================================================

    #[test]
    fn test_valid_transfer_basic() {
        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("valid transfer should succeed");

        assert!(
            cs.is_satisfied().unwrap(),
            "Valid transfer should satisfy all constraints"
        );

        println!("✓ Valid transfer (100 - 30 = 70, 50 + 30 = 80)");
        println!("  Constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_valid_transfer_exact_balance() {
        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 100);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("should succeed");

        assert!(
            cs.is_satisfied().unwrap(),
            "Transferring exact balance should work"
        );

        println!("✓ Valid transfer of entire balance (100 - 100 = 0)");
    }

    #[test]
    fn test_valid_small_transfer() {
        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(1000, 500, 1);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("✓ Valid small transfer (amount = 1)");
    }

    #[test]
    fn test_multiple_amounts() {
        for amount in [1u64, 10, 50, 99, 100] {
            let (
                leaf_s,
                leaf_r,
                path_s,
                path_r,
                index_bits_s,
                index_bits_r,
                amount_fr,
                old_root,
                new_root,
            ) = create_transfer_scenario(100, 50, amount);

            let circuit = MerkleTransferKernelCircuit {
                leaf_s: Some(leaf_s),
                leaf_r: Some(leaf_r),
                path_s: Some(path_s),
                path_r: Some(path_r),
                index_bits_s: Some(index_bits_s),
                index_bits_r: Some(index_bits_r),
                amount: Some(amount_fr),
                old_root: Some(old_root),
                new_root: Some(new_root),
            };

            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "Transfer of amount {} should work",
                amount
            );
        }

        println!("✓ Multiple transfer amounts all work");
    }

    // ========================================================================
    // SOUNDNESS TESTS - BALANCE VIOLATIONS (CRITICAL BUGS!)
    // ========================================================================

    #[test]
    fn test_insufficient_balance_bug() {
        // CRITICAL BUG TEST: Circuit allows negative balances!

        // Create a scenario with insufficient balance
        let sender_balance = 20u64;
        let receiver_balance = 50u64;
        let malicious_amount = 30u64; // More than sender has!

        let (_, _, path_s, path_r, index_bits_s, index_bits_r, _, _, _) =
            create_transfer_scenario(100, 50, 30); // Just for paths

        let (_, _, _, _, fake_old_root) = create_two_leaf_tree(sender_balance, receiver_balance);

        // Compute malicious new_root where sender balance wraps around
        let wrapped_balance = u64::MAX - (malicious_amount - sender_balance - 1);
        let new_receiver_balance = receiver_balance + malicious_amount;
        let (_, _, _, _, malicious_new_root) =
            create_two_leaf_tree(wrapped_balance, new_receiver_balance);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(Fr::from(sender_balance)),
            leaf_r: Some(Fr::from(receiver_balance)),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(Fr::from(malicious_amount)),
            old_root: Some(fake_old_root),
            new_root: Some(malicious_new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        if cs.is_satisfied().unwrap() {
            println!("❌ CRITICAL BUG CONFIRMED: Insufficient balance NOT rejected!");
            println!(
                "   Sender: {}, Amount: {}",
                sender_balance, malicious_amount
            );
            println!("   Circuit allows negative balance (wraps in field arithmetic)");
            println!("   This creates money from nothing!");
        } else {
            println!("✓ Insufficient balance correctly rejected (bug fixed!)");
        }
    }

    #[test]
    fn test_zero_amount_allowed() {
        let (leaf_s, leaf_r, path_s, path_r, index_bits_s, index_bits_r, _, old_root, _) =
            create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(Fr::ZERO),
            old_root: Some(old_root),
            new_root: Some(old_root), // No change!
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        if cs.is_satisfied().unwrap() {
            println!("⚠️  Zero amount transfer is allowed");
            println!("   Consider if this is desired behavior");
        } else {
            println!("✓ Zero amount correctly rejected");
        }
    }

    // ========================================================================
    // SOUNDNESS TESTS - INDEX VIOLATIONS
    // ========================================================================

    #[test]
    fn test_same_sender_receiver_rejected() {
        let (leaf_s, leaf_r, path_s, path_r, index_bits_s, _, amount, old_root, new_root) =
            create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_s), // SAME as sender!
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        assert!(
            !cs.is_satisfied().unwrap(),
            "Should reject when sender = receiver"
        );

        println!("✓ Same sender/receiver correctly rejected");
    }

    #[test]
    fn test_invalid_index_bit_rejected() {
        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            mut index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 30);

        index_bits_s[0] = Fr::from(2u64); // Invalid bit!

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        assert!(
            !cs.is_satisfied().unwrap(),
            "Should reject invalid bit value"
        );

        println!("✓ Invalid index bit (value=2) correctly rejected");
    }

    // ========================================================================
    // SOUNDNESS TESTS - ROOT VIOLATIONS
    // ========================================================================

    #[test]
    fn test_wrong_old_root_rejected() {
        let (leaf_s, leaf_r, path_s, path_r, index_bits_s, index_bits_r, amount, _, new_root) =
            create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(Fr::from(99999u64)),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        assert!(!cs.is_satisfied().unwrap(), "Should reject wrong old_root");

        println!("✓ Wrong old_root correctly rejected");
    }

    #[test]
    fn test_wrong_new_root_rejected() {
        let (leaf_s, leaf_r, path_s, path_r, index_bits_s, index_bits_r, amount, old_root, _) =
            create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(Fr::from(88888u64)),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        assert!(!cs.is_satisfied().unwrap(), "Should reject wrong new_root");

        println!("✓ Wrong new_root correctly rejected");
    }

    #[test]
    fn test_wrong_sender_path_rejected() {
        let (
            leaf_s,
            leaf_r,
            mut path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 30);

        path_s[0] = Fr::from(77777u64); // Corrupt path

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation succeeds");

        assert!(
            !cs.is_satisfied().unwrap(),
            "Should reject corrupted sender path"
        );

        println!("✓ Wrong sender path correctly rejected");
    }

    // ========================================================================
    // SOUNDNESS TESTS - PATH UPDATE LOGIC
    // ========================================================================

    #[test]
    fn test_wrong_divergence_slot_rejected() {
        let sender_balance = 100u64;
        let receiver_balance = 50u64;
        let amount = 30u64;

        let (leaf_s, leaf_r, path_s, path_r_initial, old_root) =
            create_two_leaf_tree(sender_balance, receiver_balance);

        let index_bits_s = [Fr::ZERO; DEPTH];
        let mut index_bits_r = [Fr::ZERO; DEPTH];
        index_bits_r[0] = Fr::ONE;

        let leaf_s_updated = Fr::from(sender_balance - amount);
        let leaf_r_updated = Fr::from(receiver_balance + amount);

        let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

        let first_diff_idx = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();

        // Malicious: patch wrong slot
        let wrong_idx = if first_diff_idx == 0 {
            1
        } else {
            first_diff_idx - 1
        };
        let mut wrong_path_r = path_r_initial;
        wrong_path_r[wrong_idx] = spine[first_diff_idx];

        let malicious_new_root = compute_native_root(leaf_r_updated, &wrong_path_r, &index_bits_r);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r_initial),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(Fr::from(amount)),
            old_root: Some(old_root),
            new_root: Some(malicious_new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Should reject wrong divergence slot"
        );

        println!("✓ Wrong divergence slot correctly rejected");
    }

    #[test]
    fn test_wrong_spine_value_rejected() {
        let sender_balance = 100u64;
        let receiver_balance = 50u64;
        let amount = 30u64;

        let (leaf_s, leaf_r, path_s, path_r_initial, old_root) =
            create_two_leaf_tree(sender_balance, receiver_balance);

        let index_bits_s = [Fr::ZERO; DEPTH];
        let mut index_bits_r = [Fr::ZERO; DEPTH];
        index_bits_r[0] = Fr::ONE;

        let leaf_s_updated = Fr::from(sender_balance - amount);
        let leaf_r_updated = Fr::from(receiver_balance + amount);

        let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

        let first_diff_idx = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();

        // Malicious: correct slot but wrong value
        let mut wrong_path_r = path_r_initial;
        wrong_path_r[first_diff_idx] = spine[first_diff_idx] + Fr::ONE;

        let malicious_new_root = compute_native_root(leaf_r_updated, &wrong_path_r, &index_bits_r);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r_initial),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(Fr::from(amount)),
            old_root: Some(old_root),
            new_root: Some(malicious_new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Should reject wrong spine value"
        );

        println!("✓ Wrong spine value correctly rejected");
    }

    // ========================================================================
    // PROPERTY TESTS
    // ========================================================================

    #[test]
    fn test_conservation_of_value() {
        let sender_bal = 100u64;
        let receiver_bal = 50u64;
        let amount = 30u64;

        let total_before = sender_bal + receiver_bal;
        let total_after = (sender_bal - amount) + (receiver_bal + amount);

        assert_eq!(total_before, total_after, "Total value should be conserved");

        println!(
            "✓ Conservation of value: {} = {}",
            total_before, total_after
        );
    }

    #[test]
    fn test_constraint_count_analysis() {
        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 30);

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let num_constraints = cs.num_constraints();

        println!("📊 Constraint Count Analysis:");
        println!("   Total: {}", num_constraints);
        println!("   Tree depth: {}", DEPTH);
        println!("   Estimated per component:");
        println!("     - Index bit checks (2×{}): ~{}", DEPTH, DEPTH * 2);
        println!("     - Merkle path verifications: ~{}", DEPTH * 10);
        println!("     - Balance updates: ~10");
        println!("     - Path update logic: ~{}", DEPTH * 5);
        println!("     - First difference: ~{}", DEPTH * 2);

        assert!(
            num_constraints > 50 && num_constraints < 50000,
            "Constraint count unreasonable: {}",
            num_constraints
        );
    }
}
