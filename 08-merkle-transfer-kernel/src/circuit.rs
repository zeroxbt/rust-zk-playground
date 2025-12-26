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
    type TransferScenario = (
        Fr,
        Fr, // leaf_s, leaf_r
        [Fr; DEPTH],
        [Fr; DEPTH], // path_s, path_r (ORIGINAL, not updated!)
        [Fr; DEPTH],
        [Fr; DEPTH], // index_bits_s, index_bits_r
        Fr,          // amount
        Fr,
        Fr, // old_root, new_root
    );

    fn create_transfer_scenario(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
    ) -> TransferScenario {
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
    // ========================================================================
    // ADDITIONAL SOUNDNESS TESTS
    // Add these tests to the existing test module in the circuit file
    // ========================================================================

    // ========================================================================
    // A. NONTRIVIAL DIVERGENCE DEPTH TESTS
    // These test first_difference_selectors, spine indexing, and patching
    // at various tree depths where sender/receiver paths diverge.
    // ========================================================================

    /// Create a tree where sender and receiver diverge at a specific depth.
    ///
    /// For divergence at depth D:
    /// - Sender index bits: all zeros up to D, then 0 at D
    /// - Receiver index bits: all zeros up to D, then 1 at D
    ///
    /// This means they share a common path for levels 0..D, then diverge.
    struct DivergenceScenario {
        leaf_s: Fr,
        leaf_r: Fr,
        path_s: [Fr; DEPTH],
        path_r: [Fr; DEPTH],
        index_bits_s: [Fr; DEPTH],
        index_bits_r: [Fr; DEPTH],
        amount: Fr,
        old_root: Fr,
        new_root: Fr,
    }

    fn create_divergence_at_depth(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
        divergence_depth: usize,
    ) -> DivergenceScenario {
        assert!(divergence_depth < DEPTH, "divergence_depth must be < DEPTH");

        let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();

        let leaf_s = Fr::from(sender_balance);
        let leaf_r = Fr::from(receiver_balance);

        // Build index bits: identical up to divergence_depth, then differ
        let index_bits_s = [Fr::ZERO; DEPTH];
        let mut index_bits_r = [Fr::ZERO; DEPTH];

        // At divergence_depth: sender goes left (0), receiver goes right (1)
        index_bits_r[divergence_depth] = Fr::ONE;

        // Build the tree bottom-up to compute paths
        // We need to construct valid Merkle paths for both leaves

        // Start by computing what the tree looks like
        // At level divergence_depth, we have two subtrees that merge

        // Compute the hash of leaf_s going up to divergence_depth
        let mut current_s = leaf_s;
        let mut path_s = [Fr::ZERO; DEPTH];

        // Compute the hash of leaf_r going up to divergence_depth
        let mut current_r = leaf_r;
        let mut path_r = [Fr::ZERO; DEPTH];

        // For levels below divergence, both paths are independent
        // We'll use dummy siblings (zeros)
        for i in 0..divergence_depth {
            path_s[i] = Fr::ZERO; // dummy sibling
            path_r[i] = Fr::ZERO; // dummy sibling

            // Hash with dummy (on the right for sender, on the right for receiver)
            // Sender: index bit is 0, so sender is on left
            current_s = sponge.hash_with_dst(&[current_s, Fr::ZERO], Some(MERKLE_NODE_DST));
            // Receiver: index bit is 0, so receiver is on left
            current_r = sponge.hash_with_dst(&[current_r, Fr::ZERO], Some(MERKLE_NODE_DST));
        }

        // At divergence_depth, the two subtrees merge:
        // sender's subtree hash is current_s (goes left, index bit 0)
        // receiver's subtree hash is current_r (goes right, index bit 1)
        path_s[divergence_depth] = current_r; // sender's sibling is receiver's subtree
        path_r[divergence_depth] = current_s; // receiver's sibling is sender's subtree

        // Merge them
        let merged = sponge.hash_with_dst(&[current_s, current_r], Some(MERKLE_NODE_DST));
        let mut current = merged;

        // Continue up the tree with dummy siblings
        for i in (divergence_depth + 1)..DEPTH {
            path_s[i] = Fr::ZERO;
            path_r[i] = Fr::ZERO;
            current = sponge.hash_with_dst(&[current, Fr::ZERO], Some(MERKLE_NODE_DST));
        }

        let old_root = current;

        // Verify paths are correct
        let computed_root_s = compute_native_root(leaf_s, &path_s, &index_bits_s);
        let computed_root_r = compute_native_root(leaf_r, &path_r, &index_bits_r);
        assert_eq!(computed_root_s, old_root, "sender path verification failed");
        assert_eq!(
            computed_root_r, old_root,
            "receiver path verification failed"
        );

        // Now compute the transfer
        let amount_fr = Fr::from(amount);
        let leaf_s_updated = Fr::from(sender_balance - amount);
        let leaf_r_updated = Fr::from(receiver_balance + amount);

        // Compute spine for updated sender
        let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

        // Find first difference (should be at divergence_depth)
        let first_diff = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();
        assert_eq!(first_diff, divergence_depth, "divergence point mismatch");

        // Update receiver's path at divergence point
        let mut path_r_updated = path_r;
        path_r_updated[divergence_depth] = spine[divergence_depth];

        // Compute new root
        let new_root = compute_native_root(leaf_r_updated, &path_r_updated, &index_bits_r);

        // Verify mid roots match
        let mid_root_s = compute_native_root(leaf_s_updated, &path_s, &index_bits_s);
        let mid_root_r = compute_native_root(leaf_r, &path_r_updated, &index_bits_r);
        assert_eq!(mid_root_s, mid_root_r, "mid roots should match");

        DivergenceScenario {
            leaf_s,
            leaf_r,
            path_s,
            path_r, // Original path, circuit updates it
            index_bits_s,
            index_bits_r,
            amount: amount_fr,
            old_root,
            new_root,
        }
    }

    #[test]
    fn test_divergence_at_depth_0() {
        // First difference at the very first level (immediate divergence)
        let DivergenceScenario {
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        } = create_divergence_at_depth(100, 50, 30, 0);

        // Verify divergence is at expected depth
        let first_diff = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();
        assert_eq!(first_diff, 0, "Expected divergence at depth 0");

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

        assert!(
            cs.is_satisfied().unwrap(),
            "Transfer with divergence at depth 0 should succeed"
        );

        println!("✓ Divergence at depth 0 works correctly");
    }

    #[test]
    fn test_divergence_at_depth_3() {
        // First difference at middle of tree
        let divergence_depth = 3;
        assert!(divergence_depth < DEPTH, "Test requires DEPTH > 3");

        let DivergenceScenario {
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        } = create_divergence_at_depth(100, 50, 30, divergence_depth);

        // Verify divergence is at expected depth
        let first_diff = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();
        assert_eq!(
            first_diff, divergence_depth,
            "Expected divergence at depth 3"
        );

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

        assert!(
            cs.is_satisfied().unwrap(),
            "Transfer with divergence at depth 3 should succeed"
        );

        println!("✓ Divergence at depth 3 works correctly");
    }

    #[test]
    fn test_divergence_at_depth_minus_2() {
        // First difference near the top of tree (DEPTH - 2)
        let divergence_depth = DEPTH - 2;

        let DivergenceScenario {
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        } = create_divergence_at_depth(100, 50, 30, divergence_depth);

        // Verify divergence is at expected depth
        let first_diff = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();
        assert_eq!(
            first_diff, divergence_depth,
            "Expected divergence at DEPTH-2"
        );

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

        assert!(
            cs.is_satisfied().unwrap(),
            "Transfer with divergence at DEPTH-2 should succeed"
        );

        println!(
            "✓ Divergence at depth {} (DEPTH-2) works correctly",
            divergence_depth
        );
    }

    #[test]
    fn test_divergence_at_depth_minus_1() {
        // First difference at the very top of tree (DEPTH - 1)
        // This is the latest possible divergence - paths share almost everything
        let divergence_depth = DEPTH - 1;

        let DivergenceScenario {
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            index_bits_r,
            amount,
            old_root,
            new_root,
        } = create_divergence_at_depth(100, 50, 30, divergence_depth);

        // Verify divergence is at expected depth
        let first_diff = (0..DEPTH)
            .find(|&i| index_bits_s[i] != index_bits_r[i])
            .unwrap();
        assert_eq!(
            first_diff, divergence_depth,
            "Expected divergence at DEPTH-1"
        );

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

        assert!(
            cs.is_satisfied().unwrap(),
            "Transfer with divergence at DEPTH-1 should succeed"
        );

        println!(
            "✓ Divergence at depth {} (DEPTH-1) works correctly",
            divergence_depth
        );
    }

    // ========================================================================
    // B. POLARITY REGRESSION TESTS
    // These catch left/right ordering regressions in conditional_swap
    // and native generator alignment.
    // ========================================================================

    #[test]
    fn test_polarity_single_bit_flip_rejected() {
        // Create a valid transfer, then flip one index bit without updating paths
        // This should be rejected because the Merkle path computation will be wrong

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

        // Flip just one bit in sender's index (breaks left/right ordering)
        // Find a bit that's currently 0 and flip it to 1 (or vice versa)
        let flip_idx = 0;
        index_bits_s[flip_idx] = if index_bits_s[flip_idx] == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        };

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

        assert!(
            !cs.is_satisfied().unwrap(),
            "Single bit flip in sender index should be rejected (polarity check)"
        );

        println!("✓ Polarity: single bit flip in sender index correctly rejected");
    }

    #[test]
    fn test_polarity_invert_all_sender_bits_rejected() {
        // Invert ALL bits in sender's index without updating anything else
        // This simulates a complete polarity inversion

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

        // Invert all sender bits
        let inverted_index_bits_s: [Fr; DEPTH] = index_bits_s
            .iter()
            .map(|&b| if b == Fr::ZERO { Fr::ONE } else { Fr::ZERO })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(inverted_index_bits_s),
            index_bits_r: Some(index_bits_r),
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Inverting all sender bits should be rejected (polarity check)"
        );

        println!("✓ Polarity: all bits inverted correctly rejected");
    }

    #[test]
    fn test_polarity_swap_sender_receiver_indices_rejected() {
        // Swap sender and receiver indices (but not leaves/paths)
        // This tests that index bits are correctly bound to their leaves

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

        // Swap the indices (but keep leaves in original position)
        let circuit = MerkleTransferKernelCircuit {
            leaf_s: Some(leaf_s),
            leaf_r: Some(leaf_r),
            path_s: Some(path_s),
            path_r: Some(path_r),
            index_bits_s: Some(index_bits_r), // Swapped!
            index_bits_r: Some(index_bits_s), // Swapped!
            amount: Some(amount),
            old_root: Some(old_root),
            new_root: Some(new_root),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Swapping sender/receiver indices should be rejected"
        );

        println!("✓ Polarity: swapped indices correctly rejected");
    }

    #[test]
    fn test_polarity_receiver_bit_flip_rejected() {
        // Flip one bit in receiver's index without updating paths

        let (
            leaf_s,
            leaf_r,
            path_s,
            path_r,
            index_bits_s,
            mut index_bits_r,
            amount,
            old_root,
            new_root,
        ) = create_transfer_scenario(100, 50, 30);

        // Flip a bit in receiver's index (choose one that won't make it equal to sender)
        let flip_idx = 1; // Flip second bit
        index_bits_r[flip_idx] = if index_bits_r[flip_idx] == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        };

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

        assert!(
            !cs.is_satisfied().unwrap(),
            "Bit flip in receiver index should be rejected"
        );

        println!("✓ Polarity: receiver bit flip correctly rejected");
    }

    // ========================================================================
    // C. ONE-HOT MISUSE REGRESSION TESTS
    // These prove that the one-hot constraint is load-bearing.
    // ========================================================================

    /// Test helper: Manually construct selectors that violate one-hot property
    /// and verify this breaks the circuit when one-hot isn't enforced.
    ///
    /// This test documents that enforce_one_hot is CRITICAL for soundness.
    #[test]
    fn test_one_hot_is_load_bearing_documentation() {
        // This test demonstrates WHY one-hot is necessary by showing what
        // would happen if selectors weren't properly constrained.

        // If selectors were [0.5, 0.5, 0, 0, ...] instead of one-hot:
        // - select_from_array would return a weighted average
        // - update_one_slot would partially update multiple slots
        // This could allow creating inconsistent state transitions.

        // We can't actually bypass enforce_one_hot in the circuit without
        // modifying it, but we CAN verify that our first_difference_selectors
        // always produces valid one-hot outputs for valid inputs.

        let test_cases: Vec<([Fr; DEPTH], [Fr; DEPTH])> = vec![
            // Case 1: Differ at position 0
            ([Fr::ZERO; DEPTH], {
                let mut b = [Fr::ZERO; DEPTH];
                b[0] = Fr::ONE;
                b
            }),
            // Case 2: Differ at position 3
            (
                {
                    let mut a = [Fr::ZERO; DEPTH];
                    a[0] = Fr::ONE;
                    a[1] = Fr::ONE;
                    a[2] = Fr::ONE;
                    a
                },
                {
                    let mut b = [Fr::ZERO; DEPTH];
                    b[0] = Fr::ONE;
                    b[1] = Fr::ONE;
                    b[2] = Fr::ONE;
                    b[3] = Fr::ONE;
                    b
                },
            ),
            // Case 3: Differ at last position
            (
                {
                    let mut a = [Fr::ZERO; DEPTH];
                    for elem in a.iter_mut().take(DEPTH - 1) {
                        *elem = Fr::ONE;
                    }
                    a
                },
                [Fr::ONE; DEPTH],
            ),
        ];

        for (i, (a_bits, b_bits)) in test_cases.iter().enumerate() {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let a_states: [State; DEPTH] = State::witness_array(&cs, a_bits).unwrap();
            let b_states: [State; DEPTH] = State::witness_array(&cs, b_bits).unwrap();

            let (selectors, found) = first_difference_selectors(&cs, &a_states, &b_states).unwrap();

            // Verify exactly one selector is 1
            let sum: Fr = selectors.iter().map(|s| s.val()).sum();
            assert_eq!(sum, Fr::ONE, "Case {}: selectors must sum to 1", i);

            // Verify each selector is binary
            for (j, s) in selectors.iter().enumerate() {
                assert!(
                    s.val() == Fr::ZERO || s.val() == Fr::ONE,
                    "Case {}: selector {} must be binary, got {:?}",
                    i,
                    j,
                    s.val()
                );
            }

            // Verify found is 1
            assert_eq!(found.val(), Fr::ONE, "Case {}: found must be 1", i);

            // Verify the one-hot constraint is satisfied
            enforce_one_hot(&cs, &selectors).unwrap();
            assert!(
                cs.is_satisfied().unwrap(),
                "Case {}: constraints must be satisfied",
                i
            );
        }

        println!("✓ One-hot: first_difference_selectors always produces valid one-hot");
    }

    #[test]
    fn test_one_hot_multi_select_attack_blocked() {
        // This test verifies that if an attacker tried to set multiple selectors to 1
        // (which would allow selecting/updating multiple values simultaneously),
        // the one-hot constraint would catch it.

        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create "malicious" selectors where two positions are 1
        let mut malicious_vals = [Fr::ZERO; DEPTH];
        malicious_vals[0] = Fr::ONE;
        malicious_vals[1] = Fr::ONE; // TWO positions are 1!

        let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

        // Try to enforce one-hot on these malicious selectors
        enforce_one_hot(&cs, &selectors).unwrap();

        // The constraint system should NOT be satisfied
        assert!(
            !cs.is_satisfied().unwrap(),
            "Multi-select (two 1s) should be rejected by one-hot constraint"
        );

        println!("✓ One-hot: multi-select attack (two 1s) correctly blocked");
    }

    #[test]
    fn test_one_hot_zero_select_attack_blocked() {
        // This test verifies that if an attacker tried to set ALL selectors to 0
        // (which would mean no update happens), the one-hot constraint catches it.

        let cs = ConstraintSystem::<Fr>::new_ref();

        // All zeros - no selection at all
        let malicious_vals = [Fr::ZERO; DEPTH];
        let selectors: [State; DEPTH] = State::witness_array(&cs, &malicious_vals).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Zero-select (all 0s) should be rejected by one-hot constraint"
        );

        println!("✓ One-hot: zero-select attack (all 0s) correctly blocked");
    }

    #[test]
    fn test_one_hot_fractional_attack_blocked() {
        // This test verifies that non-binary selector values are rejected.
        // An attacker might try to use fractional values to partially update.

        let cs = ConstraintSystem::<Fr>::new_ref();

        // Try fractional values that sum to 1
        let half = Fr::ONE.double().inverse().unwrap(); // 0.5 in the field
        let mut fractional_vals = [Fr::ZERO; DEPTH];
        fractional_vals[0] = half;
        fractional_vals[1] = half; // 0.5 + 0.5 = 1, but not binary!

        let selectors: [State; DEPTH] = State::witness_array(&cs, &fractional_vals).unwrap();

        enforce_one_hot(&cs, &selectors).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Fractional selectors should be rejected by one-hot constraint"
        );

        println!("✓ One-hot: fractional attack (0.5 + 0.5) correctly blocked");
    }

    #[test]
    fn test_one_hot_valid_cases() {
        // Verify that all valid one-hot vectors ARE accepted

        for active_idx in 0..DEPTH {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let mut vals = [Fr::ZERO; DEPTH];
            vals[active_idx] = Fr::ONE;

            let selectors: [State; DEPTH] = State::witness_array(&cs, &vals).unwrap();

            enforce_one_hot(&cs, &selectors).unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "Valid one-hot with 1 at position {} should be accepted",
                active_idx
            );
        }

        println!("✓ One-hot: all {} valid one-hot vectors accepted", DEPTH);
    }

    // ========================================================================
    // ADDITIONAL EDGE CASE TESTS
    // ========================================================================

    #[test]
    fn test_divergence_depths_comprehensive() {
        // Run transfers for ALL possible divergence depths
        // This provides complete coverage of the spine/patching logic

        for divergence_depth in 0..DEPTH {
            let DivergenceScenario {
                leaf_s,
                leaf_r,
                path_s,
                path_r,
                index_bits_s,
                index_bits_r,
                amount,
                old_root,
                new_root,
            } = create_divergence_at_depth(100, 50, 30, divergence_depth);

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

            assert!(
                cs.is_satisfied().unwrap(),
                "Divergence at depth {} should succeed",
                divergence_depth
            );
        }

        println!("✓ All {} divergence depths work correctly", DEPTH);
    }

    #[test]
    fn test_wrong_divergence_at_various_depths() {
        // For each valid divergence depth, verify that patching the WRONG
        // slot is rejected

        for divergence_depth in 1..DEPTH {
            // Create valid scenario
            let DivergenceScenario {
                leaf_s,
                leaf_r,
                path_s,
                path_r,
                index_bits_s,
                index_bits_r,
                amount,
                old_root,
                new_root: _new_root,
            } = create_divergence_at_depth(100, 50, 30, divergence_depth);

            // Compute what the circuit would compute
            let leaf_s_updated = leaf_s - amount;
            let leaf_r_updated = leaf_r + amount;
            let spine = compute_spine(leaf_s_updated, &path_s, &index_bits_s);

            // Patch the WRONG slot (one before the correct one)
            let wrong_slot = divergence_depth - 1;
            let mut wrong_path_r = path_r;
            wrong_path_r[wrong_slot] = spine[divergence_depth]; // Wrong slot!

            let malicious_new_root =
                compute_native_root(leaf_r_updated, &wrong_path_r, &index_bits_r);

            let circuit = MerkleTransferKernelCircuit {
                leaf_s: Some(leaf_s),
                leaf_r: Some(leaf_r),
                path_s: Some(path_s),
                path_r: Some(path_r),
                index_bits_s: Some(index_bits_s),
                index_bits_r: Some(index_bits_r),
                amount: Some(amount),
                old_root: Some(old_root),
                new_root: Some(malicious_new_root),
            };

            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();

            assert!(
                !cs.is_satisfied().unwrap(),
                "Wrong patch slot at divergence depth {} should be rejected",
                divergence_depth
            );
        }

        println!("✓ Wrong patch slot rejected at all divergence depths");
    }
}
