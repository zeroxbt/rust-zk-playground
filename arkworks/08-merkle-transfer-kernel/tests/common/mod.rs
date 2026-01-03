#![allow(dead_code)]

use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
use merkle_membership::merkle::spec::MERKLE_NODE_DST;
use merkle_transfer_kernel::circuit::DEPTH;

/// Compute Merkle root natively for testing
pub fn compute_native_root(leaf: Fr, path: &[Fr], index_bits: &[Fr]) -> Fr {
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
pub fn create_two_leaf_tree(
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
pub fn compute_spine(leaf: Fr, path: &[Fr; DEPTH], index_bits: &[Fr; DEPTH]) -> [Fr; DEPTH] {
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

/// Transfer scenario data
pub struct TransferScenario {
    pub leaf_s: Fr,
    pub leaf_r: Fr,
    pub path_s: [Fr; DEPTH],
    pub path_r: [Fr; DEPTH],
    pub index_bits_s: [Fr; DEPTH],
    pub index_bits_r: [Fr; DEPTH],
    pub amount: Fr,
    pub old_root: Fr,
    pub new_root: Fr,
}

/// Create complete valid transfer data
///
/// IMPORTANT: The circuit internally updates path_r during execution,
/// so we return the ORIGINAL path_r_initial, not the updated one.
/// The circuit will compute the update itself.
pub fn create_transfer_scenario(
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

    TransferScenario {
        leaf_s,
        leaf_r,
        path_s: path_s_initial,
        path_r: path_r_initial,
        index_bits_s,
        index_bits_r,
        amount: amount_fr,
        old_root,
        new_root,
    }
}

/// Divergence scenario for testing various tree depths
pub struct DivergenceScenario {
    pub leaf_s: Fr,
    pub leaf_r: Fr,
    pub path_s: [Fr; DEPTH],
    pub path_r: [Fr; DEPTH],
    pub index_bits_s: [Fr; DEPTH],
    pub index_bits_r: [Fr; DEPTH],
    pub amount: Fr,
    pub old_root: Fr,
    pub new_root: Fr,
}

/// Create a tree where sender and receiver diverge at a specific depth.
///
/// For divergence at depth D:
/// - Sender index bits: all zeros up to D, then 0 at D
/// - Receiver index bits: all zeros up to D, then 1 at D
///
/// This means they share a common path for levels 0..D, then diverge.
pub fn create_divergence_at_depth(
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
