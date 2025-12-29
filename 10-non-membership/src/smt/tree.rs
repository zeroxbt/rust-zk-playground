use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
use merkle_membership::merkle::spec::MERKLE_NODE_DST;

use crate::smt::{
    spec::{NULLIFIER_MARKER, NonMembershipProof, index_bits},
    storage::Storage,
};

pub struct SparseMerkleTree<'a, const D: usize> {
    storage: Storage<D>,
    sponge: SpongeNative<PoseidonPermutation<'a>, 3, 2>,
}

impl<const D: usize> Default for SparseMerkleTree<'_, D> {
    fn default() -> Self {
        let sponge = SpongeNative::default();
        let mut defaults = Vec::with_capacity(D + 1);
        let mut cur = Fr::ZERO;
        for _ in 0..=D {
            defaults.push(cur);
            cur = sponge.hash_with_dst(&[cur, cur], Some(MERKLE_NODE_DST));
        }
        Self {
            storage: Storage::new(defaults),
            sponge,
        }
    }
}

impl<const D: usize> SparseMerkleTree<'_, D> {
    pub fn insert(&mut self, nullifier: Fr) -> bool {
        if self.contains(nullifier) {
            return false;
        }

        let index_bits = index_bits(nullifier);
        let siblings = self.siblings(nullifier);
        let mut cur = NULLIFIER_MARKER;

        self.storage.store(0, index_bits, cur);
        for (level, &sib) in siblings.iter().enumerate() {
            let (left, right) = if index_bits[level] {
                (sib, cur)
            } else {
                (cur, sib)
            };
            cur = self
                .sponge
                .hash_with_dst(&[left, right], Some(MERKLE_NODE_DST));
            self.storage.store(level + 1, index_bits, cur);
        }

        true
    }

    pub fn root(&self) -> Fr {
        self.storage.get(D, [false; D])
    }

    pub fn prove(&self, nullifier: Fr) -> NonMembershipProof<D> {
        NonMembershipProof::new(self.siblings(nullifier), nullifier)
    }

    fn siblings(&self, leaf: Fr) -> [Fr; D] {
        let mut siblings = [Fr::ZERO; D];
        let index_bits = index_bits(leaf);
        for (level, sib) in siblings.iter_mut().enumerate() {
            let mut sib_idx = index_bits;
            sib_idx[level] = !index_bits[level];
            *sib = self.storage.get(level, sib_idx);
        }

        siblings
    }

    pub fn contains(&self, leaf: Fr) -> bool {
        self.storage.contains(0, index_bits(leaf))
    }
}
