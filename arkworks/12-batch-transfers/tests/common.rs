use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use batch_transfers::spec::{AccountProof, MembershipProof, TransferStep};
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};
use merkle_membership::merkle::spec::MERKLE_NODE_DST;
use nullifiers::commitment::{native::create_commitment, spec::LeafData};
use rand::thread_rng;

pub const DEPTH: usize = 4;

#[derive(Default)]
/// Simple sparse Merkle tree for tests
pub struct TestTree<const D: usize> {
    leaves: Vec<(usize, Fr)>, // (index, commitment)
    empty_leaf: Fr,
}

impl<const D: usize> TestTree<D> {
    pub fn insert(&mut self, index: usize, commitment: Fr) {
        self.leaves.retain(|(i, _)| *i != index);
        self.leaves.push((index, commitment));
    }

    fn get_leaf(&self, index: usize) -> Fr {
        self.leaves
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, c)| *c)
            .unwrap_or(self.empty_leaf)
    }

    pub fn index_to_bits(index: usize) -> [Fr; D] {
        let mut bits = [Fr::ZERO; D];
        for (i, b) in bits.iter_mut().enumerate().take(D) {
            if (index >> i) & 1 == 1 {
                *b = Fr::ONE;
            }
        }
        bits
    }

    pub fn compute_root(&self) -> Fr {
        self.compute_node(0, D)
    }

    fn compute_node(&self, node_index: usize, level: usize) -> Fr {
        if level == 0 {
            return self.get_leaf(node_index);
        }

        let left = self.compute_node(node_index * 2, level - 1);
        let right = self.compute_node(node_index * 2 + 1, level - 1);
        hash_pair(left, right)
    }

    pub fn get_path(&self, index: usize) -> [Fr; D] {
        let mut path = [Fr::ZERO; D];
        let mut current_index = index;

        for (level, p) in path.iter_mut().enumerate().take(D) {
            let sibling_index = current_index ^ 1;
            *p = self.compute_node_at_level(sibling_index, level);
            current_index >>= 1;
        }

        path
    }

    fn compute_node_at_level(&self, node_index: usize, level: usize) -> Fr {
        if level == 0 {
            return self.get_leaf(node_index);
        }

        let left = self.compute_node_at_level(node_index * 2, level - 1);
        let right = self.compute_node_at_level(node_index * 2 + 1, level - 1);
        hash_pair(left, right)
    }
}

fn hash_pair(left: Fr, right: Fr) -> Fr {
    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    sponge.hash_with_dst(&[left, right], Some(MERKLE_NODE_DST))
}

#[derive(Clone, Debug)]
pub struct TestAccount {
    pub secret: Fr,
    pub balance: Fr,
    pub salt: Fr,
    pub nonce: Fr,
    pub index: usize,
}

impl TestAccount {
    pub fn random(index: usize, balance: u64) -> Self {
        let mut rng = thread_rng();
        Self {
            secret: Fr::rand(&mut rng),
            balance: Fr::from(balance),
            salt: Fr::rand(&mut rng),
            nonce: Fr::ZERO,
            index,
        }
    }

    pub fn commitment(&self) -> Fr {
        create_commitment(&self.to_leaf_data())
    }

    pub fn to_leaf_data(&self) -> LeafData {
        LeafData::new(self.secret, self.balance, self.salt, self.nonce)
    }

    pub fn with_balance(&self, new_balance: u64) -> Self {
        Self {
            secret: self.secret,
            balance: Fr::from(new_balance),
            salt: self.salt,
            nonce: self.nonce,
            index: self.index,
        }
    }

    pub fn increment_nonce(&self) -> Self {
        Self {
            secret: self.secret,
            balance: self.balance,
            salt: self.salt,
            nonce: self.nonce + Fr::ONE,
            index: self.index,
        }
    }
}

pub fn build_account_proof<const D: usize>(
    account: &TestAccount,
    tree: &TestTree<D>,
) -> AccountProof<D> {
    AccountProof::new(
        account.to_leaf_data(),
        MembershipProof::new(
            TestTree::<D>::index_to_bits(account.index),
            tree.get_path(account.index),
        ),
    )
}

pub fn build_transfer_step<const D: usize>(
    sender: &TestAccount,
    receiver: &TestAccount,
    amount: u64,
    tree: &TestTree<D>,
) -> TransferStep<D> {
    TransferStep::new(
        build_account_proof(sender, tree),
        build_account_proof(receiver, tree),
        Fr::from(amount),
    )
}
