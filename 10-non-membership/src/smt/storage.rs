use std::collections::HashMap;

use ark_bls12_381::Fr;

pub struct Storage<const D: usize> {
    map: HashMap<(usize, [bool; D]), Fr>,
    defaults: Vec<Fr>,
}

impl<const D: usize> Storage<D> {
    pub fn new(defaults: Vec<Fr>) -> Self {
        Self {
            map: HashMap::new(),
            defaults,
        }
    }

    fn normalize_key(level: usize, mut index_bits: [bool; D]) -> [bool; D] {
        for b in index_bits.iter_mut().take(level) {
            *b = false;
        }
        index_bits
    }

    pub fn store(&mut self, level: usize, index_bits: [bool; D], value: Fr) -> Option<Fr> {
        self.map
            .insert((level, Self::normalize_key(level, index_bits)), value)
    }

    pub fn get(&self, level: usize, index_bits: [bool; D]) -> Fr {
        self.map
            .get(&(level, Self::normalize_key(level, index_bits)))
            .copied()
            .unwrap_or(self.defaults[level])
    }

    pub fn contains(&self, level: usize, index_bits: [bool; D]) -> bool {
        self.map.contains_key(&(level, index_bits))
    }
}
