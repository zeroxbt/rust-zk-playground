use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};

pub fn less_than(a: Fr, b: Fr) -> bool {
    let a_bits = a.into_bigint().to_bits_be();
    let b_bits = b.into_bigint().to_bits_be();

    for (&a_bit, b_bit) in a_bits.iter().zip(b_bits) {
        if a_bit != b_bit {
            return !a_bit & b_bit;
        }
    }

    false
}

pub fn verify_sorted_non_membership(nullifier: Fr, lower: Fr, upper: Fr) -> bool {
    less_than(lower, nullifier) && less_than(nullifier, upper)
}
