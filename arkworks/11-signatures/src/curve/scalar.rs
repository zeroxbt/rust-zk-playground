use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar(BigUint);

impl Scalar {
    /// Jubjub prime-order subgroup size r (Sapling)
    pub fn modulus() -> BigUint {
        BigUint::parse_bytes(
            b"0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7",
            16,
        )
        .expect("valid hex")
    }

    pub fn zero() -> Self {
        Scalar(BigUint::zero())
    }

    pub fn one() -> Self {
        Scalar(BigUint::one())
    }

    pub fn from_fr_reduced(x: Fr) -> Self {
        let n = BigUint::from_bytes_be(&x.into_bigint().to_bytes_be());
        let r = Self::modulus();
        Scalar(n % r)
    }

    pub fn add(&self, rhs: &Scalar) -> Scalar {
        let r = Self::modulus();
        Scalar((&self.0 + &rhs.0) % r)
    }

    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        let r = Self::modulus();
        Scalar((&self.0 * &rhs.0) % r)
    }

    pub fn to_bits_be<const T: usize>(&self) -> [bool; T] {
        let bytes = self.0.to_bytes_be();
        let mut bits = [false; T];

        let mut bit_pos = T;
        for b in bytes.iter().rev() {
            for i in 0..8 {
                if bit_pos == 0 {
                    break;
                }
                bit_pos -= 1;
                bits[bit_pos] = ((b >> i) & 1) == 1;
            }
            if bit_pos == 0 {
                break;
            }
        }
        bits
    }
}

#[test]
fn test_scalar_to_bits_be_fixed() {
    // 5 in binary is 101
    let five = Scalar(BigUint::from(5u64));
    let bits = five.to_bits_be::<8>();
    assert_eq!(bits, [false, false, false, false, false, true, false, true]);
}

#[test]
fn test_scalar_to_bits_be_fixed_larger() {
    // 256 = 2^8 = 100000000 in binary
    let n = Scalar(BigUint::from(256u64));
    let bits = n.to_bits_be::<16>();
    // Should be: 0000000100000000
    assert_eq!(bits[..7], [false; 7]);
    assert!(bits[7]);
    assert_eq!(bits[8..], [false; 8]);
}
