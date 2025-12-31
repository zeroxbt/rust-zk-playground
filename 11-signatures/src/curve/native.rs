use ark_bls12_381::Fr;
use ark_ff::Field;

use crate::curve::spec::{D, Point};

pub fn add(p: &Point, q: &Point) -> Point {
    let x = (p.x() * q.y() + p.y() * q.x()) / (Fr::ONE + D * p.x() * q.x() * p.y() * q.y());
    let y = (p.y() * q.y() + p.x() * q.x()) / (Fr::ONE - D * p.x() * q.x() * p.y() * q.y());
    Point::new(x, y)
}

pub fn double(p: &Point) -> Point {
    add(p, p)
}

pub fn scalar_mul(scalar_bits_be: &[bool], point: &Point) -> Point {
    let mut result = Point::identity();
    for bit in scalar_bits_be.iter() {
        result = add(&result, &result);
        if *bit {
            result = add(&result, point);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::spec::Point;

    // ============================================================
    // POINT ADDITION - IDENTITY TESTS
    // ============================================================

    #[test]
    fn test_add_generator_and_identity() {
        let g = Point::generator();
        let id = Point::identity();
        let result = add(&g, &id);
        assert_eq!(result, g, "G + O should equal G");
    }

    #[test]
    fn test_add_identity_and_generator() {
        let g = Point::generator();
        let id = Point::identity();
        let result = add(&id, &g);
        assert_eq!(result, g, "O + G should equal G");
    }

    #[test]
    fn test_add_identity_and_identity() {
        let id = Point::identity();
        let result = add(&id, &id);
        assert_eq!(result, id, "O + O should equal O");
    }

    // ============================================================
    // POINT ADDITION - BASIC TESTS
    // ============================================================

    #[test]
    fn test_add_generator_to_itself_is_on_curve() {
        let g = Point::generator();
        let result = add(&g, &g);
        assert!(result.is_on_curve(), "2G should be on curve");
    }

    #[test]
    fn test_add_generator_and_negation_is_identity() {
        let g = Point::generator();
        let neg_g = g.negate();
        let result = add(&g, &neg_g);
        assert_eq!(result, Point::identity(), "G + (-G) should equal O");
    }

    #[test]
    fn test_add_negation_and_generator_is_identity() {
        let g = Point::generator();
        let neg_g = g.negate();
        let result = add(&neg_g, &g);
        assert_eq!(result, Point::identity(), "(-G) + G should equal O");
    }

    // ============================================================
    // POINT ADDITION - COMMUTATIVITY AND ASSOCIATIVITY
    // ============================================================

    #[test]
    fn test_add_is_commutative() {
        let g = Point::generator();
        let two_g = add(&g, &g);

        let result1 = add(&g, &two_g);
        let result2 = add(&two_g, &g);

        assert_eq!(result1, result2, "Addition should be commutative");
    }

    #[test]
    fn test_add_is_associative() {
        let g = Point::generator();
        let two_g = add(&g, &g);

        // (G + G) + G
        let left = add(&two_g, &g);
        // G + (G + G)
        let right = add(&g, &two_g);

        assert_eq!(left, right, "Addition should be associative");
    }

    #[test]
    fn test_add_associativity_three_different_points() {
        let g = Point::generator();
        let two_g = add(&g, &g);
        let three_g = add(&two_g, &g);

        // (G + 2G) + 3G
        let left = add(&add(&g, &two_g), &three_g);
        // G + (2G + 3G)
        let right = add(&g, &add(&two_g, &three_g));

        assert_eq!(
            left, right,
            "Addition should be associative for different points"
        );
    }

    // ============================================================
    // DOUBLE TESTS
    // ============================================================

    #[test]
    fn test_double_equals_add_to_self() {
        let g = Point::generator();
        let doubled = double(&g);
        let added = add(&g, &g);
        assert_eq!(doubled, added, "double(G) should equal G + G");
    }

    #[test]
    fn test_double_identity_is_identity() {
        let id = Point::identity();
        let result = double(&id);
        assert_eq!(result, id, "double(O) should equal O");
    }

    #[test]
    fn test_double_result_is_on_curve() {
        let g = Point::generator();
        let result = double(&g);
        assert!(result.is_on_curve(), "double(G) should be on curve");
    }

    #[test]
    fn test_double_twice_is_4g() {
        let g = Point::generator();
        let two_g = double(&g);
        let four_g = double(&two_g);

        // 4G via repeated addition
        let four_g_manual = add(&add(&add(&g, &g), &g), &g);

        assert_eq!(four_g, four_g_manual, "double(double(G)) should equal 4G");
    }

    // ============================================================
    // SCALAR MULTIPLICATION - BASIC TESTS
    // ============================================================

    #[test]
    fn test_scalar_mul_by_zero() {
        let g = Point::generator();
        let result = scalar_mul(&[], &g);
        assert_eq!(result, Point::identity(), "[0]G should equal O");
    }

    #[test]
    fn test_scalar_mul_by_one() {
        let g = Point::generator();
        // 1 in binary (big-endian) is [true]
        let result = scalar_mul(&[true], &g);
        assert_eq!(result, g, "[1]G should equal G");
    }

    #[test]
    fn test_scalar_mul_by_two() {
        let g = Point::generator();
        // 2 in binary (big-endian) is [true, false]
        let result = scalar_mul(&[true, false], &g);
        let expected = double(&g);
        assert_eq!(result, expected, "[2]G should equal 2G");
    }

    #[test]
    fn test_scalar_mul_by_three() {
        let g = Point::generator();
        // 3 in binary (big-endian) is [true, true]
        let result = scalar_mul(&[true, true], &g);
        let expected = add(&double(&g), &g);
        assert_eq!(result, expected, "[3]G should equal 3G");
    }

    #[test]
    fn test_scalar_mul_by_four() {
        let g = Point::generator();
        // 4 in binary (big-endian) is [true, false, false]
        let result = scalar_mul(&[true, false, false], &g);
        let expected = double(&double(&g));
        assert_eq!(result, expected, "[4]G should equal 4G");
    }

    #[test]
    fn test_scalar_mul_by_five() {
        let g = Point::generator();
        // 5 in binary (big-endian) is [true, false, true]
        let result = scalar_mul(&[true, false, true], &g);
        let expected = add(&double(&double(&g)), &g);
        assert_eq!(result, expected, "[5]G should equal 5G");
    }

    #[test]
    fn test_scalar_mul_by_seven() {
        let g = Point::generator();
        // 7 in binary (big-endian) is [true, true, true]
        let result = scalar_mul(&[true, true, true], &g);
        // 7G = 4G + 2G + G
        let two_g = double(&g);
        let four_g = double(&two_g);
        let expected = add(&add(&four_g, &two_g), &g);
        assert_eq!(result, expected, "[7]G should equal 7G");
    }

    #[test]
    fn test_scalar_mul_by_eight() {
        let g = Point::generator();
        // 8 in binary (big-endian) is [true, false, false, false]
        let result = scalar_mul(&[true, false, false, false], &g);
        let expected = double(&double(&double(&g)));
        assert_eq!(result, expected, "[8]G should equal 8G");
    }

    // ============================================================
    // SCALAR MULTIPLICATION - PROPERTIES
    // ============================================================

    #[test]
    fn test_scalar_mul_result_is_on_curve() {
        let g = Point::generator();
        // Test several scalars
        for bits in [
            vec![true],
            vec![true, false],
            vec![true, true],
            vec![true, false, true],
            vec![true, true, true, true],
        ] {
            let result = scalar_mul(&bits, &g);
            assert!(result.is_on_curve(), "scalar_mul result should be on curve");
        }
    }

    #[test]
    fn test_scalar_mul_leading_zeros_ignored() {
        let g = Point::generator();
        // [false, false, true] should equal [true] (both represent 1)
        let with_zeros = scalar_mul(&[false, false, true], &g);
        let without_zeros = scalar_mul(&[true], &g);
        assert_eq!(
            with_zeros, without_zeros,
            "Leading zeros should not affect result"
        );
    }

    #[test]
    fn test_scalar_mul_all_zeros_is_identity() {
        let g = Point::generator();
        let result = scalar_mul(&[false, false, false], &g);
        assert_eq!(result, Point::identity(), "All zeros should give identity");
    }

    #[test]
    fn test_scalar_mul_distributive() {
        let g = Point::generator();
        // [2]G + [3]G should equal [5]G
        let two_g = scalar_mul(&[true, false], &g);
        let three_g = scalar_mul(&[true, true], &g);
        let sum = add(&two_g, &three_g);
        let five_g = scalar_mul(&[true, false, true], &g);
        assert_eq!(sum, five_g, "[2]G + [3]G should equal [5]G");
    }

    #[test]
    fn test_scalar_mul_on_identity() {
        let id = Point::identity();
        let result = scalar_mul(&[true, true, true], &id);
        assert_eq!(result, id, "[k]O should equal O for any k");
    }

    // ============================================================
    // LARGER SCALAR TESTS
    // ============================================================

    #[test]
    fn test_scalar_mul_by_sixteen() {
        let g = Point::generator();
        // 16 in binary (big-endian) is [true, false, false, false, false]
        let result = scalar_mul(&[true, false, false, false, false], &g);
        let expected = double(&double(&double(&double(&g))));
        assert_eq!(result, expected, "[16]G should equal 16G");
    }

    #[test]
    fn test_scalar_mul_consistency() {
        let g = Point::generator();
        // Compute 10G two ways:
        // 1. scalar_mul with bits [true, false, true, false]
        // 2. [8]G + [2]G
        let ten_g_direct = scalar_mul(&[true, false, true, false], &g);
        let eight_g = scalar_mul(&[true, false, false, false], &g);
        let two_g = scalar_mul(&[true, false], &g);
        let ten_g_sum = add(&eight_g, &two_g);
        assert_eq!(
            ten_g_direct, ten_g_sum,
            "10G computed two ways should match"
        );
    }
}
