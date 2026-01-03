use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp};

pub const A: Fr = MontFp!("-1");
pub const D: Fr =
    MontFp!("19257038036680949359750312669786877991949435402254120286184196891950884077233");

#[derive(PartialEq, Debug, Clone)]
pub struct Point {
    x: Fr,
    y: Fr,
}

impl Point {
    pub fn x(&self) -> Fr {
        self.x
    }

    pub fn y(&self) -> Fr {
        self.y
    }

    pub fn new(x: Fr, y: Fr) -> Self {
        Self { x, y }
    }

    pub fn identity() -> Self {
        Self {
            x: Fr::ZERO,
            y: Fr::ONE,
        }
    }

    pub fn generator() -> Self {
        Self {
            x: MontFp!(
                "8076246640662884909881801758704306714034609987455869804520522091855516602923"
            ),
            y: MontFp!(
                "13262374693698910701929044844600465831413122818447359594527400194675274060458"
            ),
        }
    }

    pub fn is_on_curve(&self) -> bool {
        let x_sq = self.x.square();
        let y_sq = self.y.square();
        A * x_sq + y_sq == Fr::ONE + D * x_sq * y_sq
    }

    pub fn negate(&self) -> Self {
        Self {
            x: -Fr::ONE * self.x,
            y: self.y,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    // ============================================================
    // PARAMETER TESTS
    // ============================================================

    #[test]
    fn test_a_is_minus_one() {
        assert_eq!(A, -Fr::ONE);
    }

    #[test]
    fn test_d_is_correct_ratio() {
        // d = -10240 / 10241
        let num = -Fr::from(10240u64);
        let den = Fr::from(10241u64);
        let expected = num * den.inverse().unwrap();
        assert_eq!(D, expected);
    }

    #[test]
    fn test_a_not_equal_d() {
        assert_ne!(A, D);
    }

    // ============================================================
    // IDENTITY POINT TESTS
    // ============================================================

    #[test]
    fn test_identity_coordinates() {
        let id = Point::identity();
        assert_eq!(id.x, Fr::ZERO);
        assert_eq!(id.y, Fr::ONE);
    }

    #[test]
    fn test_identity_is_on_curve() {
        let id = Point::identity();
        assert!(id.is_on_curve(), "Identity point should be on curve");
    }

    // ============================================================
    // GENERATOR POINT TESTS
    // ============================================================

    #[test]
    fn test_generator_is_on_curve() {
        let g = Point::generator();
        assert!(g.is_on_curve(), "Generator point should be on curve");
    }

    #[test]
    fn test_generator_is_not_identity() {
        let g = Point::generator();
        let id = Point::identity();
        assert_ne!(g, id, "Generator should not be identity");
    }

    // ============================================================
    // CURVE EQUATION TESTS
    // ============================================================

    #[test]
    fn test_is_on_curve_rejects_random_point() {
        let bad_point = Point {
            x: Fr::from(12345u64),
            y: Fr::from(67890u64),
        };
        assert!(
            !bad_point.is_on_curve(),
            "Random point should not be on curve"
        );
    }

    #[test]
    fn test_is_on_curve_rejects_origin() {
        let origin = Point {
            x: Fr::ZERO,
            y: Fr::ZERO,
        };
        assert!(!origin.is_on_curve(), "Origin should not be on curve");
    }

    // ============================================================
    // CURVE EQUATION VERIFICATION
    // ============================================================

    #[test]
    fn test_curve_equation_at_identity() {
        let id = Point::identity();
        let lhs = A * id.x.square() + id.y.square();
        let rhs = Fr::ONE + D * id.x.square() * id.y.square();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_curve_equation_at_generator() {
        let g = Point::generator();
        let x_sq = g.x.square();
        let y_sq = g.y.square();
        let lhs = A * x_sq + y_sq;
        let rhs = Fr::ONE + D * x_sq * y_sq;
        assert_eq!(lhs, rhs);
    }

    // ============================================================
    // NEGATION TESTS
    // ============================================================

    #[test]
    fn test_negate_identity_is_identity() {
        let id = Point::identity();
        let neg_id = id.negate();
        assert_eq!(neg_id, id);
    }

    #[test]
    fn test_negate_generator_is_on_curve() {
        let g = Point::generator();
        let neg_g = g.negate();
        assert!(neg_g.is_on_curve(), "Negated generator should be on curve");
    }

    #[test]
    fn test_negate_flips_x_only() {
        let g = Point::generator();
        let neg_g = g.negate();
        assert_eq!(neg_g.x, -g.x);
        assert_eq!(neg_g.y, g.y);
    }

    #[test]
    fn test_double_negate_is_original() {
        let g = Point::generator();
        let double_neg = g.negate().negate();
        assert_eq!(double_neg, g);
    }
}
