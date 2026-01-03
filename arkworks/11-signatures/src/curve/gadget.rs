use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::curve::spec::{D, Point};

#[derive(Clone, Debug)]
pub struct PointVar {
    x: State,
    y: State,
}

impl PointVar {
    pub fn x(&self) -> State {
        self.x
    }

    pub fn y(&self) -> State {
        self.y
    }

    pub fn new(x: State, y: State) -> Self {
        Self { x, y }
    }

    pub fn identity() -> Self {
        Self {
            x: State::zero(),
            y: State::one(),
        }
    }

    pub fn from_point(cs: &ConstraintSystemRef<Fr>, p: &Point) -> Result<Self, SynthesisError> {
        let x = State::witness(cs, p.x())?;
        let y = State::witness(cs, p.y())?;
        Ok(Self { x, y })
    }

    pub fn from_point_input(
        cs: &ConstraintSystemRef<Fr>,
        p: &Point,
    ) -> Result<Self, SynthesisError> {
        let x = State::input(cs, p.x())?;
        let y = State::input(cs, p.y())?;
        Ok(Self { x, y })
    }

    pub fn generator(cs: &ConstraintSystemRef<Fr>) -> Result<Self, SynthesisError> {
        Self::from_point(cs, &Point::generator())
    }

    pub fn negate(&self, cs: &ConstraintSystemRef<Fr>) -> Result<Self, SynthesisError> {
        let neg_x = State::witness(cs, -self.x().val())?;
        cs.enforce_constraint(
            LinearCombination::from(self.x.var()) + neg_x.var(),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        Ok(Self {
            x: neg_x,
            y: self.y,
        })
    }
}

pub fn add(
    cs: &ConstraintSystemRef<Fr>,
    p: &PointVar,
    q: &PointVar,
) -> Result<PointVar, SynthesisError> {
    let pxqy = State::witness(cs, p.x.val() * q.y.val())?;
    let pyqx = State::witness(cs, p.y.val() * q.x.val())?;
    let pyqy = State::witness(cs, p.y.val() * q.y.val())?;
    let pxqx = State::witness(cs, p.x.val() * q.x.val())?;
    let pxqxpyqy = State::witness(cs, pxqx.val() * pyqy.val())?;

    cs.enforce_constraint(
        LinearCombination::from(p.x.var()),
        LinearCombination::from(q.y.var()),
        LinearCombination::from(pxqy.var()),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(p.y.var()),
        LinearCombination::from(q.x.var()),
        LinearCombination::from(pyqx.var()),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(p.y.var()),
        LinearCombination::from(q.y.var()),
        LinearCombination::from(pyqy.var()),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(p.x.var()),
        LinearCombination::from(q.x.var()),
        LinearCombination::from(pxqx.var()),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(pxqx.var()),
        LinearCombination::from(pyqy.var()),
        LinearCombination::from(pxqxpyqy.var()),
    )?;

    let x = State::witness(
        cs,
        (pxqy.val() + pyqx.val()) / (Fr::ONE + D * pxqxpyqy.val()),
    )?;
    let y = State::witness(
        cs,
        (pyqy.val() + pxqx.val()) / (Fr::ONE - D * pxqxpyqy.val()),
    )?;

    cs.enforce_constraint(
        LinearCombination::from(x.var()),
        LinearCombination::from(Variable::One) + (D, pxqxpyqy.var()),
        LinearCombination::from(pxqy.var()) + pyqx.var(),
    )?;
    cs.enforce_constraint(
        LinearCombination::from(y.var()),
        LinearCombination::from(Variable::One) + (-D, pxqxpyqy.var()),
        LinearCombination::from(pyqy.var()) + pxqx.var(),
    )?;

    Ok(PointVar::new(x, y))
}

/// Select between two points based on a bit.
///
/// If bit {return p1} else {return p0}
/// Precondition: b ∈ {0,1}
pub fn select(
    cs: &ConstraintSystemRef<Fr>,
    bit: &State,
    p1: &PointVar,
    p0: &PointVar,
) -> Result<PointVar, SynthesisError> {
    let out_x_val = if bit.val() == Fr::ONE {
        p1.x.val()
    } else {
        p0.x.val()
    };
    let out_x = State::witness(cs, out_x_val)?;

    cs.enforce_constraint(
        LinearCombination::from(bit.var()),
        LinearCombination::from(p1.x.var()) - p0.x.var(),
        LinearCombination::from(out_x.var()) - p0.x.var(),
    )?;

    let out_y_val = if bit.val() == Fr::ONE {
        p1.y.val()
    } else {
        p0.y.val()
    };
    let out_y = State::witness(cs, out_y_val)?;

    cs.enforce_constraint(
        LinearCombination::from(bit.var()),
        LinearCombination::from(p1.y.var()) - p0.y.var(),
        LinearCombination::from(out_y.var()) - p0.y.var(),
    )?;

    Ok(PointVar::new(out_x, out_y))
}

/// Scalar multiplication via double-and-add.
///
/// Precondition: b ∈ {0,1}
pub fn scalar_mul(
    cs: &ConstraintSystemRef<Fr>,
    scalar_bits_be: &[State],
    point: &PointVar,
) -> Result<PointVar, SynthesisError> {
    let mut result = PointVar::identity();
    for bit in scalar_bits_be.iter() {
        let p0 = add(cs, &result, &result)?;
        let p1 = add(cs, &p0, point)?;

        result = select(cs, bit, &p1, &p0)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use ark_ff::AdditiveGroup;
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;
    use crate::curve::{native, spec::Point};

    // ============================================================
    // HELPER
    // ============================================================

    fn assert_point_eq(pv: &PointVar, p: &Point, msg: &str) {
        assert_eq!(pv.x.val(), p.x(), "{} - x mismatch", msg);
        assert_eq!(pv.y.val(), p.y(), "{} - y mismatch", msg);
    }

    // ============================================================
    // POINTVAR BASIC TESTS
    // ============================================================

    #[test]
    fn test_identity_coordinates() {
        let id = PointVar::identity();
        assert_eq!(id.x.val(), Fr::ZERO);
        assert_eq!(id.y.val(), Fr::ONE);
    }

    #[test]
    fn test_from_point() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let p = Point::generator();
        let pv = PointVar::from_point(&cs, &p).unwrap();

        assert_eq!(pv.x.val(), p.x());
        assert_eq!(pv.y.val(), p.y());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_generator() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let gv = PointVar::generator(&cs).unwrap();
        let g = Point::generator();

        assert_eq!(gv.x.val(), g.x());
        assert_eq!(gv.y.val(), g.y());
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // NEGATE TESTS
    // ============================================================

    #[test]
    fn test_negate_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let gv = PointVar::from_point(&cs, &g).unwrap();

        let neg_gv = gv.negate(&cs).unwrap();
        let neg_g = g.negate();

        assert_point_eq(&neg_gv, &neg_g, "negate(G)");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_negate_identity() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let id = Point::identity();
        let idv = PointVar::from_point(&cs, &id).unwrap();

        let neg_idv = idv.negate(&cs).unwrap();

        assert_point_eq(&neg_idv, &id, "negate(identity)");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // ADD - CONSISTENCY WITH NATIVE
    // ============================================================

    #[test]
    fn test_add_matches_native_g_plus_g() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let result_var = add(&cs, &gv, &gv).unwrap();

        let result_native = native::add(&g, &g);

        assert_point_eq(&result_var, &result_native, "G + G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_add_matches_native_g_plus_2g() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();

        let result_var = add(&cs, &gv, &two_gv).unwrap();
        let result_native = native::add(&g, &two_g);

        assert_point_eq(&result_var, &result_native, "G + 2G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_add_matches_native_chain() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        // Compute 4G natively: G + G + G + G
        let two_g = native::add(&g, &g);
        let three_g = native::add(&two_g, &g);
        let four_g = native::add(&three_g, &g);

        // Compute 4G via gadget
        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = add(&cs, &gv, &gv).unwrap();
        let three_gv = add(&cs, &two_gv, &gv).unwrap();
        let four_gv = add(&cs, &three_gv, &gv).unwrap();

        assert_point_eq(&four_gv, &four_g, "4G via chain");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // ADD - IDENTITY BEHAVIOR
    // ============================================================

    #[test]
    fn test_add_identity_left() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let id = Point::identity();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let idv = PointVar::from_point(&cs, &id).unwrap();

        let result = add(&cs, &idv, &gv).unwrap();

        assert_point_eq(&result, &g, "O + G = G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_add_identity_right() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let id = Point::identity();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let idv = PointVar::from_point(&cs, &id).unwrap();

        let result = add(&cs, &gv, &idv).unwrap();

        assert_point_eq(&result, &g, "G + O = G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_add_identity_plus_identity() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let id = Point::identity();

        let idv1 = PointVar::from_point(&cs, &id).unwrap();
        let idv2 = PointVar::from_point(&cs, &id).unwrap();

        let result = add(&cs, &idv1, &idv2).unwrap();

        assert_point_eq(&result, &id, "O + O = O");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // ADD - NEGATION
    // ============================================================

    #[test]
    fn test_add_point_plus_negation() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let neg_g = g.negate();
        let id = Point::identity();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let neg_gv = PointVar::from_point(&cs, &neg_g).unwrap();

        let result = add(&cs, &gv, &neg_gv).unwrap();

        assert_point_eq(&result, &id, "G + (-G) = O");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // ADD - COMMUTATIVITY
    // ============================================================

    #[test]
    fn test_add_is_commutative() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();

        let result1 = add(&cs, &gv, &two_gv).unwrap();
        let result2 = add(&cs, &two_gv, &gv).unwrap();

        assert_eq!(result1.x.val(), result2.x.val(), "commutativity x");
        assert_eq!(result1.y.val(), result2.y.val(), "commutativity y");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // ADD - ASSOCIATIVITY
    // ============================================================

    #[test]
    fn test_add_is_associative() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);
        let three_g = native::add(&two_g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();
        let three_gv = PointVar::from_point(&cs, &three_g).unwrap();

        // (G + 2G) + 3G
        let left_inner = add(&cs, &gv, &two_gv).unwrap();
        let left = add(&cs, &left_inner, &three_gv).unwrap();

        // G + (2G + 3G)
        let right_inner = add(&cs, &two_gv, &three_gv).unwrap();
        let right = add(&cs, &gv, &right_inner).unwrap();

        assert_eq!(left.x.val(), right.x.val(), "associativity x");
        assert_eq!(left.y.val(), right.y.val(), "associativity y");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // CONSTRAINT COUNT
    // ============================================================

    #[test]
    fn test_add_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let before = cs.num_constraints();

        let _ = add(&cs, &gv, &gv).unwrap();

        let after = cs.num_constraints();
        let add_constraints = after - before;

        println!("add() uses {} constraints", add_constraints);
        assert_eq!(add_constraints, 7, "add should use exactly 7 constraints");
    }

    // ============================================================
    // SOUNDNESS - WRONG WITNESSES SHOULD FAIL
    // ============================================================

    #[test]
    fn test_add_wrong_witness_rejected() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // Compute correct intermediate values
        let pxqy = State::witness(&cs, g.x() * g.y()).unwrap();
        let pyqx = State::witness(&cs, g.y() * g.x()).unwrap();
        let pyqy = State::witness(&cs, g.y() * g.y()).unwrap();
        let pxqx = State::witness(&cs, g.x() * g.x()).unwrap();
        let pxqxpyqy = State::witness(&cs, pxqx.val() * pyqy.val()).unwrap();

        // Constrain products correctly
        cs.enforce_constraint(
            LinearCombination::from(gv.x.var()),
            LinearCombination::from(gv.y.var()),
            LinearCombination::from(pxqy.var()),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(gv.y.var()),
            LinearCombination::from(gv.x.var()),
            LinearCombination::from(pyqx.var()),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(gv.y.var()),
            LinearCombination::from(gv.y.var()),
            LinearCombination::from(pyqy.var()),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(gv.x.var()),
            LinearCombination::from(gv.x.var()),
            LinearCombination::from(pxqx.var()),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(pxqx.var()),
            LinearCombination::from(pyqy.var()),
            LinearCombination::from(pxqxpyqy.var()),
        )
        .unwrap();

        // Witness WRONG x value
        let wrong_x = State::witness(&cs, Fr::from(12345u64)).unwrap();
        let correct_y = State::witness(
            &cs,
            (pyqy.val() + pxqx.val()) / (Fr::ONE - D * pxqxpyqy.val()),
        )
        .unwrap();

        // Constrain with wrong x
        cs.enforce_constraint(
            LinearCombination::from(wrong_x.var()),
            LinearCombination::from(Variable::One) + (D, pxqxpyqy.var()),
            LinearCombination::from(pxqy.var()) + pyqx.var(),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(correct_y.var()),
            LinearCombination::from(Variable::One) + (-D, pxqxpyqy.var()),
            LinearCombination::from(pyqy.var()) + pxqx.var(),
        )
        .unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Wrong x witness should not satisfy constraints"
        );
    }

    // ============================================================
    // SELECT TESTS
    // ============================================================

    #[test]
    fn test_select_bit_one_returns_first() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();
        let bit = State::witness(&cs, Fr::ONE).unwrap();

        let result = select(&cs, &bit, &gv, &two_gv).unwrap();

        assert_point_eq(&result, &g, "select(1, G, 2G) = G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select_bit_zero_returns_second() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();
        let bit = State::witness(&cs, Fr::ZERO).unwrap();

        let result = select(&cs, &bit, &gv, &two_gv).unwrap();

        assert_point_eq(&result, &two_g, "select(0, G, 2G) = 2G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select_same_point() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let bit = State::witness(&cs, Fr::ONE).unwrap();

        let result = select(&cs, &bit, &gv, &gv).unwrap();

        assert_point_eq(&result, &g, "select(1, G, G) = G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::add(&g, &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let two_gv = PointVar::from_point(&cs, &two_g).unwrap();
        let bit = State::witness(&cs, Fr::ONE).unwrap();

        let before = cs.num_constraints();
        let _ = select(&cs, &bit, &gv, &two_gv).unwrap();
        let after = cs.num_constraints();

        assert_eq!(after - before, 2, "select should use 2 constraints");
    }

    // ============================================================
    // SCALAR_MUL - BASIC TESTS
    // ============================================================

    #[test]
    fn test_scalar_mul_by_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        let bits: Vec<State> = vec![];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &Point::identity(), "[0]G = O");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_one() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 1 in big-endian binary is [true] -> [1]
        let bits = vec![State::witness(&cs, Fr::ONE).unwrap()];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &g, "[1]G = G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_two() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let two_g = native::double(&g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 2 in big-endian binary is [1, 0]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &two_g, "[2]G = 2G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_three() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let three_g = native::add(&native::double(&g), &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 3 in big-endian binary is [1, 1]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &three_g, "[3]G = 3G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_four() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let four_g = native::double(&native::double(&g));

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 4 in big-endian binary is [1, 0, 0]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &four_g, "[4]G = 4G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_five() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let five_g = native::add(&native::double(&native::double(&g)), &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 5 in big-endian binary is [1, 0, 1]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &five_g, "[5]G = 5G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_seven() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        // 7G = 4G + 2G + G
        let two_g = native::double(&g);
        let four_g = native::double(&two_g);
        let seven_g = native::add(&native::add(&four_g, &two_g), &g);

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 7 in big-endian binary is [1, 1, 1]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &seven_g, "[7]G = 7G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_by_eight() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let eight_g = native::double(&native::double(&native::double(&g)));

        let gv = PointVar::from_point(&cs, &g).unwrap();
        // 8 in big-endian binary is [1, 0, 0, 0]
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &eight_g, "[8]G = 8G");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // SCALAR_MUL - CONSISTENCY WITH NATIVE
    // ============================================================

    #[test]
    fn test_scalar_mul_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // Test scalar 42 = 0b101010
        let scalar_bits_native = vec![true, false, true, false, true, false];
        let scalar_bits_gadget: Vec<State> = scalar_bits_native
            .iter()
            .map(|&b| State::witness(&cs, if b { Fr::ONE } else { Fr::ZERO }).unwrap())
            .collect();

        let result_gadget = scalar_mul(&cs, &scalar_bits_gadget, &gv).unwrap();
        let result_native = native::scalar_mul(&scalar_bits_native, &g);

        assert_point_eq(&result_gadget, &result_native, "[42]G");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_matches_native_larger() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // Test scalar 255 = 0b11111111
        let scalar_bits_native = vec![true, true, true, true, true, true, true, true];
        let scalar_bits_gadget: Vec<State> = scalar_bits_native
            .iter()
            .map(|&b| State::witness(&cs, if b { Fr::ONE } else { Fr::ZERO }).unwrap())
            .collect();

        let result_gadget = scalar_mul(&cs, &scalar_bits_gadget, &gv).unwrap();
        let result_native = native::scalar_mul(&scalar_bits_native, &g);

        assert_point_eq(&result_gadget, &result_native, "[255]G");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // SCALAR_MUL - LEADING ZEROS
    // ============================================================

    #[test]
    fn test_scalar_mul_leading_zeros() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // [0, 0, 1] and [1] should both give G
        let bits_with_zeros = vec![
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];
        let bits_without = vec![State::witness(&cs, Fr::ONE).unwrap()];

        let result_with = scalar_mul(&cs, &bits_with_zeros, &gv).unwrap();
        let result_without = scalar_mul(&cs, &bits_without, &gv).unwrap();

        assert_eq!(
            result_with.x.val(),
            result_without.x.val(),
            "leading zeros x"
        );
        assert_eq!(
            result_with.y.val(),
            result_without.y.val(),
            "leading zeros y"
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_scalar_mul_all_zeros() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        let bits = vec![
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &Point::identity(), "[0]G = O");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // SCALAR_MUL - IDENTITY POINT
    // ============================================================

    #[test]
    fn test_scalar_mul_on_identity() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let id = Point::identity();

        let idv = PointVar::from_point(&cs, &id).unwrap();

        // Any scalar times identity should be identity
        let bits = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];

        let result = scalar_mul(&cs, &bits, &idv).unwrap();

        assert_point_eq(&result, &id, "[k]O = O");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // SCALAR_MUL - CONSTRAINT COUNT
    // ============================================================

    #[test]
    fn test_scalar_mul_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // 8-bit scalar
        let bits: Vec<State> = (0..8)
            .map(|_| State::witness(&cs, Fr::ZERO).unwrap())
            .collect();

        let before = cs.num_constraints();
        let _ = scalar_mul(&cs, &bits, &gv).unwrap();
        let after = cs.num_constraints();

        let constraints_per_bit = (after - before) / 8;
        println!(
            "scalar_mul uses {} constraints for 8 bits ({} per bit)",
            after - before,
            constraints_per_bit
        );

        // Expected: 7 (double) + 7 (add) + 2 (select) = 16 per bit
        assert_eq!(constraints_per_bit, 16, "should be 16 constraints per bit");
    }

    // ============================================================
    // SCALAR_MUL - DISTRIBUTIVE PROPERTY
    // ============================================================

    #[test]
    fn test_scalar_mul_distributive() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // [2]G + [3]G should equal [5]G
        // 2 = [1,0], 3 = [1,1], 5 = [1,0,1]
        let bits_2 = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
        ];
        let bits_3 = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];
        let bits_5 = vec![
            State::witness(&cs, Fr::ONE).unwrap(),
            State::witness(&cs, Fr::ZERO).unwrap(),
            State::witness(&cs, Fr::ONE).unwrap(),
        ];

        let two_g = scalar_mul(&cs, &bits_2, &gv).unwrap();
        let three_g = scalar_mul(&cs, &bits_3, &gv).unwrap();
        let five_g = scalar_mul(&cs, &bits_5, &gv).unwrap();

        let sum = add(&cs, &two_g, &three_g).unwrap();

        assert_eq!(sum.x.val(), five_g.x.val(), "distributive x");
        assert_eq!(sum.y.val(), five_g.y.val(), "distributive y");
        assert!(cs.is_satisfied().unwrap());
    }

    // ============================================================
    // SOUNDNESS - NON-BOOLEAN BITS
    // ============================================================

    #[test]
    fn test_scalar_mul_non_boolean_bit_wrong_result() {
        // This test demonstrates that without boolean enforcement,
        // a malicious prover can satisfy constraints but get wrong results.

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();
        let id = Point::identity();

        let idv = PointVar::from_point(&cs, &id).unwrap();
        let gv = PointVar::from_point(&cs, &g).unwrap();

        // After first double: identity + identity = identity
        let doubled = add(&cs, &idv, &idv).unwrap();

        // After add: identity + G = G
        let after_add = add(&cs, &doubled, &gv).unwrap();

        // Malicious: use bit=2 instead of 0 or 1
        let bad_bit = State::witness(&cs, Fr::from(2u64)).unwrap();

        // Compute malicious witness: out = p0 + bit*(p1 - p0)
        // With bit=2, p0=identity, p1=G:
        // out_x = 0 + 2*(Gx - 0) = 2*Gx (field multiplication, NOT point doubling!)
        // out_y = 1 + 2*(Gy - 1) = 2*Gy - 1
        let malicious_x = doubled.x.val() + Fr::from(2u64) * (after_add.x.val() - doubled.x.val());
        let malicious_y = doubled.y.val() + Fr::from(2u64) * (after_add.y.val() - doubled.y.val());

        let out_x = State::witness(&cs, malicious_x).unwrap();
        let out_y = State::witness(&cs, malicious_y).unwrap();

        // These constraints ARE satisfied with bit=2 and malicious witness
        cs.enforce_constraint(
            LinearCombination::from(bad_bit.var()),
            LinearCombination::from(after_add.x.var()) - doubled.x.var(),
            LinearCombination::from(out_x.var()) - doubled.x.var(),
        )
        .unwrap();
        cs.enforce_constraint(
            LinearCombination::from(bad_bit.var()),
            LinearCombination::from(after_add.y.var()) - doubled.y.var(),
            LinearCombination::from(out_y.var()) - doubled.y.var(),
        )
        .unwrap();

        // Constraints are satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "malicious witness satisfies constraints"
        );

        // But the result is WRONG - it's not G (what [1]G should be)
        assert!(
            out_x.val() != g.x() || out_y.val() != g.y(),
            "malicious result should differ from correct [1]G"
        );

        // And it's not even on the curve!
        let malicious_point = Point::new(malicious_x, malicious_y);
        assert!(
            !malicious_point.is_on_curve(),
            "malicious result is not even on the curve"
        );

        println!("✓ Without boolean enforcement, prover can produce invalid results");
    }

    #[test]
    fn test_scalar_mul_with_boolean_enforcement() {
        // This test shows how to properly enforce boolean bits
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // Create bit and enforce it's boolean
        let bit = State::witness(&cs, Fr::ONE).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(bit.var()),
            LinearCombination::from(bit.var()) - Variable::One,
            LinearCombination::zero(),
        )
        .unwrap();

        let bits = vec![bit];
        let result = scalar_mul(&cs, &bits, &gv).unwrap();

        assert_point_eq(&result, &g, "[1]G = G with boolean enforcement");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_non_boolean_bit_fails_with_enforcement() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = Point::generator();

        let gv = PointVar::from_point(&cs, &g).unwrap();

        // Create non-boolean bit and try to enforce it's boolean
        let bad_bit = State::witness(&cs, Fr::from(2u64)).unwrap();
        cs.enforce_constraint(
            LinearCombination::from(bad_bit.var()),
            LinearCombination::from(bad_bit.var()) - Variable::One,
            LinearCombination::zero(),
        )
        .unwrap();

        let bits = vec![bad_bit];
        let _ = scalar_mul(&cs, &bits, &gv).unwrap();

        // Now constraints should NOT be satisfied because 2*(2-1) ≠ 0
        assert!(
            !cs.is_satisfied().unwrap(),
            "non-boolean bit with enforcement should fail"
        );
    }
}
