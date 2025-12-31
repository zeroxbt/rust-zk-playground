use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::sponge::gadget::State;

use crate::curve::spec::{D, Point};

pub struct PointVar {
    pub x: State,
    pub y: State,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::native;
    use crate::curve::spec::Point;
    use ark_ff::AdditiveGroup;
    use ark_relations::r1cs::ConstraintSystem;

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
}
