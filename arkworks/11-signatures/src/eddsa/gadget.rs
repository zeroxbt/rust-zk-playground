use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use hash_preimage::{
    poseidon::native::PoseidonPermutation,
    sponge::gadget::{SpongeGadget, State},
};

use crate::{
    curve::gadget::{PointVar, add, scalar_mul},
    eddsa::spec::{SIG_HASH_DST, SignatureVar},
};

pub fn to_bits_le_fixed(
    cs: &ConstraintSystemRef<Fr>,
    s: State,
) -> Result<[State; 256], SynthesisError> {
    let val_bigint = s.val().into_bigint();
    let bits_le = val_bigint.to_bits_le();
    // Build weighted sum Σ b_i * 2^i
    let mut acc = LinearCombination::<Fr>::zero();

    let mut pow2 = Fr::ONE;
    let two = Fr::from(2u64);

    let mut b_states = [State::zero(); 256];

    for (i, b) in b_states.iter_mut().enumerate() {
        let &b_val = bits_le.get(i).ok_or(SynthesisError::AssignmentMissing)?;
        let b_val = if b_val { Fr::ONE } else { Fr::ZERO };
        *b = State::witness(cs, b_val)?;

        cs.enforce_constraint(
            LinearCombination::from(b.var()),
            LinearCombination::from(b.var()) - (Fr::ONE, Variable::One),
            LinearCombination::zero(),
        )?;

        acc += (pow2, b.var());
        pow2 *= two;
    }

    cs.enforce_constraint(
        acc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(s.var()),
    )?;

    Ok(b_states)
}

pub fn verify(
    cs: &ConstraintSystemRef<Fr>,
    pk: &PointVar,
    msg: State,
    signature: &SignatureVar,
) -> Result<(), SynthesisError> {
    let sponge = SpongeGadget::<PoseidonPermutation, 3, 2>::default();

    let h_fr = sponge.hash_with_dst(
        cs,
        &[signature.r().x(), signature.r().y(), pk.x(), pk.y(), msg],
        Some(SIG_HASH_DST),
        1,
    )?;

    let lhs = scalar_mul(cs, signature.s(), &PointVar::generator(cs)?)?;
    let mut scalar_bits = to_bits_le_fixed(cs, h_fr)?;
    scalar_bits.reverse();
    let rhs = add(cs, signature.r(), &scalar_mul(cs, &scalar_bits, pk)?)?;

    cs.enforce_constraint(
        LinearCombination::from(lhs.x().var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(rhs.x().var()),
    )?;

    cs.enforce_constraint(
        LinearCombination::from(lhs.y().var()),
        LinearCombination::from(Variable::One),
        LinearCombination::from(rhs.y().var()),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;
    use crate::{
        curve::{native as curve_native, scalar::Scalar, spec::Point},
        eddsa::native as eddsa_native,
    };

    // ============================================================
    // HELPERS
    // ============================================================

    fn sample_keypair() -> (Fr, Point) {
        let sk = Fr::from(123456789u64);
        let sk_scalar = Scalar::from_fr_reduced(sk);
        let pk = curve_native::scalar_mul(&sk_scalar.to_bits_be::<256>(), &Point::generator());
        (sk, pk)
    }

    fn witness_bits_fixed(cs: &ConstraintSystemRef<Fr>, bits: &[bool]) -> [State; 256] {
        let mut result = [State::zero(); 256];
        for (i, &b) in bits.iter().enumerate() {
            result[i] = State::witness(cs, if b { Fr::ONE } else { Fr::ZERO }).unwrap();
        }
        result
    }

    // ============================================================
    // BASIC VERIFY TESTS
    // ============================================================

    #[test]
    fn test_verify_valid_signature() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        // Sign natively
        let sig = eddsa_native::sign(sk, msg);

        // Witness inputs
        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        // Verify in circuit
        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(cs.is_satisfied().unwrap(), "Valid signature should verify");
        println!("✓ Valid signature verified");
        println!("  Constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_verify_different_messages() {
        for i in 0..5 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let (sk, pk) = sample_keypair();
            let msg = Fr::from(i as u64 * 1000);

            let sig = eddsa_native::sign(sk, msg);

            let pk_var = PointVar::from_point(&cs, &pk).unwrap();
            let msg_var = State::witness(&cs, msg).unwrap();
            let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
            let s_bits = witness_bits_fixed(&cs, sig.s());

            verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

            assert!(cs.is_satisfied().unwrap(), "Signature {} should verify", i);
        }
        println!("✓ Multiple messages verified");
    }

    #[test]
    fn test_verify_different_keys() {
        for i in 1..5 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let sk = Fr::from(i as u64 * 11111);
            let sk_scalar = Scalar::from_fr_reduced(sk);
            let pk = curve_native::scalar_mul(&sk_scalar.to_bits_be::<256>(), &Point::generator());
            let msg = Fr::from(42u64);

            let sig = eddsa_native::sign(sk, msg);

            let pk_var = PointVar::from_point(&cs, &pk).unwrap();
            let msg_var = State::witness(&cs, msg).unwrap();
            let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
            let s_bits = witness_bits_fixed(&cs, sig.s());

            verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

            assert!(cs.is_satisfied().unwrap(), "Key {} should verify", i);
        }
        println!("✓ Multiple keys verified");
    }

    // ============================================================
    // INVALID SIGNATURE TESTS
    // ============================================================

    #[test]
    fn test_verify_wrong_message_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);
        let wrong_msg = Fr::from(43u64);

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, wrong_msg).unwrap(); // Wrong message
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Wrong message should fail");
        println!("✓ Wrong message rejected");
    }

    #[test]
    fn test_verify_wrong_public_key_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, _) = sample_keypair();
        let msg = Fr::from(42u64);

        // Different key
        let wrong_sk = Fr::from(987654321u64);
        let wrong_sk_scalar = Scalar::from_fr_reduced(wrong_sk);
        let wrong_pk =
            curve_native::scalar_mul(&wrong_sk_scalar.to_bits_be::<256>(), &Point::generator());

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &wrong_pk).unwrap(); // Wrong PK
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Wrong public key should fail");
        println!("✓ Wrong public key rejected");
    }

    #[test]
    fn test_verify_tampered_r_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        let sig = eddsa_native::sign(sk, msg);

        // Tamper with R
        let wrong_r = Point::generator();

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, &wrong_r).unwrap(); // Wrong R
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Tampered R should fail");
        println!("✓ Tampered R rejected");
    }

    #[test]
    fn test_verify_tampered_s_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        let sig = eddsa_native::sign(sk, msg);

        // Tamper with s - flip first bit
        let mut wrong_s = *sig.s();
        wrong_s[0] = !wrong_s[0];

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, &wrong_s); // Wrong s

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Tampered s should fail");
        println!("✓ Tampered s rejected");
    }

    #[test]
    fn test_verify_negated_r_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, &sig.r().negate()).unwrap(); // Negated R
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Negated R should fail");
        println!("✓ Negated R rejected");
    }

    #[test]
    fn test_verify_all_zero_s_fails() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        let sig = eddsa_native::sign(sk, msg);

        // All zeros for s
        let zero_s = vec![false; 256];

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, &zero_s);

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Zero s should fail");
        println!("✓ Zero s rejected");
    }

    // ============================================================
    // EDGE CASES
    // ============================================================

    #[test]
    fn test_verify_zero_message() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::ZERO;

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(cs.is_satisfied().unwrap(), "Zero message should verify");
        println!("✓ Zero message verified");
    }

    #[test]
    fn test_verify_one_message() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::ONE;

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(cs.is_satisfied().unwrap(), "One message should verify");
        println!("✓ One message verified");
    }

    // ============================================================
    // CONSTRAINT COUNT
    // ============================================================

    #[test]
    fn test_verify_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        let sig = eddsa_native::sign(sk, msg);

        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        let before = cs.num_constraints();
        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();
        let after = cs.num_constraints();

        let verify_constraints = after - before;
        println!("verify() uses {} constraints", verify_constraints);

        // Expected breakdown:
        // - Poseidon hash: ~300 constraints
        // - [s]G scalar_mul: 256 * 16 = 4096 constraints
        // - h bit decomposition: 256 * 2 + 1 = 513 constraints
        // - [h]PK scalar_mul: 256 * 16 = 4096 constraints
        // - R + [h]PK add: 7 constraints
        // - Equality check: 2 constraints
        // Total: ~9000+ constraints
    }

    // ============================================================
    // CONSISTENCY WITH NATIVE
    // ============================================================

    #[test]
    fn test_gadget_consistent_with_native() {
        let (sk, pk) = sample_keypair();
        let msg = Fr::from(42u64);

        // Sign natively
        let sig = eddsa_native::sign(sk, msg);

        // Verify natively
        let native_result = eddsa_native::verify(&pk, msg, &sig);
        assert!(native_result, "Native verify should pass");

        // Verify in circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pk_var = PointVar::from_point(&cs, &pk).unwrap();
        let msg_var = State::witness(&cs, msg).unwrap();
        let r_var = PointVar::from_point(&cs, sig.r()).unwrap();
        let s_bits = witness_bits_fixed(&cs, sig.s());

        verify(&cs, &pk_var, msg_var, &SignatureVar::new(r_var, s_bits)).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit verify should match native"
        );
        println!("✓ Gadget consistent with native");
    }
}
