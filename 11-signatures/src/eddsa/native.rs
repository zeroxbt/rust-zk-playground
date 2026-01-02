use ark_bls12_381::Fr;
use hash_preimage::{poseidon::native::PoseidonPermutation, sponge::native::SpongeNative};

use crate::{
    curve::{
        native::{add, scalar_mul},
        scalar::Scalar,
        spec::Point,
    },
    eddsa::spec::{SIG_HASH_DST, Signature},
};

pub fn sign(sk_fr: Fr, msg: Fr) -> Signature {
    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();
    let g = Point::generator();

    // Secret scalar (mod r)
    let sk = Scalar::from_fr_reduced(sk_fr);

    // r = H(sk_fr, msg) mod r
    let r_fr = sponge.hash_with_dst(&[sk_fr, msg], Some(SIG_HASH_DST));
    let r = Scalar::from_fr_reduced(r_fr);

    let r_point = scalar_mul(&r.to_bits_be::<256>(), &g);
    let pk = scalar_mul(&sk.to_bits_be::<256>(), &g);

    // h = H(R, A, msg) mod r
    let h_fr = sponge.hash_with_dst(
        &[r_point.x(), r_point.y(), pk.x(), pk.y(), msg],
        Some(SIG_HASH_DST),
    );
    let h = Scalar::from_fr_reduced(h_fr);

    // s = r + h*sk mod r
    let s = r.add(&h.mul(&sk));

    Signature::new(r_point, s.to_bits_be::<256>())
}

pub fn verify(pk: &Point, msg: Fr, sig: &Signature) -> bool {
    let sponge = SpongeNative::<PoseidonPermutation, 3, 2>::default();

    let h_fr = sponge.hash_with_dst(
        &[sig.r().x(), sig.r().y(), pk.x(), pk.y(), msg],
        Some(SIG_HASH_DST),
    );
    let h = Scalar::from_fr_reduced(h_fr);

    let lhs = scalar_mul(sig.s(), &Point::generator());
    let rhs = add(sig.r(), &scalar_mul(&h.to_bits_be::<256>(), pk));

    // Cofactor = 8 safety
    mul_by_cofactor_8(&lhs) == mul_by_cofactor_8(&rhs)
}

fn mul_by_cofactor_8(p: &Point) -> Point {
    let p2 = add(p, p);
    let p4 = add(&p2, &p2);
    add(&p4, &p4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::native::scalar_mul;
    use crate::curve::spec::Point;
    use ark_ff::{AdditiveGroup, Field};

    // ============================================================
    // HELPER FUNCTIONS
    // ============================================================

    fn sample_secret_key() -> Fr {
        // A fixed secret key for testing (in practice, this would be random)
        Fr::from(123456789u64)
    }

    fn another_secret_key() -> Fr {
        Fr::from(987654321u64)
    }

    fn sample_message() -> Fr {
        Fr::from(42u64)
    }

    fn another_message() -> Fr {
        Fr::from(12345u64)
    }

    fn public_key_from_secret(sk_fr: Fr) -> Point {
        let sk = Scalar::from_fr_reduced(sk_fr);
        scalar_mul(&sk.to_bits_be::<256>(), &Point::generator())
    }

    // ============================================================
    // BASIC SIGN AND VERIFY
    // ============================================================

    #[test]
    fn test_sign_and_verify_basic() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);
        let valid = verify(&pk, msg, &sig);

        assert!(valid, "Signature should verify for correct message and key");
    }

    #[test]
    fn test_sign_and_verify_different_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = another_message();

        let sig = sign(sk, msg);
        let valid = verify(&pk, msg, &sig);

        assert!(valid, "Signature should verify for different message");
    }

    #[test]
    fn test_sign_and_verify_zero_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = Fr::ZERO;

        let sig = sign(sk, msg);
        let valid = verify(&pk, msg, &sig);

        assert!(valid, "Signature should verify for zero message");
    }

    #[test]
    fn test_sign_and_verify_one_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = Fr::ONE;

        let sig = sign(sk, msg);
        let valid = verify(&pk, msg, &sig);

        assert!(valid, "Signature should verify for message = 1");
    }

    // ============================================================
    // SIGNATURE DETERMINISM
    // ============================================================

    #[test]
    fn test_sign_is_deterministic() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig1 = sign(sk, msg);
        let sig2 = sign(sk, msg);

        assert_eq!(sig1.r(), sig2.r(), "Same inputs should produce same R");
        assert_eq!(sig1.s(), sig2.s(), "Same inputs should produce same s");
    }

    #[test]
    fn test_different_messages_produce_different_signatures() {
        let sk = sample_secret_key();
        let msg1 = sample_message();
        let msg2 = another_message();

        let sig1 = sign(sk, msg1);
        let sig2 = sign(sk, msg2);

        assert!(
            sig1.r() != sig2.r() || sig1.s() != sig2.s(),
            "Different messages should produce different signatures"
        );
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let sk1 = sample_secret_key();
        let sk2 = another_secret_key();
        let msg = sample_message();

        let sig1 = sign(sk1, msg);
        let sig2 = sign(sk2, msg);

        assert!(
            sig1.r() != sig2.r() || sig1.s() != sig2.s(),
            "Different keys should produce different signatures"
        );
    }

    // ============================================================
    // VERIFICATION FAILURES - WRONG MESSAGE
    // ============================================================

    #[test]
    fn test_verify_fails_for_wrong_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();
        let wrong_msg = another_message();

        let sig = sign(sk, msg);
        let valid = verify(&pk, wrong_msg, &sig);

        assert!(!valid, "Signature should not verify for wrong message");
    }

    #[test]
    fn test_verify_fails_for_slightly_different_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();
        let wrong_msg = msg + Fr::ONE;

        let sig = sign(sk, msg);
        let valid = verify(&pk, wrong_msg, &sig);

        assert!(!valid, "Signature should not verify for msg + 1");
    }

    // ============================================================
    // VERIFICATION FAILURES - WRONG PUBLIC KEY
    // ============================================================

    #[test]
    fn test_verify_fails_for_wrong_public_key() {
        let sk = sample_secret_key();
        let wrong_pk = public_key_from_secret(another_secret_key());
        let msg = sample_message();

        let sig = sign(sk, msg);
        let valid = verify(&wrong_pk, msg, &sig);

        assert!(!valid, "Signature should not verify for wrong public key");
    }

    #[test]
    fn test_verify_fails_for_identity_public_key() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig = sign(sk, msg);
        let valid = verify(&Point::identity(), msg, &sig);

        assert!(
            !valid,
            "Signature should not verify for identity public key"
        );
    }

    #[test]
    fn test_verify_fails_for_generator_as_public_key() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig = sign(sk, msg);
        let valid = verify(&Point::generator(), msg, &sig);

        // This might pass if sk happens to be 1, but with our sample key it shouldn't
        assert!(
            !valid,
            "Signature should not verify for generator as public key"
        );
    }

    // ============================================================
    // VERIFICATION FAILURES - TAMPERED SIGNATURE
    // ============================================================

    #[test]
    fn test_verify_fails_for_tampered_r() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        // Tamper with R by using a different point
        let tampered_sig = Signature::new(Point::generator(), *sig.s());

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with tampered R");
    }

    #[test]
    fn test_verify_fails_for_negated_r() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        let tampered_sig = Signature::new(sig.r().negate(), *sig.s());

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with negated R");
    }

    #[test]
    fn test_verify_fails_for_identity_r() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        let tampered_sig = Signature::new(Point::identity(), *sig.s());

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with identity R");
    }

    #[test]
    fn test_verify_fails_for_tampered_s() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        // Flip a bit in s
        let mut tampered_s = *sig.s();
        if !tampered_s.is_empty() {
            tampered_s[0] = !tampered_s[0];
        }

        let tampered_sig = Signature::new(sig.r().clone(), tampered_s);

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with tampered s");
    }

    #[test]
    fn test_verify_fails_for_all_zero_s() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        let tampered_sig = Signature::new(sig.r().clone(), [false; 256]);

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with all-zero s");
    }

    #[test]
    fn test_verify_fails_for_all_one_s() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg = sample_message();

        let sig = sign(sk, msg);

        let tampered_sig = Signature::new(sig.r().clone(), [true; 256]);

        let valid = verify(&pk, msg, &tampered_sig);
        assert!(!valid, "Signature should not verify with all-one s");
    }

    // ============================================================
    // SIGNATURE VALIDITY
    // ============================================================

    #[test]
    fn test_signature_r_is_on_curve() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig = sign(sk, msg);

        assert!(sig.r().is_on_curve(), "Signature R should be on curve");
    }

    #[test]
    fn test_signature_r_is_not_identity() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig = sign(sk, msg);

        assert_ne!(
            *sig.r(),
            Point::identity(),
            "Signature R should not be identity"
        );
    }

    #[test]
    fn test_signature_s_is_not_empty() {
        let sk = sample_secret_key();
        let msg = sample_message();

        let sig = sign(sk, msg);

        assert!(!sig.s().is_empty(), "Signature s should not be empty");
    }

    // ============================================================
    // CROSS-KEY TESTS
    // ============================================================

    #[test]
    fn test_signature_not_valid_for_different_key_same_message() {
        let sk1 = sample_secret_key();
        let sk2 = another_secret_key();
        let pk2 = public_key_from_secret(sk2);
        let msg = sample_message();

        // Sign with sk1, verify with pk2
        let sig = sign(sk1, msg);
        let valid = verify(&pk2, msg, &sig);

        assert!(!valid, "Signature from sk1 should not verify with pk2");
    }

    #[test]
    fn test_cannot_use_signature_for_different_message() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);
        let msg1 = sample_message();
        let msg2 = another_message();

        // Sign msg1, try to use for msg2
        let sig = sign(sk, msg1);
        let valid = verify(&pk, msg2, &sig);

        assert!(!valid, "Signature for msg1 should not verify for msg2");
    }

    // ============================================================
    // MULTIPLE SIGNATURES
    // ============================================================

    #[test]
    fn test_multiple_signatures_all_verify() {
        let sk = sample_secret_key();
        let pk = public_key_from_secret(sk);

        for i in 0..10 {
            let msg = Fr::from(i as u64);
            let sig = sign(sk, msg);
            let valid = verify(&pk, msg, &sig);
            assert!(valid, "Signature {} should verify", i);
        }
    }

    #[test]
    fn test_multiple_keys_all_work() {
        for i in 1..10 {
            let sk = Fr::from(i as u64 * 1000);
            let pk = public_key_from_secret(sk);
            let msg = Fr::from(42u64);

            let sig = sign(sk, msg);
            let valid = verify(&pk, msg, &sig);
            assert!(valid, "Signature with key {} should verify", i);
        }
    }
}
