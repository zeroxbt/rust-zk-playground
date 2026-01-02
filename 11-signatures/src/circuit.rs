use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::ConstraintSynthesizer;
use hash_preimage::sponge::gadget::State;

use crate::{
    curve::{gadget::PointVar, spec::Point},
    eddsa::gadget::verify,
};

pub struct EddsaVerificationCircuit {
    r: Option<Point>,
    s: Option<[Fr; 256]>,
    pk: Option<Point>,
    msg: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EddsaVerificationCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let r = PointVar::from_point_input(&cs, &self.r.unwrap_or(Point::identity()))?;
        let pk = PointVar::from_point_input(&cs, &self.pk.unwrap_or(Point::identity()))?;
        let msg = State::input(&cs, self.msg.unwrap_or_default())?;
        let s: [State; 256] = State::input_array(&cs, &self.s.unwrap_or([Fr::ZERO; 256]))?;

        verify(&cs, &pk, msg, &s, &r)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;

    use crate::{
        circuit::EddsaVerificationCircuit,
        curve::{native::scalar_mul, scalar::Scalar, spec::Point},
        eddsa::{native::sign, spec::Signature},
    };

    // -----------------------
    // Helpers
    // -----------------------

    fn bool_bits_to_fr_bits(bits: &[bool; 256]) -> [Fr; 256] {
        let mut out = [Fr::ZERO; 256];
        for (i, b) in bits.iter().enumerate() {
            out[i] = if *b { Fr::ONE } else { Fr::ZERO };
        }
        out
    }

    /// Public key derivation consistent with your native signing code:
    ///   sk = Scalar::from_fr_reduced(sk_fr)
    ///   pk = sk * G
    fn pk_from_sk_fr(sk_fr: Fr) -> Point {
        let g = Point::generator();
        let sk = Scalar::from_fr_reduced(sk_fr);
        scalar_mul(&sk.to_bits_be::<256>(), &g)
    }

    fn run_circuit(
        pk: Option<Point>,
        r: Option<Point>,
        s: Option<[Fr; 256]>,
        msg: Option<Fr>,
    ) -> (ConstraintSystemRef<Fr>, ark_relations::r1cs::Result<()>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = EddsaVerificationCircuit { r, s, pk, msg };
        let res = circuit.generate_constraints(cs.clone());
        (cs, res)
    }

    fn make_valid_instance(rng: &mut impl ark_std::rand::RngCore) -> (Point, Point, [Fr; 256], Fr) {
        let sk_fr = Fr::rand(rng);
        let msg = Fr::rand(rng);

        let sig: Signature = sign(sk_fr, msg);
        let pk = pk_from_sk_fr(sk_fr);

        let r = sig.r;
        let s_fr_bits = bool_bits_to_fr_bits(&sig.s);

        (pk, r, s_fr_bits, msg)
    }

    // -----------------------
    // Positive test
    // -----------------------

    #[test]
    fn eddsa_verification_circuit_accepts_valid_signature() {
        let mut rng = test_rng();
        let (pk, r, s, msg) = make_valid_instance(&mut rng);

        let (cs, res) = run_circuit(Some(pk), Some(r), Some(s), Some(msg));
        res.unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "constraints not satisfied for a valid signature"
        );
    }

    // -----------------------
    // Negative tests (tampering)
    // -----------------------

    #[test]
    fn eddsa_verification_circuit_rejects_wrong_message() {
        let mut rng = test_rng();
        let (pk, r, s, msg) = make_valid_instance(&mut rng);

        let msg2 = msg + Fr::ONE;

        let (cs, res) = run_circuit(Some(pk), Some(r), Some(s), Some(msg2));
        res.unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit unexpectedly satisfied for wrong message"
        );
    }

    #[test]
    fn eddsa_verification_circuit_rejects_wrong_public_key() {
        let mut rng = test_rng();
        let (_, r, s, msg) = make_valid_instance(&mut rng);

        let sk2 = Fr::rand(&mut rng);
        let pk2 = pk_from_sk_fr(sk2);

        // Extremely low probability pk2 == pk; ignore as negligible.
        let (cs, res) = run_circuit(Some(pk2), Some(r), Some(s), Some(msg));
        res.unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit unexpectedly satisfied for wrong public key"
        );
    }

    #[test]
    fn eddsa_verification_circuit_rejects_wrong_r_point() {
        let mut rng = test_rng();
        let (pk, _, s, msg) = make_valid_instance(&mut rng);

        // Use an unrelated R' = k*G for random k
        let k2 = Scalar::from_fr_reduced(Fr::rand(&mut rng));
        let r2 = scalar_mul(&k2.to_bits_be::<256>(), &Point::generator());

        let (cs, res) = run_circuit(Some(pk), Some(r2), Some(s), Some(msg));
        res.unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit unexpectedly satisfied for wrong R"
        );
    }

    #[test]
    fn eddsa_verification_circuit_rejects_wrong_s_bits() {
        let mut rng = test_rng();
        let (pk, r, mut s, msg) = make_valid_instance(&mut rng);

        // Flip one bit, keep it boolean
        s[0] = if s[0] == Fr::ONE { Fr::ZERO } else { Fr::ONE };

        let (cs, res) = run_circuit(Some(pk), Some(r), Some(s), Some(msg));
        res.unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit unexpectedly satisfied for wrong s"
        );
    }

    // -----------------------
    // Public input shape sanity check
    // -----------------------

    #[test]
    fn eddsa_verification_circuit_public_inputs_count() {
        let mut rng = test_rng();
        let (pk, r, s, msg) = make_valid_instance(&mut rng);

        let (cs, res) = run_circuit(Some(pk), Some(r), Some(s), Some(msg));
        res.unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Inputs allocated by the circuit:
        // - r.x, r.y  => 2
        // - pk.x, pk.y => 2
        // - msg => 1
        // - s[256] => 256
        // Total = 261 public inputs, plus the implicit "1" instance variable.
        assert_eq!(
            cs.num_instance_variables(),
            1 + 261,
            "unexpected number of instance variables"
        );
    }
}
