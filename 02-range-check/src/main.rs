use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_std::test_rng;

struct RangePlusCircuit<F: PrimeField> {
    x: Option<F>, // private
    y: Option<F>, // public
    n_bits: usize,
    k: F,                       // constant
    bits_le: Option<Vec<bool>>, // private
}

impl<F: PrimeField> RangePlusCircuit<F> {
    fn for_setup(n_bits: usize, k: F) -> Self {
        Self {
            x: None,
            y: None,
            n_bits,
            k,
            bits_le: None,
        }
    }

    fn for_prove(x: F, y: F, bits_le: Vec<bool>, n_bits: usize, k: F) -> Self {
        Self {
            x: Some(x),
            y: Some(y),
            n_bits,
            k,
            bits_le: Some(bits_le),
        }
    }
}

// Prove I know a value x such that:
//   1) x + k = y
//   2) 0 <= x < 2^n_bits
impl<F: PrimeField> ConstraintSynthesizer<F> for RangePlusCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce: x + k = y  => (x + k) * 1 = y
        let left = LinearCombination::from(x_var) + (self.k, Variable::One);
        cs.enforce_constraint(
            left,
            LinearCombination::from(Variable::One),
            LinearCombination::from(y_var),
        )?;

        // Build weighted sum Σ b_i * 2^i
        let mut acc = LinearCombination::<F>::zero();

        let mut pow2 = F::one();
        let two = F::from(2u64);

        for i in 0..self.n_bits {
            let b_var = cs.new_witness_variable(|| {
                let bits_le = self
                    .bits_le
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let bit = *bits_le.get(i).ok_or(SynthesisError::AssignmentMissing)?;
                Ok(F::from(bit as u64))
            })?;

            // Enforce boolean: b * (b - 1) = 0
            cs.enforce_constraint(
                LinearCombination::from(b_var),
                LinearCombination::from(b_var) - (F::one(), Variable::One),
                LinearCombination::<F>::zero(),
            )?;

            // Add b_i * 2^i
            acc += (pow2, b_var);
            pow2 *= two;
        }

        // Enforce Σ b_i * 2^i = x  (i.e., (acc) * 1 = x)
        cs.enforce_constraint(
            acc,
            LinearCombination::from(Variable::One),
            LinearCombination::from(x_var),
        )?;

        Ok(())
    }
}

fn main() {
    let k = Fr::from(123u64);
    let n_bits = 16;

    let x = Fr::from(7u64);
    let y = x + k;

    let setup_circuit = RangePlusCircuit::<Fr>::for_setup(n_bits, k);
    let prove_circuit =
        RangePlusCircuit::<Fr>::for_prove(x, y, x.into_bigint().to_bits_le(), n_bits, k);

    let public_inputs = [y];

    let mut rng = test_rng();

    let params =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(setup_circuit, &mut rng)
            .unwrap();

    let pvk = prepare_verifying_key(&params.vk);

    let proof =
        Groth16::<Bls12_381>::create_random_proof_with_reduction(prove_circuit, &params, &mut rng)
            .unwrap();

    let valid = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

    println!("proof is valid: {}", valid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn create_circuits() -> (RangePlusCircuit<Fr>, RangePlusCircuit<Fr>) {
        let n_bits = 16;
        let k = Fr::from(123u64);
        let x = Fr::from(7u64);
        let y = x + k;
        let setup_circuit = RangePlusCircuit::for_setup(n_bits, k);
        let prove_circuit =
            RangePlusCircuit::for_prove(x, y, x.into_bigint().to_bits_le(), n_bits, k);

        (setup_circuit, prove_circuit)
    }

    fn prove(
        pk: ProvingKey<Bls12_381>,
        circuit: RangePlusCircuit<Fr>,
    ) -> ark_groth16::Proof<Bls12_381> {
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut test_rng())
            .unwrap()
    }

    fn setup(
        circuit: RangePlusCircuit<Fr>,
    ) -> (ProvingKey<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .unwrap();
        let vk = prepare_verifying_key(&pk.vk);

        (pk, vk)
    }

    #[test]
    fn range_plus_valid() {
        let (sc, pc) = create_circuits();
        let public_inputs = &[pc.y.unwrap()];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);
        assert!(Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap());
    }

    #[test]
    fn range_plus_wrong_public() {
        let (sc, pc) = create_circuits();
        let wrong_public_inputs = &[Fr::from(1)];
        let (pk, vk) = setup(sc);
        let proof = prove(pk, pc);
        assert!(!Groth16::<Bls12_381>::verify_proof(&vk, &proof, wrong_public_inputs).unwrap());
    }

    #[test]
    fn constraints_wrong_bits() {
        let n_bits = 16;
        let k = Fr::from(123u64);
        let x = Fr::from(7u64);
        let y = x + k;
        let circuit = RangePlusCircuit::for_prove(x, y, y.into_bigint().to_bits_le(), n_bits, k);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn proving_panics_for_out_of_range_bits() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let n_bits = 16;
        let k = Fr::from(123u64);

        // x is exactly 2^n_bits, so the low 16 bits are all zero.
        let x = Fr::from(1u64 << 16);
        let y = x + k;

        let setup_circuit = RangePlusCircuit::for_setup(n_bits, k);
        let params = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            setup_circuit,
            &mut test_rng(),
        )
        .unwrap();

        // Proof attempt with inconsistent bits (reconstructs to 0)
        let prove_circuit =
            RangePlusCircuit::for_prove(x, y, x.into_bigint().to_bits_le(), n_bits, k);
        let res = catch_unwind(AssertUnwindSafe(|| {
            Groth16::<Bls12_381>::create_random_proof_with_reduction(
                prove_circuit,
                &params,
                &mut test_rng(),
            )
            .unwrap();
        }));

        assert!(res.is_err(), "proving should panic for out-of-range x/bits");
    }
}
