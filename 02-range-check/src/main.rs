use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_std::test_rng;

const N_BITS: usize = 3;

struct RangeCheckCircuit<F: Field> {
    x: Option<F>,
}
impl<F: PrimeField> ConstraintSynthesizer<F> for RangeCheckCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;

        // Build weighted sum Σ b_i * 2^i
        let mut acc = LinearCombination::<F>::zero();

        let mut pow2 = F::one();
        let two = F::from(2u64);

        for i in 0..N_BITS {
            let b_var = cs.new_witness_variable(|| {
                let x = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                let bits = x.into_bigint().to_bits_le();
                let bit = bits[i] as u64;
                Ok(F::from(bit))
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
    let x = Fr::from(7);

    let mut rng = test_rng();

    let params = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        RangeCheckCircuit::<Fr> { x: None },
        &mut rng,
    )
    .unwrap();

    let pvk = prepare_verifying_key(&params.vk);

    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        RangeCheckCircuit::<Fr> { x: Some(x) },
        &params,
        &mut rng,
    )
    .unwrap();

    let valid = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &[]).unwrap();

    println!("proof is valid: {}", valid);
}
