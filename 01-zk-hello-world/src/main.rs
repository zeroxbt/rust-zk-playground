use ark_bls12_381::Bls12_381;
use ark_ff::Field;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use rand::thread_rng;

// Our circuit: prove we know x such that x + 1 = y (public)
struct HelloCircuit<F: Field> {
    // Private witness
    pub x: Option<F>,
    // Public input
    pub y: Option<F>,
}

// Implement the circuit constraints
impl<F: Field> ConstraintSynthesizer<F> for HelloCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate x as a private witness variable
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate y as a public input variable
        let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        // We want to enforce: x + 1 = y
        //
        // In R1CS form, that's:
        // (x + 1) * 1 = y
        //
        // So we build three linear combinations: (x + 1), (1), and (y).

        let one = F::one();

        let left: LinearCombination<F> = LinearCombination::from(x_var) + (one, Variable::One);
        let right: LinearCombination<F> = LinearCombination::from(Variable::One);
        let output: LinearCombination<F> = LinearCombination::from(y_var);

        cs.enforce_constraint(left, right, output)?;

        Ok(())
    }
}

fn main() {
    // We'll prove knowledge of x such that x + 1 = y.
    // Choose x = 6, so y = 7.
    use ark_bls12_381::Fr;

    let x_val = Fr::from(6u64);
    let y_val = Fr::from(7u64);

    // 1) Setup phase: generate proving and verifying keys for this circuit structure
    let mut rng = thread_rng();
    let circuit_for_setup = HelloCircuit {
        x: None, // During setup, we don't fix the witness values
        y: None,
    };

    let params = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit_for_setup,
        &mut rng,
    )
    .expect("parameter generation should not fail");

    let pvk = prepare_verifying_key(&params.vk);

    // 2) Prover phase: create a proof for a specific x and y
    let circuit_for_proof = HelloCircuit {
        x: Some(x_val),
        y: Some(y_val),
    };

    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit_for_proof,
        &params,
        &mut rng,
    )
    .expect("proof generation should not fail");

    // 3) Verifier phase: verify the proof using only the public input y
    let public_inputs = [y_val];

    let is_valid = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &public_inputs)
        .expect("verification should not fail");

    println!("Is the proof valid? {}", is_valid);
}
