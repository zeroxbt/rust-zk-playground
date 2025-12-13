use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_std::test_rng;
use zk_hello_world::circuits::mul::MulCircuit;

pub mod circuits;

pub type Curve = Bls12_381;
pub type Fr = <Curve as Pairing>::ScalarField;

fn prove_and_verify<C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone>(
    circuit: C,
    public_inputs: &[Fr],
) -> bool {
    let mut rng = test_rng();

    let params =
        Groth16::<Curve>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .expect("parameter generation should not fail");
    let pvk = prepare_verifying_key(&params.vk);

    let proof = Groth16::<Curve>::create_random_proof_with_reduction(circuit, &params, &mut rng)
        .expect("proof generation should not fail");

    Groth16::<Curve>::verify_proof(&pvk, &proof, public_inputs)
        .expect("verification should not fail")
}

fn main() {
    let a = Fr::from(3u64);
    let b = Fr::from(4u64);
    let c = a * b;

    let circuit = MulCircuit {
        a: Some(a),
        b: Some(b),
        c: Some(c),
    };
    let is_valid = prove_and_verify(circuit, &[c]);

    println!("Curve: Bls12_381, circuit: Mul, valid: {}", is_valid);
}
