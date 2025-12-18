use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

use crate::toy_hash::spec::{MDS, ROUND_CONSTANTS};

pub fn permute_gadget(
    cs: &ConstraintSystemRef<Fr>,
    s0_var: Variable,
    s1_var: Variable,
    s0: Fr,
    s1: Fr,
) -> Result<(Variable, Variable, Fr, Fr), SynthesisError> {
    let mut s0 = s0;
    let mut s1 = s1;
    let mut s0_var = s0_var;
    let mut s1_var = s1_var;
    for round_constants in ROUND_CONSTANTS {
        let c0 = round_constants[0];
        let c1 = round_constants[1];
        let u0 = s0 + c0;
        let u1 = s1 + c1;

        // add round constants
        let u0_var = cs.new_witness_variable(|| Ok(u0))?;
        let u1_var = cs.new_witness_variable(|| Ok(u1))?;
        cs.enforce_constraint(
            LinearCombination::from(s0_var) + (c0, Variable::One),
            LinearCombination::from(Variable::One),
            LinearCombination::from(u0_var),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(s1_var) + (c1, Variable::One),
            LinearCombination::from(Variable::One),
            LinearCombination::from(u1_var),
        )?;

        // s-box u^5 (mirrors circuit)
        let u0_2 = u0 * u0;
        let u0_2_var = cs.new_witness_variable(|| Ok(u0_2))?;
        cs.enforce_constraint(
            LinearCombination::from(u0_var),
            LinearCombination::from(u0_var),
            LinearCombination::from(u0_2_var),
        )?;
        let u0_4 = u0_2 * u0_2;
        let u0_4_var = cs.new_witness_variable(|| Ok(u0_4))?;
        cs.enforce_constraint(
            LinearCombination::from(u0_2_var),
            LinearCombination::from(u0_2_var),
            LinearCombination::from(u0_4_var),
        )?;
        let v0 = u0_4 * u0;
        let v0_var = cs.new_witness_variable(|| Ok(v0))?;
        cs.enforce_constraint(
            LinearCombination::from(u0_4_var),
            LinearCombination::from(u0_var),
            LinearCombination::from(v0_var),
        )?;

        let u1_2 = u1 * u1;
        let u1_2_var = cs.new_witness_variable(|| Ok(u1_2))?;
        cs.enforce_constraint(
            LinearCombination::from(u1_var),
            LinearCombination::from(u1_var),
            LinearCombination::from(u1_2_var),
        )?;
        let u1_4 = u1_2 * u1_2;
        let u1_4_var = cs.new_witness_variable(|| Ok(u1_4))?;
        cs.enforce_constraint(
            LinearCombination::from(u1_2_var),
            LinearCombination::from(u1_2_var),
            LinearCombination::from(u1_4_var),
        )?;
        let v1 = u1_4 * u1;
        let v1_var = cs.new_witness_variable(|| Ok(v1))?;
        cs.enforce_constraint(
            LinearCombination::from(u1_4_var),
            LinearCombination::from(u1_var),
            LinearCombination::from(v1_var),
        )?;

        // linear mixing
        s0 = MDS[0][0] * v0 + MDS[0][1] * v1;
        s1 = MDS[1][0] * v0 + MDS[1][1] * v1;

        s0_var = cs.new_witness_variable(|| Ok(s0))?;
        s1_var = cs.new_witness_variable(|| Ok(s1))?;
        cs.enforce_constraint(
            LinearCombination::from((MDS[0][0], v0_var)) + (MDS[0][1], v1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(s0_var),
        )?;
        cs.enforce_constraint(
            LinearCombination::from((MDS[1][0], v0_var)) + (MDS[1][1], v1_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(s1_var),
        )?;
    }

    Ok((s0_var, s1_var, s0, s1))
}
