use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};

#[derive(Clone, Debug)]
pub struct MulCircuit<F: Field> {
    pub a: Option<F>, // private
    pub b: Option<F>, // private
    pub c: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

        let left: LinearCombination<F> = LinearCombination::from(a_var);
        let right: LinearCombination<F> = LinearCombination::from(b_var);
        let output: LinearCombination<F> = LinearCombination::from(c_var);

        cs.enforce_constraint(left, right, output)?;
        Ok(())
    }
}
