use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct ChainedCircuit<F: Field> {
    pub a: Option<F>, // private
    pub b: Option<F>, // private
    pub c: Option<F>, // private
    pub d: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for ChainedCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_witness_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        let d_var = cs.new_input_variable(|| self.d.ok_or(SynthesisError::AssignmentMissing))?;

        // temp = a * b
        let tmp_var = cs.new_witness_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // Enforce: a * b = tmp
        cs.enforce_constraint(
            LinearCombination::from(a_var),
            LinearCombination::from(b_var),
            LinearCombination::from(tmp_var),
        )?;

        // Enforce: tmp + c = d  => (tmp + c) * 1 = d
        let left: LinearCombination<F> =
            LinearCombination::from(tmp_var) + LinearCombination::from(c_var);
        let right: LinearCombination<F> = LinearCombination::from(Variable::One);
        let output: LinearCombination<F> = LinearCombination::from(d_var);

        cs.enforce_constraint(left, right, output)?;
        Ok(())
    }
}
