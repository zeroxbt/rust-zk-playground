use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct AddOneCircuit<F: Field> {
    pub x: Option<F>, // private
    pub y: Option<F>, // public
}

impl<F: Field> ConstraintSynthesizer<F> for AddOneCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let one = F::one();
        let left: LinearCombination<F> = LinearCombination::from(x_var) + (one, Variable::One);
        let right: LinearCombination<F> = LinearCombination::from(Variable::One);
        let output: LinearCombination<F> = LinearCombination::from(y_var);

        cs.enforce_constraint(left, right, output)?;
        Ok(())
    }
}
