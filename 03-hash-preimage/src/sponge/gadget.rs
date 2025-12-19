use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

#[derive(Clone, Copy, Debug)]
pub struct State {
    pub val: Fr,
    pub var: Variable,
}

pub struct SpongeGadget<P, const WIDTH: usize, const RATE: usize>
where
    P: PermutationGadget<WIDTH>,
{
    pub perm: P,
}
pub trait PermutationGadget<const T: usize> {
    fn permute_in_place(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        state: &mut [State; T],
    ) -> Result<(), SynthesisError>;
}

impl<P, const WIDTH: usize, const RATE: usize> SpongeGadget<P, WIDTH, RATE>
where
    P: PermutationGadget<WIDTH>,
{
    pub fn hash(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        msg: &[Fr],
        dst_capacity: Option<Fr>,
        squeeze_lane: usize,
    ) -> Result<State, SynthesisError> {
        // init zeros
        let mut state: [State; WIDTH] = std::array::from_fn(|_| State {
            val: Fr::ZERO,
            var: Variable::Zero,
        });

        for s in &mut state {
            s.var = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
            cs.enforce_constraint(
                LinearCombination::from(s.var),
                LinearCombination::from(Variable::One),
                LinearCombination::zero(),
            )?;
        }

        // optional DST in capacity lane (lane 0 in your layout)
        if let Some(tag) = dst_capacity {
            state[0].val = tag;
            state[0].var = cs.new_witness_variable(|| Ok(tag))?;
            cs.enforce_constraint(
                LinearCombination::from(state[0].var),
                LinearCombination::from(Variable::One),
                LinearCombination::from((tag, Variable::One)),
            )?;
        }

        // absorb + permute per block
        for chunk in msg.chunks(RATE) {
            for (lane, val) in chunk.iter().enumerate() {
                let idx = 1 + lane;
                let old_var = state[idx].var;
                state[idx].val += *val;
                let x_var = cs.new_witness_variable(|| Ok(*val))?;
                state[idx].var = cs.new_witness_variable(|| Ok(state[idx].val))?;
                cs.enforce_constraint(
                    LinearCombination::from(old_var) + (Fr::ONE, x_var),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(state[idx].var),
                )?;
            }

            self.perm.permute_in_place(cs, &mut state)?;
        }

        Ok(state[squeeze_lane])
    }
}
