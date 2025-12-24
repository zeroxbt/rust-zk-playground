use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

#[derive(Clone, Copy, Debug)]
pub struct State {
    val: Fr,
    var: Variable,
}

impl State {
    pub fn witness(cs: &ConstraintSystemRef<Fr>, val: Fr) -> Result<Self, SynthesisError> {
        Ok(Self {
            val,
            var: cs.new_witness_variable(|| Ok(val))?,
        })
    }

    pub fn witness_array<'a, const T: usize>(
        cs: &'a ConstraintSystemRef<Fr>,
        vals: &'a [Fr],
    ) -> Result<[State; T], SynthesisError> {
        let mut states = [State::zero(); T];
        for (state, &val) in states.iter_mut().zip(vals) {
            *state = Self::witness(cs, val)?;
        }

        Ok(states)
    }

    pub fn input(cs: &ConstraintSystemRef<Fr>, val: Fr) -> Result<Self, SynthesisError> {
        Ok(Self {
            val,
            var: cs.new_input_variable(|| Ok(val))?,
        })
    }

    pub fn zero() -> Self {
        Self {
            val: Fr::ZERO,
            var: Variable::Zero,
        }
    }

    pub fn val(&self) -> Fr {
        self.val
    }

    pub fn var(&self) -> Variable {
        self.var
    }
}

pub struct SpongeGadget<P, const WIDTH: usize, const RATE: usize>
where
    P: PermutationGadget<WIDTH>,
{
    perm: P,
}

impl<P, const WIDTH: usize, const RATE: usize> Default for SpongeGadget<P, WIDTH, RATE>
where
    P: PermutationGadget<WIDTH> + Default,
{
    fn default() -> Self {
        Self { perm: P::default() }
    }
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
        msg: &[State],
        squeeze_lane: usize,
    ) -> Result<State, SynthesisError> {
        self.hash_with_dst(cs, msg, None, squeeze_lane)
    }

    pub fn hash_with_dst(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        msg: &[State],
        dst_capacity: Option<Fr>,
        squeeze_lane: usize,
    ) -> Result<State, SynthesisError> {
        // init zeros
        let mut state: [State; WIDTH] = std::array::from_fn(|_| State {
            val: Fr::ZERO,
            var: Variable::Zero,
        });

        for s in &mut state {
            *s = State::witness(cs, Fr::ZERO)?;
            cs.enforce_constraint(
                LinearCombination::from(s.var()),
                LinearCombination::from(Variable::One),
                LinearCombination::zero(),
            )?;
        }

        // optional DST in capacity lane (lane 0 in your layout)
        if let Some(tag) = dst_capacity {
            state[0] = State::witness(cs, tag)?;
            cs.enforce_constraint(
                LinearCombination::from(state[0].var()),
                LinearCombination::from(Variable::One),
                LinearCombination::from((tag, Variable::One)),
            )?;
        }

        // absorb + permute per block
        for chunk in msg.chunks(RATE) {
            for (lane, x) in chunk.iter().enumerate() {
                let idx = 1 + lane;
                let old_var = state[idx].var();
                state[idx] = State::witness(cs, state[idx].val() + x.val())?;
                cs.enforce_constraint(
                    LinearCombination::from(old_var) + (Fr::ONE, x.var()),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(state[idx].var()),
                )?;
            }

            self.perm.permute_in_place(cs, &mut state)?;
        }

        Ok(state[squeeze_lane])
    }
}
