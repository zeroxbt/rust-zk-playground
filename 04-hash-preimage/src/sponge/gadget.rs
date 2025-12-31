use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError, Variable};

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

    pub fn input_array<'a, const T: usize>(
        cs: &'a ConstraintSystemRef<Fr>,
        vals: &'a [Fr],
    ) -> Result<[State; T], SynthesisError> {
        let mut states = [State::zero(); T];
        for (state, &val) in states.iter_mut().zip(vals) {
            *state = Self::input(cs, val)?;
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

    pub fn one() -> Self {
        Self {
            val: Fr::ONE,
            var: Variable::One,
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
        let mut state: [State; WIDTH] = State::witness_array(cs, &[Fr::ZERO; WIDTH])?;

        // optional DST in capacity lane (lane 0 in your layout)
        if let Some(tag) = dst_capacity {
            state[0] = State::witness(cs, tag)?;
        }

        // absorb + permute per block
        for chunk in msg.chunks(RATE) {
            for (lane, x) in chunk.iter().enumerate() {
                let idx = 1 + lane;
                state[idx] = State::witness(cs, state[idx].val() + x.val())?;
            }

            self.perm.permute_in_place(cs, &mut state)?;
        }

        Ok(state[squeeze_lane])
    }
}
