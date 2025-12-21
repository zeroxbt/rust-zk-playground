use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

use crate::{
    sponge::gadget::{PermutationGadget, State},
    toy_hash::{native::ToyHashPermutation, spec::ToyHashSpec},
};

impl PermutationGadget<2> for ToyHashPermutation<'_> {
    fn permute_in_place(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        state: &mut [State; 2],
    ) -> Result<(), SynthesisError> {
        for rc in &self.spec().ark {
            apply_ark(cs, rc, state)?;
            apply_s_box_5(self.spec(), cs, state)?;
            apply_mds(self.spec(), cs, state)?;
        }

        Ok(())
    }
}

fn apply_ark(
    cs: &ConstraintSystemRef<Fr>,
    rc: &[Fr; 2],
    state: &mut [State; 2],
) -> Result<(), SynthesisError> {
    for (i, s) in state.iter_mut().enumerate() {
        let old_s_var = s.var();
        let c = rc[i];
        *s = State::witness(cs, s.val() + c)?;
        cs.enforce_constraint(
            LinearCombination::from(old_s_var) + (c, Variable::One),
            LinearCombination::from(Variable::One),
            LinearCombination::from(s.var()),
        )?;
    }

    Ok(())
}

fn apply_s_box_5(
    spec: &ToyHashSpec,
    cs: &ConstraintSystemRef<Fr>,
    state: &mut [State; 2],
) -> Result<(), SynthesisError> {
    // TODO: generalize s_box to any alpha
    assert!(spec.alpha == 5, "This gadget only supports alpha=5");
    for s in state {
        let s0_2 = State::witness(cs, s.val() * s.val())?;
        cs.enforce_constraint(
            LinearCombination::from(s.var()),
            LinearCombination::from(s.var()),
            LinearCombination::from(s0_2.var()),
        )?;
        let s0_4 = State::witness(cs, s0_2.val() * s0_2.val())?;
        cs.enforce_constraint(
            LinearCombination::from(s0_2.var()),
            LinearCombination::from(s0_2.var()),
            LinearCombination::from(s0_4.var()),
        )?;
        let s0_5 = State::witness(cs, s0_4.val() * s.val())?;
        cs.enforce_constraint(
            LinearCombination::from(s0_4.var()),
            LinearCombination::from(s.var()),
            LinearCombination::from(s0_5.var()),
        )?;
        *s = s0_5;
    }

    Ok(())
}

fn apply_mds(
    spec: &ToyHashSpec,
    cs: &ConstraintSystemRef<Fr>,
    state: &mut [State; 2],
) -> Result<(), SynthesisError> {
    let state_snapshot = *state;

    for (i, s) in state.iter_mut().enumerate() {
        let mut val_acc = Fr::ZERO;
        let mut lc_acc = LinearCombination::zero();
        for (j, state_snapshot_elem) in state_snapshot.iter().enumerate() {
            val_acc += spec.mds[i][j] * state_snapshot_elem.val();
            lc_acc += (spec.mds[i][j], state_snapshot_elem.var());
        }
        *s = State::witness(cs, val_acc)?;
        cs.enforce_constraint(
            lc_acc,
            LinearCombination::from(Variable::One),
            LinearCombination::from(s.var()),
        )?;
    }

    Ok(())
}
