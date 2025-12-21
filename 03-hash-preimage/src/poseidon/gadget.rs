use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

use crate::{
    poseidon::{
        native::PoseidonPermutation,
        spec::{PoseidonSpec, WIDTH},
    },
    sponge::gadget::{PermutationGadget, State},
};

impl PermutationGadget<3> for PoseidonPermutation<'_> {
    fn permute_in_place(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        state: &mut [State; 3],
    ) -> Result<(), SynthesisError> {
        assert!(self.spec.full_rounds.is_multiple_of(2));
        assert_eq!(
            self.spec.ark.len(),
            self.spec.full_rounds + self.spec.partial_rounds
        );

        let (first_full, rest) = self.spec.ark.split_at(self.spec.full_rounds / 2);
        let (partial, last_full) = rest.split_at(self.spec.partial_rounds);

        for rc in first_full {
            apply_ark(cs, rc, state)?;
            apply_s_box_17(self.spec, cs, state, true)?;
            apply_mds(self.spec, cs, state)?;
        }
        for rc in partial {
            apply_ark(cs, rc, state)?;
            apply_s_box_17(self.spec, cs, state, false)?;
            apply_mds(self.spec, cs, state)?;
        }
        for rc in last_full {
            apply_ark(cs, rc, state)?;
            apply_s_box_17(self.spec, cs, state, true)?;
            apply_mds(self.spec, cs, state)?;
        }

        Ok(())
    }
}

fn apply_ark(
    cs: &ConstraintSystemRef<Fr>,
    rc: &[Fr; WIDTH],
    state: &mut [State; WIDTH],
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

fn apply_s_box_17(
    spec: &PoseidonSpec,
    cs: &ConstraintSystemRef<Fr>,
    state: &mut [State; WIDTH],
    is_full_round: bool,
) -> Result<(), SynthesisError> {
    // TODO: generalize s_box to any alpha
    assert!(spec.alpha == 17, "This gadget only supports alpha=17");
    if is_full_round {
        for state_elem in state {
            apply_s_box_17_inner(cs, state_elem)?;
        }
    } else {
        apply_s_box_17_inner(cs, &mut state[0])?;
    }

    Ok(())
}

fn apply_s_box_17_inner(cs: &ConstraintSystemRef<Fr>, s: &mut State) -> Result<(), SynthesisError> {
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
    let s0_8 = State::witness(cs, s0_4.val() * s0_4.val())?;
    cs.enforce_constraint(
        LinearCombination::from(s0_4.var()),
        LinearCombination::from(s0_4.var()),
        LinearCombination::from(s0_8.var()),
    )?;
    let s0_16 = State::witness(cs, s0_8.val() * s0_8.val())?;
    cs.enforce_constraint(
        LinearCombination::from(s0_8.var()),
        LinearCombination::from(s0_8.var()),
        LinearCombination::from(s0_16.var()),
    )?;
    let s0_17 = State::witness(cs, s0_16.val() * s.val())?;
    cs.enforce_constraint(
        LinearCombination::from(s0_16.var()),
        LinearCombination::from(s.var()),
        LinearCombination::from(s0_17.var()),
    )?;
    *s = s0_17;

    Ok(())
}

fn apply_mds(
    spec: &PoseidonSpec,
    cs: &ConstraintSystemRef<Fr>,
    state: &mut [State; WIDTH],
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
