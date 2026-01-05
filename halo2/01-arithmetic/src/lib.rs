use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Configuration: defines what columns and gates exist
#[derive(Debug, Clone)]
pub struct MulConfig {
    /// Advice column for first input
    a: Column<Advice>,
    /// Advice column for second input
    b: Column<Advice>,
    /// Advice column for output
    c: Column<Advice>,
    /// Selector that activates the multiplication gate
    s_mul: Selector,
}

/// Circuit: holds the witness values we want to prove
#[derive(Default, Clone)]
pub struct MulCircuit<F: Field> {
    pub a: Value<F>,
    pub b: Value<F>,
}

impl<F: Field> Circuit<F> for MulCircuit<F> {
    type Config = MulConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Step 1: Create the columns
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let s_mul = meta.selector();

        // Step 2: Define the custom gate
        meta.create_gate("mul", |meta| {
            // Query the cells at the current row
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let s = meta.query_selector(s_mul);

            // Return constraints: each must equal zero when satisfied
            // s * (a * b - c) = 0
            // When s=1: enforces a * b = c
            // When s=0: constraint is trivially 0
            vec![s * (a * b - c)]
        });
        MulConfig { a, b, c, s_mul }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "multiplication",
            |mut region| {
                // Enable the selector at row 0
                config.s_mul.enable(&mut region, 0)?;

                // Assign a at row 0, column a
                region.assign_advice(|| "a", config.a, 0, || self.a)?;

                // Assign b at row 0, column b
                region.assign_advice(|| "b", config.b, 0, || self.b)?;

                // Compute and assign c at row 0, column c
                let c_val = self.a.and_then(|a| self.b.map(|b| a * b));
                region.assign_advice(|| "c", config.c, 0, || c_val)?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    use super::*;

    #[test]
    fn test_mul_valid() {
        // Prove: 3 * 4 = 12
        let a = Fr::from(3);
        let b = Fr::from(4);

        let circuit = MulCircuit {
            a: Value::known(a),
            b: Value::known(b),
        };

        // k=4 means 2^4 = 16 rows available
        let prover = MockProver::run(4, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_mul_zero() {
        // Edge case: 0 * 5 = 0
        let circuit = MulCircuit {
            a: Value::known(Fr::from(0)),
            b: Value::known(Fr::from(5)),
        };

        let prover = MockProver::run(4, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
