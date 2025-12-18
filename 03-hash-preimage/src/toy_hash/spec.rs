use ark_bls12_381::Fr;
use ark_ff::MontFp;

pub const WIDTH: usize = 2;
pub const ROUNDS: usize = 3;

pub const ROUND_CONSTANTS: [[Fr; 2]; ROUNDS] = [
    [MontFp!("2"), MontFp!("7")],
    [MontFp!("4"), MontFp!("18")],
    [MontFp!("5"), MontFp!("6")],
];
pub const MDS: [[Fr; 2]; 2] = [[MontFp!("3"), MontFp!("8")], [MontFp!("4"), MontFp!("5")]];
