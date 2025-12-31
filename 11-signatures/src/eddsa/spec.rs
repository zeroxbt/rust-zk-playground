use crate::curve::spec::Point;

pub struct Signature {
    pub r: Point,
    pub s: Vec<bool>,
}
