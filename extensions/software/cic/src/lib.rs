//! Software project (`org.calve.software`): the CIC module. Semantics live in
//! `calve-domain`; the ABI runtime in `cic-guest`.

use calve_domain::software;
use cic_guest::contract::session::{Group, Relation};
use cic_guest::contract::wire::{CaptureOp, ClassifyIn, ClassifyOut, DiffIn, DiffOut, Tuple};
use cic_guest::{Domain, Fail};

#[derive(Default)]
struct Software;

impl Domain for Software {
    const METADATA: &'static str = include_str!("../../metadata.json");

    fn classify(&self, x: ClassifyIn) -> Result<ClassifyOut, Fail> {
        software::classify(x)
    }
    fn capture_op(&self, t: &Tuple) -> Result<CaptureOp, Fail> {
        software::capture_op(t)
    }
    fn relate_group(&self, g: &Group) -> Vec<Relation> {
        software::relate_group(g)
    }
    fn diff(&self, x: DiffIn) -> Result<DiffOut, Fail> {
        software::diff(x)
    }
}

cic_guest::export!(Software);
