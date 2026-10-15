//! Rust (`org.calve.rust`): the CIC module. Semantics live in
//! `calve-domain`; the ABI runtime in `cic-guest`.

use calve_domain::language;
use cic_guest::contract::wire::{CheckPlanIn, CheckPlanOut, DetectIn, DetectOut};
use cic_guest::{Domain, Fail};

#[derive(Default)]
struct Rust;

impl Domain for Rust {
    const METADATA: &'static str = include_str!("../../metadata.json");

    fn detect(&self, x: DetectIn) -> Result<DetectOut, Fail> {
        Ok(language::detect("rust", &x))
    }
    fn check_plan(&self, x: CheckPlanIn) -> Result<CheckPlanOut, Fail> {
        Ok(language::check_plan("rust", &x))
    }
}

cic_guest::export!(Rust);
