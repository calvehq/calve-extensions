//! Go (`org.calve.go`): the CIC module. Semantics live in
//! `calve-domain`; the ABI runtime in `cic-guest`.

use calve_domain::language;
use cic_guest::contract::wire::{CheckPlanIn, CheckPlanOut, DetectIn, DetectOut};
use cic_guest::{Domain, Fail};

#[derive(Default)]
struct Go;

impl Domain for Go {
    const METADATA: &'static str = include_str!("../../metadata.json");

    fn detect(&self, x: DetectIn) -> Result<DetectOut, Fail> {
        Ok(language::detect("go", &x))
    }
    fn check_plan(&self, x: CheckPlanIn) -> Result<CheckPlanOut, Fail> {
        Ok(language::check_plan("go", &x))
    }
}

cic_guest::export!(Go);
