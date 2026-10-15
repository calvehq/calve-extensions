//! C/C++ (`org.calve.c-cpp`): the CIC module. Semantics live in
//! `calve-domain`; the ABI runtime in `cic-guest`.

use calve_domain::language;
use cic_guest::contract::wire::{CheckPlanIn, CheckPlanOut, DetectIn, DetectOut};
use cic_guest::{Domain, Fail};

#[derive(Default)]
struct CCpp;

impl Domain for CCpp {
    const METADATA: &'static str = include_str!("../../metadata.json");

    fn detect(&self, x: DetectIn) -> Result<DetectOut, Fail> {
        Ok(language::detect("c-cpp", &x))
    }
    fn check_plan(&self, x: CheckPlanIn) -> Result<CheckPlanOut, Fail> {
        Ok(language::check_plan("c-cpp", &x))
    }
}

cic_guest::export!(CCpp);
