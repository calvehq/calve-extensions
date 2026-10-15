//! General project (`org.calve.general`): the CIC module. Semantics live in
//! `calve-domain`; the ABI runtime in `cic-guest`.

use cic_guest::Domain;

#[derive(Default)]
struct General;

impl Domain for General {
    const METADATA: &'static str = include_str!("../../metadata.json");
}

cic_guest::export!(General);
