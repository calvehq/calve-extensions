//! First-party domain semantics for calve-extensions. Pure modules (`ignore`, `language`,
//! `software`) compile to wasm32 for the CIC modules; the OpenAEVC extension servers are behind
//! the `native` feature. Nothing here depends on Calve internals — only the Calve Integration
//! Contract and OpenAEVC's protocol crates.

#[cfg(feature = "native")]
pub mod general;
pub mod ignore;
pub mod language;
pub mod software;
