# Authoring an extension

A Calve extension package has three parts, published together as one version in a signed TUF
catalog (`<id>/<version>/…`, listed in `<id>/package.json`).

## 1. `metadata.json` → `calve-integration.json`

The declarations Calve reads, signed with the package. Calve knows nothing about a domain
beyond them (schema `calve.integration/1`):

- `extension_id`, `version`, `display_name`, `abi`, `cic` (supported CIC ranges), `schema`;
- `capabilities.required` / `optional` and `ops`: the CIC operations the module implements
  (`describe`, `detect`, `check_plan`, `classify`, `capture`, `relate`, `diff`);
- `files` (a file domain): the resource kind, the `put`/`delete` effect kinds, kinds still
  valid only in recorded `history`, the write action, verifier, evaluator and `ignore_files`;
- `resources`: non-file kinds edited with `calve resource set <short>:<name>=JSON`;
- `checks`: the verifier that judges Calve's check evidence (requires `detect` and
  `check_plan`);
- `relations`: derived relation kinds and their payload schemas (closed objects of strings,
  integers and booleans), with `optional_relations` deciding whether a failed `relate` drops
  them or fails the capture.

Every kind must start with the extension id. `cargo xtask check-architecture` validates each
file with the contract's own rules.

## 2. The CIC module (`cic/`)

A `cdylib` built for `wasm32-unknown-unknown`. Implement `cic_guest::Domain` and call
`cic_guest::export!(YourType)` once:

```rust
#[derive(Default)]
struct Toy;

impl cic_guest::Domain for Toy {
    const METADATA: &'static str = include_str!("../../metadata.json");
    // override the ops you declared: classify, capture_op, relate_group, diff, detect, check_plan
}

cic_guest::export!(Toy);
```

The runtime handles `hello/0`, request sequencing and the streaming capture/relate protocols;
your code sees one tuple, one group or one request at a time. Rules Calve's host enforces:

- exactly one decision per `classify` entry and one op per capture tuple, in order;
- relations only between members of one delivered group, of declared kinds, with valid
  payloads;
- deterministic results: no clocks, randomness, environment, files, network or threads (the
  module has no imports; `check-architecture` refuses code that names them);
- bounded work: Calve meters fuel and memory and kills a module that exceeds them.

Put the semantics in a pure library (here `calve-domain`) so they are unit-tested natively,
and add the module to `crates/conformance` so it runs on Calve's production host and an
independent host with byte-identical transcripts.

## 3. The native extension (`native/`)

An OpenAEVC extension (`openaevc::extension::server`) that validates and applies the effects
OpenAEVC records and implements the declared verifiers and evaluators. It runs as a normal
process with the user's permissions, so installing or enabling it requires
`--acknowledge-native`. Name the binary as its manifest `entrypoint.command`.

## Publishing

`cargo xtask dist --out dist` assembles the packages for the current platform;
`cargo xtask publish --keys <dir> --dist dist --repo <catalog>` signs a new catalog version.
Users add the catalog with the printed root digest and install by id.
