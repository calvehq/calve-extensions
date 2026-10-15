# calve-extensions

First-party extensions for [Calve](https://github.com/calvehq/calve-cli), distributed through a
signed TUF catalog. Calve itself ships no domain semantics: everything it knows about files,
languages and project resources comes from the packages enabled in a Project.

| Extension | Id | What it provides |
|---|---|---|
| `software` | `org.calve.software` | Project files as exact snapshots: ignore rules (`.calveignore` plus software and language defaults), capture, rename detection, line diffs, snapshot verifier, change-size evaluator |
| `general` | `org.calve.general` | Notes, checklists, records and artifact references (`calve resource set note:plan=…`) |
| `rust`, `go`, `python`, `javascript-typescript`, `java`, `c-cpp`, `shell`, `hcl` | `org.calve.<lang>` | Language detection, check plans and the verifier that judges check evidence |

Each package has three parts (see [docs/authoring.md](docs/authoring.md)):

- `metadata.json` — the signed `calve-integration.json` declaring the extension's kinds;
- `cic/` — a wasm module implementing the Calve Integration Contract, run by Calve in a
  supervised sandbox;
- `native/` — an OpenAEVC extension that validates and applies effects and judges candidates.
  It runs with the user's permissions; Calve requires `--acknowledge-native` to install or
  enable it.

## Using the extensions

```sh
calve extension catalog add calve <catalog URL> --root 1.root.json --root-digest <sha256>
calve extension install org.calve.software --acknowledge-native
calve extension enable org.calve.software --acknowledge-native
```

## Development

The Calve Integration Contract comes from a sibling `../calve-cli` checkout at the commit pinned
in [`CONTRACT_PIN`](CONTRACT_PIN) ([docs/contract-pins.md](docs/contract-pins.md)).

```sh
scripts/dev-env.sh              # checks the toolchain and the contract pin
cargo test --workspace          # unit tests
cargo conformance               # every CIC module on Calve's host and an independent host
cargo xtask check-architecture  # unsafe, dependency, ambient-I/O and module-export rules
cargo xtask dist --out dist     # packages for this platform
```

Publishing (maintainers): `cargo xtask keygen --keys <dir outside any repository>` once, then
`cargo xtask publish --keys <dir> --dist dist --repo <catalog dir>`; an interrupted publish
finishes with `--resume`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
