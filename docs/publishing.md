# Publishing the first-party catalog

The first-party catalog is a TUF repository. Packages are signed by a delegated publisher role,
`calve`, never by the top-level `targets` role (calve-cli ADR 0021). Keys never live in a
repository: every `xtask` command that touches keys refuses a directory inside a git worktree.

## Keys

```
cargo xtask keygen --keys KEYS [--publisher-keys PUB] [--count 3] [--threshold 2]
```

- `KEYS/{root,targets,snapshot,timestamp}.key`: the top-level roles (one key each).
- `PUB/` (default `KEYS/calve`): the publisher's keys, plus `publisher.json` with the role name,
  its signature threshold and the id prefix it may publish (`org.calve.`). Keep `PUB` apart
  from `KEYS` (offline) if the two are held by different people.

## Publish

```
cargo xtask dist --out DIST [--target TRIPLE]
cargo xtask publish --keys KEYS --dist DIST --repo REPO [--publisher-keys PUB] [--resume]
```

- Top-level `targets` signs only `index.json`, `id-policy.json` (`{"roles":{"calve":["org.calve."]}}`)
  and the delegation: role `calve`, its keys and threshold, `terminating`, and paths
  `<id>/*`, `<id>/*/*`, `<id>/*/*/*` for exactly the published ids (TUF patterns never cross
  `/`).
- `calve.json` lists every package file and carries a signature from every active publisher
  key; publishing stops if there are fewer keys than the threshold.
- An id outside the publisher's prefix, or with characters other than `[a-z0-9.-]`, is refused.
- A published file is immutable: the same path with other bytes is refused.
- Calve records the delegated role as the package's publisher (`"publisher": "calve"`) and pins
  it for later installs.

## Hosting and refresh

The catalog is served by GitHub Pages from this repository's `gh-pages` branch, at
`https://calvehq.github.io/calve-extensions/` (a static TUF repository; `.nojekyll` keeps every
file served as is).

1. Run the `catalog-build` workflow (manual). It builds `dist` for every release target
   (`x86_64`/`aarch64` Linux, `aarch64`/`x86_64` macOS, `x86_64` Windows MSVC) and uploads one
   artifact per target. It uses no key.
2. On the publisher's machine, merge the artifacts into one `DIST` (the `x86_64-unknown-linux-gnu`
   build whole, plus `native/<target>/` from each other one), check out `gh-pages` into `REPO`,
   run `publish`, and push.

Metadata expires: `timestamp.json` after 7 days, `snapshot.json` after 30, `targets.json` and
`calve.json` after 90, `root.json` after 365. Expired metadata is refused by every client.

- **Snapshot and timestamp are online.** Their keys are the secrets `CATALOG_SNAPSHOT_KEY` and
  `CATALOG_TIMESTAMP_KEY` of the `catalog-online` environment (deployments from `master` only),
  and the `catalog-refresh` workflow re-signs both files on gh-pages every Monday and Thursday:

  ```
  cargo xtask refresh --keys DIR --repo REPO   # DIR holds only snapshot.key and timestamp.key
  ```

  `refresh` refuses keys that `root.json` does not name, and never touches targets, the
  publisher's role or root. It re-signs only the state those keys last signed: the current
  `timestamp.json` and `snapshot.json` must carry valid signatures by them, the timestamp must
  name exactly that snapshot, and the snapshot must name the current `targets.json` and
  `calve.json` versions. Residual risk: whoever can write `gh-pages` can swap in a complete
  older set of genuinely signed files; a refresh re-signs it with versions below what existing
  clients have seen, so they reject it as a rollback, but a new client could be served that
  older (still first-party-signed) package set. Limit who can push to `gh-pages`.
- **Targets, the publisher's role and root are offline.** Re-sign them before they expire by
  publishing again (an empty `--dist` directory re-signs everything): at least every 90 days for
  targets and `calve.json`, and every 365 days for root (a new root version).
- GitHub disables scheduled workflows in a public repository after 60 days without activity.
  Check that `catalog-refresh` is still enabled and green whenever you re-sign, and re-enable it
  if needed.

## Rotate keys

```
cargo xtask rotate --keys KEYS --role calve|root|targets|snapshot|timestamp [--publisher-keys PUB]
```

The old key(s) move to `retired/` and new ones are created; the next `publish` uses them.

- `calve`: all publisher keys are replaced; top-level `targets` signs the new delegation and
  the new keys sign `calve.json`. Metadata signed by the retired keys is no longer accepted.
- A top-level role: the next `publish` writes root version N+1 naming the new keys, signed by
  the new root key and by the key root N names for `root` (taken from `retired/`), so
  existing clients follow the rotation. Publishing refuses if that old root key is missing.

## Verification

Publishing has been checked against the real calve client: install through the role, threshold met and not met,
a target outside the delegated paths, an id outside the prefix, publisher rotation (existing
client, new install, retired keys refused) and root/timestamp rotation (existing and fresh
clients).
