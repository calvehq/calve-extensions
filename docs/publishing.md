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

`~/calve-scripts/delegation.sh` (maintainer machine) publishes with these commands and checks
the result with the real calve client: install through the role, threshold met and not met,
a target outside the delegated paths, an id outside the prefix, publisher rotation (existing
client, new install, retired keys refused) and root/timestamp rotation (existing and fresh
clients).
