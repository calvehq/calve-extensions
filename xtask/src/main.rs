//! Maintenance tasks for calve-extensions (`cargo xtask <command>`):
//!
//! - `check-architecture`: unsafe only in `cic-guest`; dependency allowlists; no ambient I/O in
//!   CIC code; metadata/package consistency; every built module exports exactly the ABI 1
//!   functions and memory, imports nothing and has no start function.
//! - `check-contract`: one calve-cli rev everywhere, equal to the newest docs/contract-pins.md row
//!   and to what Cargo.lock resolved (ADR 0019).
//! - `keygen --keys DIR`: new ed25519 role keys, refused inside any git worktree.
//! - `dist --out DIR`: release packages for this host's platform, with `SHA256SUMS`.
//! - `sbom OUT`: CycloneDX SBOM of every locked dependency.
//! - `publish --keys DIR --dist DIR --repo DIR [--resume]`: a new TUF repository version.
//!   Everything is staged first and committed file by file, `timestamp.json` last, so a crash
//!   never exposes a partial version; `--resume` finishes an interrupted commit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use calve_integration_contract::jcs;
use calve_integration_contract::metadata::Metadata;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage: cargo xtask <check-architecture | check-contract | keygen --keys DIR | dist --out DIR | sbom OUT | publish --keys DIR --dist DIR --repo DIR [--resume]>";
const ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];
const ABI_EXPORTS: [&str; 6] = [
    "memory",
    "cic_abi_version",
    "cic_alloc",
    "cic_call",
    "cic_free",
    "cic_init",
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| -> Option<PathBuf> {
        let i = args.iter().position(|a| a == name)?;
        args.get(i + 1).map(PathBuf::from)
    };
    let result = match args.first().map(String::as_str) {
        Some("check-architecture") => check_architecture(),
        Some("check-contract") => check_contract(),
        Some("keygen") => flag("--keys")
            .ok_or_else(|| USAGE.into())
            .and_then(|k| keygen(&k)),
        Some("dist") => flag("--out")
            .ok_or_else(|| USAGE.into())
            .and_then(|o| dist(&o)),
        Some("sbom") if args.len() == 2 => sbom(Path::new(&args[1])),
        Some("publish") => match (flag("--keys"), flag("--dist"), flag("--repo")) {
            (Some(k), Some(d), Some(r)) => {
                publish(&k, &d, &r, args.iter().any(|a| a == "--resume"))
            }
            _ => Err(USAGE.into()),
        },
        _ => Err(USAGE.into()),
    };
    if let Err(e) = result {
        eprintln!("xtask failed: {e}");
        std::process::exit(1);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(c: &mut Command) -> Result {
    let status = c.status()?;
    if !status.success() {
        return Err(format!("{c:?} failed with {status}").into());
    }
    Ok(())
}

/// Extension directory names (`extensions/<name>`), sorted.
fn extensions() -> Result<Vec<String>> {
    let mut out = vec![];
    for e in fs::read_dir(root().join("extensions"))? {
        out.push(e?.file_name().into_string().map_err(|_| "non-UTF-8 name")?);
    }
    out.sort();
    Ok(out)
}

fn bin_name(ext: &str) -> String {
    format!("calve_ext_{}", ext.replace('-', "_"))
}

/// Builds every CIC module for wasm32; returns `(extension, wasm path)`.
fn build_modules() -> Result<Vec<(String, PathBuf)>> {
    let target = root().join("target/cic");
    let mut c = Command::new(env!("CARGO"));
    c.current_dir(root())
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .arg("--target-dir")
        .arg(&target);
    let exts = extensions()?;
    for e in &exts {
        c.args(["-p", &format!("calve-cic-{e}")]);
    }
    run(&mut c)?;
    Ok(exts
        .into_iter()
        .map(|e| {
            let file = format!("calve_cic_{}.wasm", e.replace('-', "_"));
            let path = target.join("wasm32-unknown-unknown/release").join(file);
            (e, path)
        })
        .collect())
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result {
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "target") {
                rust_files(&p, out)?;
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    Ok(())
}

/// Code (comments stripped) naming `word` as a whole word or path.
fn mentions(source: &str, word: &str) -> bool {
    source.lines().any(|line| {
        let code = line.split("//").next().unwrap_or_default();
        code.match_indices(word).any(|(i, _)| {
            let before = code[..i].chars().next_back();
            let after = code[i + word.len()..].chars().next();
            let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
            !ident(before) && !ident(after)
        })
    })
}

/// Ambient I/O a CIC module must not name (on wasm32 it compiles to a panicking stub, which
/// would hide a determinism bug instead of failing the build).
const AMBIENT: [&str; 7] = [
    "std::fs",
    "std::net",
    "std::env",
    "std::process",
    "std::thread",
    "SystemTime",
    "Instant",
];

/// Allowed normal dependencies per package (dev-dependencies are free).
fn allowed_deps(package: &str) -> Option<&'static [&'static str]> {
    Some(match package {
        "cic-guest" => &["calve-integration-contract", "serde", "serde_json"],
        "calve-domain" => &[
            "base64",
            "calve-integration-contract",
            "openaevc",
            "serde_json",
            "similar",
        ],
        "calve-extensions-conformance" => &[],
        p if p.starts_with("calve-cic-") => &["calve-domain", "cic-guest"],
        p if p.starts_with("calve-ext-") => &["calve-domain"],
        _ => return None,
    })
}

fn check_architecture() -> Result {
    let mut problems = vec![];
    // 1. unsafe only in the ABI runtime.
    let mut files = vec![];
    for dir in ["crates", "extensions", "xtask"] {
        rust_files(&root().join(dir), &mut files)?;
    }
    let allowed = [
        root().join("crates/cic-guest/src/lib.rs"),
        // This checker names the word it looks for.
        root().join("xtask/src/main.rs"),
    ];
    for f in &files {
        let s = fs::read_to_string(f)?;
        if !allowed.contains(f) && (mentions(&s, "unsafe") || s.contains("allow(unsafe_code)")) {
            problems.push(format!("{}: unsafe outside crates/cic-guest", f.display()));
        }
    }
    // 2. No ambient I/O in CIC code (the native servers' `std::process::ExitCode` is allowed).
    let mut cic = vec![];
    rust_files(&root().join("crates/cic-guest/src"), &mut cic)?;
    rust_files(&root().join("crates/calve-domain/src"), &mut cic)?;
    for e in extensions()? {
        rust_files(
            &root().join("extensions").join(&e).join("cic/src"),
            &mut cic,
        )?;
    }
    for f in &cic {
        let s = fs::read_to_string(f)?.replace("std::process::ExitCode", "ExitCode");
        for word in AMBIENT {
            if mentions(&s, word) {
                problems.push(format!("{}: CIC code names {word}", f.display()));
            }
        }
    }
    // 3. Dependency allowlists.
    let mut manifests = vec![
        root().join("crates/cic-guest/Cargo.toml"),
        root().join("crates/calve-domain/Cargo.toml"),
        root().join("crates/conformance/Cargo.toml"),
    ];
    for e in extensions()? {
        manifests.push(root().join("extensions").join(&e).join("cic/Cargo.toml"));
        manifests.push(root().join("extensions").join(&e).join("native/Cargo.toml"));
    }
    for m in &manifests {
        let t: toml::Value = fs::read_to_string(m)?.parse()?;
        let name = t["package"]["name"].as_str().unwrap_or_default().to_owned();
        let Some(allowed) = allowed_deps(&name) else {
            problems.push(format!(
                "{}: {name} has no dependency allowlist",
                m.display()
            ));
            continue;
        };
        let deps = t.get("dependencies").and_then(|d| d.as_table());
        for dep in deps.into_iter().flat_map(|d| d.keys()) {
            if !allowed.contains(&dep.as_str()) {
                problems.push(format!("{name} depends on {dep} (not allowlisted)"));
            }
        }
    }
    // 4. Metadata and package consistency.
    let version = {
        let t: toml::Value = fs::read_to_string(root().join("Cargo.toml"))?.parse()?;
        t["workspace"]["package"]["version"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    for e in extensions()? {
        let dir = root().join("extensions").join(&e);
        let m: Metadata = serde_json::from_slice(&fs::read(dir.join("metadata.json"))?)?;
        if let Err(v) = m.validate() {
            problems.push(format!("{e}: metadata: {v}"));
        }
        if m.extension_id != format!("org.calve.{e}") || m.version != version {
            problems.push(format!(
                "{e}: metadata id/version must be org.calve.{e}@{version}"
            ));
        }
        let t: toml::Value = fs::read_to_string(dir.join("native/Cargo.toml"))?.parse()?;
        if t["bin"][0]["name"].as_str() != Some(&bin_name(&e)) {
            problems.push(format!("{e}: native binary must be named {}", bin_name(&e)));
        }
    }
    // 5. Built modules: exactly the ABI exports, no imports, no start function.
    for (e, path) in build_modules()? {
        if let Err(p) = check_module(&fs::read(&path)?) {
            problems.push(format!("{e}: {p}"));
        }
    }
    if problems.is_empty() {
        println!("architecture check passed");
        Ok(())
    } else {
        Err(problems.join("\n").into())
    }
}

fn check_module(wasm: &[u8]) -> std::result::Result<(), String> {
    use wasmparser::{Parser, Payload};
    let mut exports = BTreeSet::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|e| e.to_string())? {
            Payload::ImportSection(s) if s.count() > 0 => return Err("module imports".into()),
            Payload::StartSection { .. } => return Err("module has a start function".into()),
            Payload::ExportSection(s) => {
                for x in s {
                    let x = x.map_err(|e| e.to_string())?;
                    // The linker's immutable layout globals carry no capability (Calve's host
                    // refuses mutable global exports); every other export is ABI 1's.
                    let linker = ["__data_end", "__heap_base"].contains(&x.name);
                    if !(x.kind == wasmparser::ExternalKind::Global && linker) {
                        exports.insert(x.name.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    let want: BTreeSet<String> = ABI_EXPORTS.iter().map(|s| (*s).to_owned()).collect();
    if exports != want {
        return Err(format!("exports {exports:?}, want exactly {want:?}"));
    }
    Ok(())
}

/// ADR 0019: every calve-cli dependency uses one `rev`, it is the newest row of
/// docs/contract-pins.md, and Cargo.lock resolved exactly that commit from the public URL.
fn check_contract() -> Result {
    const URL: &str = "https://github.com/calvehq/calve-cli.git";
    let manifest: toml::Value = fs::read_to_string(root().join("Cargo.toml"))?.parse()?;
    let deps = manifest["workspace"]["dependencies"]
        .as_table()
        .ok_or("workspace dependencies")?;
    let revs: BTreeSet<&str> = deps
        .values()
        .filter(|d| d.get("git").and_then(|g| g.as_str()) == Some(URL))
        .map(|d| d.get("rev").and_then(|r| r.as_str()).unwrap_or(""))
        .collect();
    let rev = match revs.iter().collect::<Vec<_>>().as_slice() {
        [r] if r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()) => r.to_string(),
        _ => {
            return Err(
                format!("calve-cli dependencies must share one 40-hex rev: {revs:?}").into(),
            );
        }
    };
    let pins = fs::read_to_string(root().join("docs/contract-pins.md"))?;
    let latest = pins
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("| `").and_then(|r| r.split('`').next()))
        .ok_or("docs/contract-pins.md has no pin rows")?;
    if latest != rev {
        return Err(
            format!("Cargo.toml pins {rev}, docs/contract-pins.md last records {latest}").into(),
        );
    }
    let lock = fs::read_to_string(root().join("Cargo.lock"))?;
    let want = format!("git+{URL}?rev={rev}#{rev}");
    let calve_sources: BTreeSet<&str> = lock
        .lines()
        .filter_map(|l| {
            l.strip_prefix("source = \"")
                .and_then(|l| l.strip_suffix('"'))
        })
        .filter(|s| s.contains("calvehq/calve-cli"))
        .collect();
    if calve_sources.iter().any(|s| *s != want) || calve_sources.is_empty() {
        return Err(
            format!("Cargo.lock resolves calve-cli as {calve_sources:?}, want {want}").into(),
        );
    }
    println!("contract pin {rev} consistent (Cargo.toml, Cargo.lock, docs/contract-pins.md)");
    Ok(())
}

/// Refuses key material inside a git worktree (keys never live in a repository).
fn refuse_in_worktree(dir: &Path) -> Result {
    let abs = std::path::absolute(dir)?;
    if let Some(repo) = abs.ancestors().find(|a| a.join(".git").exists()) {
        return Err(format!(
            "{} is inside the git worktree {}; keep keys outside any repository",
            abs.display(),
            repo.display()
        )
        .into());
    }
    Ok(())
}

fn keygen(dir: &Path) -> Result {
    refuse_in_worktree(dir)?;
    if dir.exists() && fs::read_dir(dir)?.next().is_some() {
        return Err(format!("{} is not empty; refusing to overwrite keys", dir.display()).into());
    }
    fs::create_dir_all(dir)?;
    restrict(dir)?;
    for role in ROLES {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let path = dir.join(format!("{role}.key"));
        fs::write(&path, hex(&key.to_bytes()))?;
        restrict(&path)?;
        println!("{role}: key id {}", key_id(&key));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict(p: &Path) -> Result {
    use std::os::unix::fs::PermissionsExt;
    let mode = if p.is_dir() { 0o700 } else { 0o600 };
    Ok(fs::set_permissions(p, fs::Permissions::from_mode(mode))?)
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> Result {
    Ok(())
}

fn load_key(dir: &Path, role: &str) -> Result<SigningKey> {
    let text = fs::read_to_string(dir.join(format!("{role}.key")))?;
    let text = text.trim();
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or("x"), 16))
        .collect::<std::result::Result<_, _>>()?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{role}.key is not a 32-byte seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn key_json(k: &SigningKey) -> Value {
    json!({"keytype": "ed25519", "scheme": "ed25519",
        "keyval": {"public": hex(k.verifying_key().as_bytes())}})
}

fn key_id(k: &SigningKey) -> String {
    sha(&jcs::to_vec(&key_json(k)).expect("integer-only"))
}

/// Signed envelope over the canonical form; written pretty-printed (clients hash the bytes).
fn envelope(signed: &Value, k: &SigningKey) -> Result<Vec<u8>> {
    let c = jcs::to_vec(signed).map_err(|_| "metadata must be integer-only")?;
    let sig = hex(&k.sign(&c).to_bytes());
    Ok(serde_json::to_vec_pretty(
        &json!({"signed": signed, "signatures": [{"keyid": key_id(k), "sig": sig}]}),
    )?)
}

fn expires(days: i64) -> String {
    (jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24 * days))
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// `<arch>-<os>`, the key Calve looks up in `package.json`.
fn platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// Release packages: `<out>/<id>/<version>/{calve-integration.json, cic.wasm,
/// native/<platform>/<binary>}` and `<out>/SHA256SUMS`.
fn dist(out: &Path) -> Result {
    let exts = extensions()?;
    let target = root().join("target/dist");
    let mut c = Command::new(env!("CARGO"));
    c.current_dir(root())
        .args(["build", "--locked", "--release"])
        .arg("--target-dir")
        .arg(&target);
    for e in &exts {
        c.args(["-p", &format!("calve-ext-{e}")]);
    }
    run(&mut c)?;
    let modules: BTreeMap<String, PathBuf> = build_modules()?.into_iter().collect();
    let mut sums = String::new();
    for e in &exts {
        let src = root().join("extensions").join(e).join("metadata.json");
        let meta: Metadata = serde_json::from_slice(&fs::read(&src)?)?;
        let dir = out.join(&meta.extension_id).join(&meta.version);
        let native = dir.join("native").join(platform());
        fs::create_dir_all(&native)?;
        let bin = format!("{}{}", bin_name(e), std::env::consts::EXE_SUFFIX);
        let files = [
            (src, dir.join("calve-integration.json")),
            (modules[e].clone(), dir.join("cic.wasm")),
            (target.join("release").join(&bin), native.join(&bin)),
        ];
        for (from, to) in files {
            fs::copy(&from, &to)?;
            let rel = to.strip_prefix(out)?.to_string_lossy().replace('\\', "/");
            sums.push_str(&format!("{}  {rel}\n", sha(&fs::read(&to)?)));
        }
    }
    fs::write(out.join("SHA256SUMS"), sums)?;
    println!("packages for {} in {}", platform(), out.display());
    Ok(())
}

/// CycloneDX 1.5 SBOM of every locked dependency, derived from Cargo.lock.
fn sbom(output: &Path) -> Result {
    let lock: toml::Value = fs::read_to_string(root().join("Cargo.lock"))?.parse()?;
    let components: Vec<Value> = lock["package"]
        .as_array()
        .ok_or("Cargo.lock has no packages")?
        .iter()
        .map(|p| {
            let field =
                |k: &str, d: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or(d).to_owned();
            let (name, version) = (field("name", ""), field("version", ""));
            json!({"type": "library", "name": name, "version": version,
                "purl": format!("pkg:cargo/{name}@{version}"),
                "properties": [{"name": "cargo:source", "value": field("source", "workspace")},
                    {"name": "cargo:checksum", "value": field("checksum", "")}]})
        })
        .collect();
    let count = components.len();
    let doc = json!({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "calve-extensions",
            "version": env!("CARGO_PKG_VERSION")}},
        "components": components});
    fs::write(output, serde_json::to_vec_pretty(&doc)?)?;
    println!("wrote {count} components to {}", output.display());
    Ok(())
}

fn read_signed(repo: &Path, file: &str) -> Result<Option<Value>> {
    let p = repo.join("metadata").join(file);
    if !p.exists() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&fs::read(p)?)?;
    Ok(Some(v["signed"].clone()))
}

/// Files of the next repository version as `(repo-relative path, bytes)`, in commit order:
/// root (first publish only), targets blobs, then targets, snapshot and timestamp metadata.
fn stage(keys: &Path, dist: &Path, repo: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let k: BTreeMap<&str, SigningKey> = ROLES
        .iter()
        .map(|r| Ok((*r, load_key(keys, r)?)))
        .collect::<Result<_>>()?;
    let mut files: Vec<(String, Vec<u8>)> = vec![];
    // Root: created once; afterwards the keys must be the ones it names.
    match read_signed(repo, "root.json")? {
        Some(r) => {
            for role in ROLES {
                if r["roles"][role]["keyids"] != json!([key_id(&k[role])]) {
                    return Err(format!("{role}.key is not the key root.json names").into());
                }
            }
        }
        None => {
            let keys: serde_json::Map<String, Value> =
                k.values().map(|s| (key_id(s), key_json(s))).collect();
            let roles: serde_json::Map<String, Value> = ROLES
                .iter()
                .map(|r| {
                    (
                        r.to_string(),
                        json!({"keyids": [key_id(&k[r])], "threshold": 1}),
                    )
                })
                .collect();
            let signed = json!({"_type": "root", "spec_version": "1.0.31", "version": 1,
                "expires": expires(365), "consistent_snapshot": true, "keys": keys, "roles": roles});
            let bytes = envelope(&signed, &k["root"])?;
            files.push(("metadata/1.root.json".into(), bytes.clone()));
            files.push(("metadata/root.json".into(), bytes));
        }
    }
    let mut version = 0;
    for f in ["targets.json", "snapshot.json", "timestamp.json"] {
        let v = read_signed(repo, f)?.map_or(0, |s| s["version"].as_u64().unwrap_or(0));
        version = version.max(v);
    }
    version += 1;
    let mut meta: serde_json::Map<String, Value> = read_signed(repo, "targets.json")?
        .and_then(|p| p["targets"].as_object().cloned())
        .unwrap_or_default();
    let mut blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut put = |path: String, bytes: Vec<u8>, meta: &mut serde_json::Map<String, Value>| {
        let entry = json!({"length": bytes.len(), "hashes": {"sha256": sha(&bytes)}});
        let index = path.ends_with("/package.json") || path == "index.json";
        if !index && meta.get(&path).is_some_and(|old| *old != entry) {
            return Err(format!("{path} is already published with other content").into());
        }
        meta.insert(path.clone(), entry);
        blobs.insert(path, bytes);
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let mut ids: BTreeSet<String> = meta
        .keys()
        .filter_map(|p| p.strip_suffix("/package.json"))
        .map(str::to_owned)
        .collect();
    for id in fs::read_dir(dist)? {
        let id = id?;
        if !id.path().is_dir() {
            continue;
        }
        let id = id.file_name().into_string().map_err(|_| "non-UTF-8 id")?;
        let index_path = format!("{id}/package.json");
        let mut index: Value = if meta.contains_key(&index_path) {
            serde_json::from_slice(&fs::read(repo.join("targets").join(&index_path))?)?
        } else {
            json!({"schema": "calve.package/1", "id": id, "versions": []})
        };
        for v in fs::read_dir(dist.join(&id))? {
            let vdir = v?.path();
            let version = vdir.file_name().and_then(|n| n.to_str()).ok_or("version")?;
            let mut native = serde_json::Map::new();
            for p in fs::read_dir(vdir.join("native"))? {
                let pdir = p?.path();
                let platform = pdir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("platform")?;
                let mut bins = fs::read_dir(&pdir)?.collect::<std::io::Result<Vec<_>>>()?;
                let bin = bins
                    .pop()
                    .filter(|_| bins.is_empty())
                    .ok_or("exactly one native binary per platform")?;
                let name = bin.file_name().into_string().map_err(|_| "binary name")?;
                // ponytail: one file name per version, so two platforms whose binaries share a
                // name (Linux and macOS) cannot share a version yet; add per-platform file names
                // when a second Unix platform ships.
                put(
                    format!("{id}/{version}/{name}"),
                    fs::read(bin.path())?,
                    &mut meta,
                )?;
                native.insert(platform.into(), json!(name));
            }
            for f in ["cic.wasm", "calve-integration.json"] {
                put(
                    format!("{id}/{version}/{f}"),
                    fs::read(vdir.join(f))?,
                    &mut meta,
                )?;
            }
            let versions = index["versions"]
                .as_array_mut()
                .ok_or("package.json versions")?;
            let mut entry = versions
                .iter()
                .find(|e| e["version"] == version)
                .cloned()
                .unwrap_or_else(|| {
                    json!({"version": version, "kind": "cic-capable", "native": {},
                        "cic": "cic.wasm", "metadata": "calve-integration.json"})
                });
            for (p, n) in native {
                entry["native"][p] = n;
            }
            versions.retain(|e| e["version"] != version);
            versions.push(entry);
        }
        put(index_path, serde_json::to_vec(&index)?, &mut meta)?;
        ids.insert(id);
    }
    let index = json!({"schema": "calve.index/1", "ids": ids});
    put("index.json".into(), serde_json::to_vec(&index)?, &mut meta)?;
    // Consistent snapshots: each target also under `<sha256>.<name>`.
    for (path, bytes) in blobs {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", &path));
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        files.push((
            format!("targets/{prefix}{}.{name}", sha(&bytes)),
            bytes.clone(),
        ));
        files.push((format!("targets/{path}"), bytes));
    }
    let targets = envelope(
        &json!({"_type": "targets", "spec_version": "1.0.31", "version": version,
            "expires": expires(90), "targets": meta}),
        &k["targets"],
    )?;
    files.push((format!("metadata/{version}.targets.json"), targets.clone()));
    files.push(("metadata/targets.json".into(), targets));
    let snapshot = envelope(
        &json!({"_type": "snapshot", "spec_version": "1.0.31", "version": version,
            "expires": expires(30), "meta": {"targets.json": {"version": version}}}),
        &k["snapshot"],
    )?;
    files.push((
        format!("metadata/{version}.snapshot.json"),
        snapshot.clone(),
    ));
    files.push(("metadata/snapshot.json".into(), snapshot.clone()));
    let timestamp = envelope(
        &json!({"_type": "timestamp", "spec_version": "1.0.31", "version": version,
            "expires": expires(7), "meta": {"snapshot.json": {"version": version,
                "length": snapshot.len(), "hashes": {"sha256": sha(&snapshot)}}}}),
        &k["timestamp"],
    )?;
    files.push(("metadata/timestamp.json".into(), timestamp));
    Ok(files)
}

fn publish(keys: &Path, dist: &Path, repo: &Path, resume: bool) -> Result {
    refuse_in_worktree(keys)?;
    let staging = repo.join(".publish");
    let order = staging.join("order.json");
    match (order.exists(), resume) {
        (true, false) => {
            return Err("an interrupted publish is staged; rerun with --resume".into());
        }
        (false, true) => return Err("nothing staged to resume".into()),
        (true, true) => {}
        (false, false) => {
            // A crash while staging committed nothing, so leftovers are discarded.
            let _ = fs::remove_dir_all(&staging);
            let files = stage(keys, dist, repo)?;
            fs::create_dir_all(&staging)?;
            for (i, (_, bytes)) in files.iter().enumerate() {
                fs::write(staging.join(i.to_string()), bytes)?;
            }
            let paths: Vec<&String> = files.iter().map(|(p, _)| p).collect();
            fs::write(staging.join("order.tmp"), serde_json::to_vec(&paths)?)?;
            fs::rename(staging.join("order.tmp"), &order)?;
        }
    }
    // Commit in order, each file atomically, timestamp.json last: until then clients still
    // see the previous version.
    let paths: Vec<String> = serde_json::from_slice(&fs::read(&order)?)?;
    for (i, path) in paths.iter().enumerate() {
        let to = repo.join(path);
        fs::create_dir_all(to.parent().ok_or("path")?)?;
        let tmp = to.with_extension("xtask-tmp");
        fs::copy(staging.join(i.to_string()), &tmp)?;
        fs::rename(&tmp, &to)?;
        if std::env::var("XTASK_FAULT_AFTER").is_ok_and(|n| n == i.to_string()) {
            return Err(format!("injected fault after committing {path}").into());
        }
    }
    fs::remove_dir_all(&staging)?;
    let root_json = fs::read(repo.join("metadata/1.root.json"))?;
    println!(
        "published {}; pin 1.root.json with --root-digest {}",
        repo.display(),
        sha(&root_json)
    );
    Ok(())
}
