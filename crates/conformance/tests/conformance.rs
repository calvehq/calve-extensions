//! CIC conformance of the ten first-party modules (rev 10 §6.8). Each module is built for
//! wasm32, checked by Calve's production module validator, and driven through the same scenario
//! on Calve's production host (`calve-app` sandbox) and the testkit's independent mini host:
//! the transcripts must be byte-identical, and their digest must match `goldens/<name>.sha256`
//! (`UPDATE_GOLDENS=1` rewrites them after a reviewed change).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

use calve_app::integration::host_hello;
use calve_app::sandbox::{CalveHost, HostConfig, validate_module};
use calve_integration_contract::driver::{Driver, Session};
use calve_integration_contract::metadata::Metadata;
use calve_testkit::cic;
use calve_testkit::mini_host::MiniHost;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EXTENSIONS: [&str; 10] = [
    "software",
    "general",
    "rust",
    "go",
    "python",
    "javascript-typescript",
    "java",
    "c-cpp",
    "shell",
    "hcl",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds every CIC module once (own target dir, so it never waits on the outer cargo lock).
fn wasm(name: &str) -> Vec<u8> {
    static BUILD: Once = Once::new();
    let target = root().join("target/cic");
    BUILD.call_once(|| {
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
        for e in EXTENSIONS {
            c.args(["-p", &format!("calve-cic-{e}")]);
        }
        assert!(
            c.status().expect("cargo").success(),
            "building the CIC modules"
        );
    });
    let file = format!("calve_cic_{}.wasm", name.replace('-', "_"));
    std::fs::read(target.join("wasm32-unknown-unknown/release").join(file)).expect("module")
}

fn metadata_text(name: &str) -> String {
    std::fs::read_to_string(root().join("extensions").join(name).join("metadata.json"))
        .expect("metadata.json")
}

fn metadata(name: &str) -> Metadata {
    serde_json::from_str(&metadata_text(name)).expect("metadata")
}

fn calve(w: &[u8]) -> Box<dyn Driver> {
    Box::new(CalveHost::new(w, HostConfig::default()).expect("calve host"))
}

fn mini(w: &[u8]) -> Box<dyn Driver> {
    Box::new(MiniHost::with_fuel(w, 2_000_000_000).expect("mini host"))
}

type Transcript = Vec<(Vec<u8>, Vec<u8>)>;

fn open(make: fn(&[u8]) -> Box<dyn Driver>, name: &str) -> Session<Box<dyn Driver>> {
    Session::open_recording(make(&wasm(name)), &host_hello(), &metadata(name)).expect("hello")
}

fn ok(s: &mut Session<Box<dyn Driver>>, op: &str, body: Value) -> Value {
    s.request(op, body).unwrap_or_else(|e| panic!("{op}: {e}"))
}

/// The scenario of one module; each session on a fresh instance (§6.2).
fn scenario(make: fn(&[u8]) -> Box<dyn Driver>, name: &str) -> Vec<Transcript> {
    let meta = metadata(name);
    let mut out = vec![];
    let mut s = open(make, name);
    let described = ok(&mut s, "describe", json!({}));
    assert_eq!(
        described,
        serde_json::from_str::<Value>(&metadata_text(name)).unwrap()
    );
    // A wire error does not end the session.
    let e = s.raw("describe", json!({})).unwrap();
    assert!(e.is_ok());
    if meta.checks.is_some() {
        let found = ok(
            &mut s,
            "detect",
            json!({"markers": ["Cargo.toml", "go.mod", "package.json", "pom.xml", "CMakeLists.txt"], "extensions": ["sh", "tf", "py"]}),
        );
        let langs = found["languages"].as_array().unwrap();
        assert_eq!(langs.len(), 1, "{name}: {found}");
        let plan = ok(
            &mut s,
            "check_plan",
            json!({"languages": langs, "markers": ["build.gradle", "CMakeLists.txt"]}),
        );
        assert!(
            !plan["checks"].as_array().unwrap().is_empty(),
            "{name}: {plan}"
        );
        let none = ok(
            &mut s,
            "check_plan",
            json!({"languages": ["cobol"], "markers": []}),
        );
        assert_eq!(none["checks"], json!([]));
        let bad = s.raw("detect", json!({"markers": 1})).unwrap().unwrap_err();
        assert_eq!(bad.code, "INVALID_INPUT");
    } else {
        // Undeclared ops are refused host-side, without a guest call.
        assert!(s.raw("detect", json!({"markers": []})).is_err());
    }
    out.push(s.transcript.take().unwrap());

    if meta.files.is_some() {
        let mut s = open(make, name);
        let classified = ok(
            &mut s,
            "classify",
            json!({
                "entries": [
                    {"path": "dist", "kind": "dir"}, {"path": "target", "kind": "dir"},
                    {"path": "notes.log", "kind": "file", "size": 3}, {"path": "keep.log", "kind": "file", "size": 3},
                    {"path": "src", "kind": "dir"},
                ],
                "ignore_sources": {".calveignore": "*.log\n!keep.log\n"},
                "markers": ["package.json"],
            }),
        );
        let ignored: Vec<bool> = classified["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["ignored"].as_bool().unwrap())
            .collect();
        assert_eq!(ignored, [true, true, true, false, false], "{classified}");
        let bad = s
            .raw(
                "classify",
                json!({"entries": [], "ignore_sources": {".calveignore": "\\"}}),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(bad.code, "INVALID_INPUT");
        let d = ok(
            &mut s,
            "diff",
            json!({"path": "a", "before": "YQpiCg", "after": "YQpjCg", "context": 3}),
        );
        assert_eq!(d["hunks"][0]["lines"], json!([" a", "-b", "+c"]));
        out.push(s.transcript.take().unwrap());

        let (base, work) = cic::scenario(40);
        let mut s = open(make, name);
        let (ops, captured) = cic::capture(&mut s, &base, &work, json!({}), 7).expect("capture");
        assert_eq!(captured.total_ops, ops.len() as u64);
        assert!(
            ops.iter().any(|o| o["op"] == "refuse"),
            "over-limit files are refused"
        );
        out.push(s.transcript.take().unwrap());

        let mut s = open(make, name);
        let related = cic::relate(
            &mut s,
            &meta,
            &captured.output_digest,
            &ops,
            json!({}),
            64,
            5,
        )
        .expect("relate");
        assert!(!related.relations.is_empty(), "the scenario holds renames");
        for r in &related.relations {
            let (from, to) = (&ops[r.members[0] as usize], &ops[r.members[1] as usize]);
            assert_eq!(
                (from["op"].as_str(), to["op"].as_str()),
                (Some("delete"), Some("add"))
            );
            assert_eq!(r.payload, json!({"from": from["path"], "to": to["path"]}));
        }
        out.push(s.transcript.take().unwrap());
    }
    out
}

fn digest(t: &[Transcript]) -> String {
    let mut h = Sha256::new();
    for session in t {
        for (req, resp) in session {
            h.update(req);
            h.update(b"\n");
            h.update(resp);
            h.update(b"\n");
        }
        h.update(b"--\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_module_is_valid_and_identical_on_both_hosts() {
    for name in EXTENSIONS {
        let w = wasm(name);
        validate_module(&w, &HostConfig::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let meta = metadata(name);
        meta.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(meta.extension_id, format!("org.calve.{name}"));
        assert_eq!(
            meta.version,
            env!("CARGO_PKG_VERSION"),
            "{name}: package and metadata versions"
        );
        let (production, independent) = (scenario(calve, name), scenario(mini, name));
        assert!(
            production == independent,
            "{name}: transcripts differ between hosts"
        );
        let golden = root()
            .join("crates/conformance/goldens")
            .join(format!("{name}.sha256"));
        let got = digest(&production);
        if std::env::var_os("UPDATE_GOLDENS").is_some() {
            std::fs::write(&golden, format!("{got}\n")).unwrap();
        }
        let want = std::fs::read_to_string(&golden).unwrap_or_default();
        assert_eq!(
            want.trim(),
            got,
            "{name}: golden transcript changed (review, then UPDATE_GOLDENS=1)"
        );
    }
}

#[test]
fn malformed_requests_get_wire_errors_not_traps() {
    for name in ["software", "rust", "general"] {
        let mut d = calve(&wasm(name));
        let hello = json!({"hello": 0, "host": serde_json::to_value(host_hello()).unwrap()});
        d.init(&calve_integration_contract::jcs::to_vec(&hello).unwrap())
            .unwrap();
        for req in [
            &b"not json"[..],
            br#"{"v":"1.0","seq":2,"op":"describe","body":{}}"#,
            br#"{"v":"9.9","seq":1,"op":"describe","body":{}}"#,
        ] {
            let resp: Value = serde_json::from_slice(&d.call(req).unwrap()).unwrap();
            assert!(resp["err"]["code"].is_string(), "{name}: {resp}");
        }
    }
}
