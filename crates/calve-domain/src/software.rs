//! First-party software domain (`org.calve.software`): Project files as exact snapshots.
//!
//! The CIC module decides what is ignored (`.calveignore` plus software and language defaults),
//! how a working-tree change is captured (one op per path; adds and deletes keyed by content
//! digest), which delete/add pairs are renames (a derived relation, never an effect), and how a
//! change reads as a line diff. The native extension validates and applies the effects OpenAEVC
//! records and judges candidates (`snapshot.verify`, `change-size`).

use calve_integration_contract::session::{Group, Relation};
use calve_integration_contract::wire::{
    CaptureOp, ClassifyIn, ClassifyOut, Decision, DiffIn, DiffOut, Entry, EntryKind, Hunk,
    MAX_DIFF_SIDE, Tuple,
};
use serde_json::json;

use crate::ignore::IgnoreRules;

pub const ID: &str = "org.calve.software";
pub const RESOURCE: &str = "org.calve.software.file";
pub const SNAPSHOT: &str = "org.calve.software.snapshot";
pub const DELETE: &str = "org.calve.software.delete";
/// A file over the inline limit, its chunks stored as OpenAEVC blobs (contract `content`).
pub const SNAPSHOT_CHUNKED: &str = "org.calve.software.snapshot-chunked";
/// The `calve.refs/1` document; its SHA-256 is bound in the native manifest.
pub const REFS: &str = include_str!("../../../extensions/software/calve-refs.json");
/// Recorded by Calve before CIC; still valid in history, never emitted.
pub const RENAME: &str = "org.calve.software.rename";
pub const RENAMED: &str = "org.calve.software.renamed";
pub const VERIFIER: &str = "org.calve.software.snapshot.verify";
pub const EVALUATOR: &str = "org.calve.software.change-size";
pub const WRITE_ACTION: &str = "org.calve.software.write";
/// Inline content limit per file; larger files are chunked up to the contract's `FILE_MAX`.
pub const MAX_CONTENT: u64 = calve_integration_contract::content::INLINE_MAX;

pub type Fail = (&'static str, &'static str);
const INVALID: Fail = ("INVALID_INPUT", "invalid input");

/// `classify`: one decision per entry, from the defaults for the root markers and the ignore
/// files the host passed.
pub fn classify(x: ClassifyIn) -> Result<ClassifyOut, Fail> {
    let rules = IgnoreRules::new(&x.markers, &x.ignore_sources)
        .map_err(|_| ("INVALID_INPUT", "invalid ignore file"))?;
    let decisions = x
        .entries
        .into_iter()
        .map(|e| {
            let d = rules.decide(&e.path, e.kind == EntryKind::Dir);
            Decision {
                path: e.path,
                ignored: d.ignored,
                rule: d.rule,
            }
        })
        .collect();
    Ok(ClassifyOut { decisions })
}

/// `capture`: adds and deletes of files carry their content digest as the group key, so the
/// host groups candidate renames; over-limit files are refused.
pub fn capture_op(t: &Tuple) -> Result<CaptureOp, Fail> {
    let key = |e: &Entry| {
        if e.kind == EntryKind::File {
            e.digest.clone()
        } else {
            None
        }
    };
    let path = t.path.clone();
    Ok(match (&t.base, &t.work) {
        (_, Some(w))
            if w.kind == EntryKind::File
                && w.size.unwrap_or(0) > calve_integration_contract::content::FILE_MAX =>
        {
            CaptureOp::Refuse {
                path,
                reason: "too_large".into(),
            }
        }
        (None, Some(w)) => CaptureOp::Add {
            path,
            group_key: key(w),
        },
        (Some(b), None) => CaptureOp::Delete {
            path,
            group_key: key(b),
        },
        (Some(b), Some(w)) if b == w => CaptureOp::Unchanged { path },
        (Some(_), Some(_)) => CaptureOp::Modify { path },
        (None, None) => return Err(INVALID),
    })
}

/// `relate`: a group of same-content ops is a rename exactly when it holds one delete and one
/// add. Anything else (copies, several candidates, an overflowed group) is ambiguous and
/// relates nothing.
pub fn relate_group(g: &Group) -> Vec<Relation> {
    let Some(ms) = &g.members else {
        return vec![];
    };
    let of = |op: &str| ms.iter().filter(|m| m.op["op"] == op).collect::<Vec<_>>();
    match (ms.len(), of("delete").as_slice(), of("add").as_slice()) {
        (2, [from], [to]) => vec![Relation {
            kind: RENAMED.into(),
            members: vec![from.op_index, to.op_index],
            payload: json!({"from": from.path, "to": to.path}),
        }],
        _ => vec![],
    }
}

fn decode(side: Option<&str>) -> Result<Vec<u8>, Fail> {
    use base64::Engine;
    side.map_or(Ok(vec![]), |s| {
        // OpenAEVC's encoding, as Calve sends it: URL-safe alphabet, no padding.
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| INVALID)
    })
}

/// `diff`: unified-diff hunks of two text sides (absent = empty); binary for NUL bytes or
/// invalid UTF-8.
pub fn diff(x: DiffIn) -> Result<DiffOut, Fail> {
    let (before, after) = (decode(x.before.as_deref())?, decode(x.after.as_deref())?);
    if before.len() as u64 > MAX_DIFF_SIDE || after.len() as u64 > MAX_DIFF_SIDE {
        return Ok(DiffOut::TooLarge);
    }
    let (Ok(old), Ok(new)) = (std::str::from_utf8(&before), std::str::from_utf8(&after)) else {
        return Ok(DiffOut::Binary);
    };
    if old.contains('\0') || new.contains('\0') {
        return Ok(DiffOut::Binary);
    }
    let text = similar::TextDiff::from_lines(old, new);
    let mut unified = text.unified_diff();
    unified.context_radius(x.context.min(1024) as usize);
    let hunks = unified
        .iter_hunks()
        .map(|h| {
            let ops = h.ops();
            let (first, last) = (&ops[0], &ops[ops.len() - 1]);
            let old = first.old_range().start..last.old_range().end;
            let new = first.new_range().start..last.new_range().end;
            // Unified convention: a 1-based start, or the line before an empty range.
            let start = |r: &std::ops::Range<usize>| (r.start + usize::from(!r.is_empty())) as u64;
            Hunk {
                old_start: start(&old),
                old_lines: old.len() as u64,
                new_start: start(&new),
                new_lines: new.len() as u64,
                lines: h
                    .iter_changes()
                    .map(|c| {
                        let sign = match c.tag() {
                            similar::ChangeTag::Equal => ' ',
                            similar::ChangeTag::Delete => '-',
                            similar::ChangeTag::Insert => '+',
                        };
                        format!(
                            "{sign}{}",
                            c.value().strip_suffix('\n').unwrap_or(c.value())
                        )
                    })
                    .collect(),
            }
        })
        .collect();
    Ok(DiffOut::Hunks { hunks })
}

#[cfg(feature = "native")]
pub use native::serve;

#[cfg(feature = "native")]
mod native {
    use openaevc::crypto::sha256;
    use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve as run};
    use openaevc::extension::wire::{
        ApplyOutput, EvaluateOutput, Operation, ValidateOutput, VerifyOutput, WireError,
    };
    use openaevc::protocol::*;
    use serde_json::{Value, json};

    use super::*;

    const FILE_KINDS: [&str; 4] = [SNAPSHOT, SNAPSHOT_CHUNKED, DELETE, RENAME];

    /// The contract's locator rules, exactly as Calve's host applies them (one parser, so no
    /// locator is valid here and read differently there).
    fn locator_ok(locator: &str) -> Result<(), String> {
        calve_integration_contract::locator::validate(locator)
    }

    /// Validates any software file effect. Returns the content digest and size it establishes;
    /// a deletion establishes no content and reports size 0.
    pub(super) fn inspect(effect: &EffectProposal) -> Result<(Option<Digest>, u64), String> {
        if !FILE_KINDS.contains(&effect.kind.as_str())
            || effect.target.kind != RESOURCE
            || effect.target.extension != ID
        {
            return Err("effect must target a Calve software file".into());
        }
        locator_ok(&effect.target.locator)?;
        if !effect.preconditions.is_empty() || !effect.outputs.is_empty() {
            return Err("software effects do not use preconditions or outputs".into());
        }
        let payload = effect
            .payload
            .as_object()
            .ok_or("payload must be an object")?;
        if effect.kind == SNAPSHOT_CHUNKED {
            // Structure and limits; Calve verifies the blobs, which an extension cannot read.
            let (digest, size) =
                calve_integration_contract::content::validate_chunked(&effect.payload)?;
            return Ok((Some(digest.parse().map_err(|_| "invalid digest")?), size));
        }
        if effect.kind == DELETE {
            if payload.len() != 1 {
                return Err("delete payload needs only previous_digest".into());
            }
            payload
                .get("previous_digest")
                .and_then(Value::as_str)
                .ok_or("missing previous_digest")?
                .parse::<Digest>()
                .map_err(|_| "invalid previous_digest")?;
            return Ok((None, 0));
        }
        let expected_keys = if effect.kind == RENAME { 4 } else { 3 };
        if payload.len() != expected_keys {
            return Err("payload needs digest, size and content (and from, for renames)".into());
        }
        if effect.kind == RENAME {
            let from = payload
                .get("from")
                .and_then(Value::as_str)
                .ok_or("missing from")?;
            locator_ok(from)?;
            if from == effect.target.locator {
                return Err("rename must change the path".into());
            }
        }
        let expected: Digest = payload
            .get("digest")
            .and_then(Value::as_str)
            .ok_or("missing digest")?
            .parse()
            .map_err(|_| "invalid digest")?;
        let size = payload
            .get("size")
            .and_then(Value::as_u64)
            .ok_or("missing size")?;
        let encoded = payload
            .get("content")
            .and_then(Value::as_str)
            .ok_or("missing content")?;
        if encoded.len() as u64 > (MAX_CONTENT * 4 / 3 + 8) {
            return Err("file exceeds 1 MiB capture limit".into());
        }
        let content = b64::decode(encoded).map_err(|_| "invalid base64 content")?;
        if content.len() as u64 != size || size > MAX_CONTENT || sha256(&content) != expected {
            return Err("content does not match digest or size".into());
        }
        Ok((Some(expected), size))
    }

    fn proposal(e: &AppliedEffect) -> EffectProposal {
        EffectProposal {
            kind: e.kind.clone(),
            target: e.target.clone(),
            payload: e.payload.clone(),
            preconditions: e.preconditions.clone(),
            outputs: e.outputs.clone(),
        }
    }

    fn config_error(m: impl Into<String>) -> WireError {
        WireError::new("invalid_config", m.into())
    }

    fn verify(config: Option<Value>, effects: &[AppliedEffect]) -> Result<VerifyOutput, WireError> {
        let config = config.unwrap_or_else(|| json!({}));
        let object = config
            .as_object()
            .ok_or_else(|| config_error("config must be an object"))?;
        if object.keys().any(|key| key != "path" && key != "digest")
            || object.contains_key("path") != object.contains_key("digest")
        {
            return Err(config_error("provide both path and digest, or neither"));
        }
        let expected = match object.get("path") {
            Some(path) => {
                let path = path
                    .as_str()
                    .ok_or_else(|| config_error("path must be a string"))?;
                let digest: Digest = object["digest"]
                    .as_str()
                    .ok_or_else(|| config_error("digest must be a string"))?
                    .parse()
                    .map_err(|_| config_error("invalid digest"))?;
                Some((path, digest))
            }
            None => None,
        };
        let mut checked = 0;
        let mut found_expected = false;
        let mut findings = Vec::new();
        for effect in effects
            .iter()
            .rev()
            .filter(|e| FILE_KINDS.contains(&e.kind.as_str()))
        {
            checked += 1;
            match inspect(&proposal(effect)) {
                Ok((digest, _)) => {
                    // A recorded rename also removes its source path: newest first, that is
                    // the state of `from`.
                    let at = |p: &str| effect.target.locator == p;
                    let moved_from = |p: &str| {
                        effect.kind == RENAME && effect.payload["from"].as_str() == Some(p)
                    };
                    if let Some((path, expected_digest)) = expected.as_ref()
                        && !found_expected
                        && (at(path) || moved_from(path))
                    {
                        found_expected = true;
                        let digest = if at(path) { digest } else { None };
                        if digest != Some(*expected_digest) {
                            findings.push(Finding {
                                code: "org.calve.software.digest_mismatch".into(),
                                message: format!(
                                    "{path} has digest {}, expected {expected_digest}",
                                    digest.map_or("<deleted>".to_owned(), |d| d.to_string())
                                ),
                                resource: Some(effect.target.clone()),
                            });
                        }
                    }
                }
                Err(message) => findings.push(Finding {
                    code: "org.calve.software.invalid_snapshot".into(),
                    message,
                    resource: Some(effect.target.clone()),
                }),
            }
        }
        if let Some((path, _)) = expected.as_ref()
            && !found_expected
        {
            findings.push(Finding {
                code: "org.calve.software.snapshot_missing".into(),
                message: format!("no snapshot of {path} in candidate"),
                resource: None,
            });
        }
        let status = if !findings.is_empty() {
            VerificationStatus::Fail
        } else if checked == 0 {
            VerificationStatus::Inconclusive
        } else {
            VerificationStatus::Pass
        };
        Ok(VerifyOutput {
            status,
            findings,
            facts: Default::default(),
        })
    }

    fn evaluate(
        config: Option<Value>,
        effects: &[AppliedEffect],
    ) -> Result<EvaluateOutput, WireError> {
        let config = config.unwrap_or_else(|| json!({}));
        let object = config
            .as_object()
            .ok_or_else(|| config_error("config must be an object"))?;
        if object
            .keys()
            .any(|key| key != "warn_after_bytes" && key != "warn_after_files")
        {
            return Err(config_error("unknown change-size option"));
        }
        let threshold = |key: &str, default: u64| -> Result<u64, WireError> {
            object
                .get(key)
                .map(|v| {
                    v.as_u64()
                        .ok_or_else(|| config_error(format!("{key} must be a nonnegative integer")))
                })
                .transpose()
                .map(|v| v.unwrap_or(default))
        };
        let warn_after_bytes = threshold("warn_after_bytes", 256 * 1024)?;
        let warn_after_files = threshold("warn_after_files", 16)?;
        let (mut files, mut bytes) = (0u64, 0u64);
        for effect in effects
            .iter()
            .filter(|e| FILE_KINDS.contains(&e.kind.as_str()))
        {
            let (_, size) =
                inspect(&proposal(effect)).map_err(|e| WireError::new("invalid_effect", e))?;
            files += 1;
            bytes = bytes
                .checked_add(size)
                .ok_or_else(|| WireError::new("overflow", "change size overflow"))?;
        }
        let verdict = if files == 0 {
            EvaluationVerdict::Unknown
        } else if files > warn_after_files || bytes > warn_after_bytes {
            EvaluationVerdict::Warn
        } else {
            EvaluationVerdict::Allow
        };
        Ok(EvaluateOutput {
            verdict,
            metrics: [
                ("org.calve.software.changed_files".into(), files as i64),
                ("org.calve.software.changed_bytes".into(), bytes as i64),
            ]
            .into(),
            facts: Default::default(),
        })
    }

    struct Software;

    impl Extension for Software {
        fn manifest(&self) -> ExtensionManifest {
            ExtensionManifest {
                id: ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                protocol: SUPPORTED_PROTOCOL,
                contract: SUPPORTED_CONTRACT,
                publisher: None,
                artifact_digest: self_artifact_digest(),
                resource_kinds: vec![ResourceKindDecl {
                    kind: RESOURCE.into(),
                    description: Some("Project file snapshot".into()),
                }],
                effect_kinds: FILE_KINDS
                    .iter()
                    .map(|kind| EffectKindDecl {
                        kind: (*kind).into(),
                        resource_kind: RESOURCE.into(),
                        required_actions: vec![WRITE_ACTION.into()],
                    })
                    .collect(),
                verifier_kinds: vec![VERIFIER.into()],
                evaluator_kinds: vec![EVALUATOR.into()],
                composition_validators: vec![],
                host_capabilities: vec![],
                schemas: [(
                    calve_integration_contract::refs::SCHEMA.to_owned(),
                    sha256(REFS.as_bytes()),
                )]
                .into(),
                execution_modes: vec!["subprocess".into()],
                entrypoint: Entrypoint {
                    command: "calve_ext_software".into(),
                    args: vec![],
                },
            }
        }

        fn handle(
            &mut self,
            operation: Operation,
            _: &mut HostContext<'_>,
        ) -> Result<Value, WireError> {
            let encode = |v: Result<Value, serde_json::Error>| {
                v.map_err(|e| WireError::new("encode", e.to_string()))
            };
            match operation {
                Operation::ValidateEffect { effect, .. } => {
                    let r = inspect(&effect);
                    encode(serde_json::to_value(ValidateOutput {
                        valid: r.is_ok(),
                        reason: r.err(),
                    }))
                }
                Operation::ApplyEffect { effect, .. } => {
                    let (digest, size) =
                        inspect(&effect).map_err(|e| WireError::new("invalid_effect", e))?;
                    let outcome = match digest {
                        Some(digest) => json!({"digest": digest, "size": size}),
                        None => json!({"deleted": true}),
                    };
                    encode(serde_json::to_value(ApplyOutput { outcome }))
                }
                Operation::Verify {
                    kind,
                    config,
                    effects,
                    ..
                } if kind == VERIFIER => encode(serde_json::to_value(verify(config, &effects)?)),
                Operation::Evaluate {
                    kind,
                    config,
                    effects,
                    ..
                } if kind == EVALUATOR => encode(serde_json::to_value(evaluate(config, &effects)?)),
                other => Err(WireError::new(
                    "unsupported",
                    format!("{} is not supported", other.name()),
                )),
            }
        }
    }

    pub fn serve() -> std::process::ExitCode {
        run(Software)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn effect(kind: &str, locator: &str, payload: Value) -> EffectProposal {
            EffectProposal {
                kind: kind.into(),
                target: ResourceRef {
                    kind: RESOURCE.into(),
                    locator: locator.into(),
                    version: None,
                    extension: ID.into(),
                },
                payload,
                preconditions: vec![],
                outputs: vec![],
            }
        }

        #[test]
        fn snapshots_deletes_and_recorded_renames() {
            let d = sha256(b"hi\n");
            let put = json!({"digest": d, "size": 3, "content": "aGkK"});
            assert_eq!(
                inspect(&effect(SNAPSHOT, "a.txt", put.clone())),
                Ok((Some(d), 3))
            );
            let mut lie = put.clone();
            lie["size"] = json!(2);
            assert!(inspect(&effect(SNAPSHOT, "a.txt", lie)).is_err());
            for bad in [
                "../x",
                ".calve/db",
                ".CALVE/db",
                ".calve./db",
                "/abs",
                "a\\b",
                "",
                "a/./b",
                "a//b",
                "a/",
                "c:x",
                "a/NUL.txt",
                "CALVE~1/db",
                "x ",
                "x.",
            ] {
                assert!(
                    inspect(&effect(SNAPSHOT, bad, put.clone())).is_err(),
                    "{bad}"
                );
            }
            let del = json!({"previous_digest": d});
            assert_eq!(inspect(&effect(DELETE, "a.txt", del)), Ok((None, 0)));
            let mut moved = put.clone();
            moved["from"] = json!("b.txt");
            assert!(inspect(&effect(RENAME, "a.txt", moved.clone())).is_ok());
            moved["from"] = json!("a.txt");
            assert!(
                inspect(&effect(RENAME, "a.txt", moved)).is_err(),
                "same path"
            );
        }

        #[test]
        fn chunked_snapshots_and_the_bound_refs_document() {
            let h = |c: char| format!("sha256:{}", c.to_string().repeat(64));
            let size = calve_integration_contract::content::INLINE_MAX + 1;
            let ok = json!({"digest": h('a'), "size": size,
                "chunks": [{"blob_digest": h('b'), "digest": h('c'), "size": size}]});
            assert_eq!(
                inspect(&effect(SNAPSHOT_CHUNKED, "big.bin", ok.clone())),
                Ok((Some(h('a').parse().unwrap()), size))
            );
            let mut short = ok.clone();
            short["size"] = json!(size - 1);
            assert!(inspect(&effect(SNAPSHOT_CHUNKED, "big.bin", short)).is_err());
            // Every effect kind is declared in the refs document the manifest binds.
            let refs =
                calve_integration_contract::refs::parse(&serde_json::from_str(REFS).unwrap())
                    .unwrap();
            let m = Software.manifest();
            assert_eq!(
                m.schemas[calve_integration_contract::refs::SCHEMA],
                sha256(REFS.as_bytes())
            );
            for k in &m.effect_kinds {
                assert!(refs.contains_key(&k.kind), "{}", k.kind);
            }
        }

        fn applied(e: EffectProposal) -> AppliedEffect {
            serde_json::from_value(json!({
                "id": "eff_agqty775fbzsti4zb533hfn7nq", "work_unit": "wku_agqty7727z6cdkfarn4zhawr2i", "kind": e.kind, "target": e.target,
                "payload": e.payload, "outcome": {},
                // A provenance recorded by OpenAEVC (shape only; the verifier ignores it).
                "provenance": {"actor": "pri_agqty76tcz4sfcvgkfpn5nwyiy", "caller": "pri_agqty76tcz4sfcvgkfpn5nwyiy",
                    "provider": "p", "worker": "local", "harness": "h",
                    "extension": {"id": ID, "version": "0.1.0", "manifest_digest": format!("sha256:{}", "0".repeat(64))},
                    "request_id": "req_agqty7736v5qdfg6a4355ptacq", "pack": "rpk_agqty77tej5g5j2vk22qgxe4l4",
                    "generation": 2, "execution": "exe_agqty773h52txmvjpttfxexzie",
                    "runtime_instance": "rti_agqty77vrv3bnooly3oihyvrza"}
            }))
            .unwrap_or_else(|err| panic!("AppliedEffect shape: {err}"))
        }

        /// Each acceptance condition of a software effect holds on its own (mutation analysis
        /// found conditions joined so that one violation alone slipped through).
        #[test]
        fn every_effect_condition_is_enforced_alone() {
            let d = sha256(b"hi\n");
            let put = json!({"digest": d, "size": 3, "content": "aGkK"});
            let ok = effect(SNAPSHOT, "a.txt", put.clone());
            assert!(inspect(&ok).is_ok());
            let mut e = ok.clone();
            e.kind = "org.calve.software.other".into();
            assert!(inspect(&e).is_err(), "kind");
            let mut e = ok.clone();
            e.target.kind = "org.other.file".into();
            assert!(inspect(&e).is_err(), "resource kind");
            let mut e = ok.clone();
            e.target.extension = "org.other".into();
            assert!(inspect(&e).is_err(), "extension");
            let mut e = ok.clone();
            e.preconditions = vec![json!({})];
            assert!(inspect(&e).is_err(), "preconditions");
            let mut e = ok.clone();
            e.outputs = vec![ok.target.clone()];
            assert!(inspect(&e).is_err(), "outputs");
            // Content must match its digest and size, each on its own.
            let other = sha256(b"ho\n");
            let wrong_digest = json!({"digest": other, "size": 3, "content": "aGkK"});
            assert!(inspect(&effect(SNAPSHOT, "a.txt", wrong_digest)).is_err());
            let wrong_size = json!({"digest": d, "size": 4, "content": "aGkK"});
            assert!(inspect(&effect(SNAPSHOT, "a.txt", wrong_size)).is_err());
            // The inline bound: MAX_CONTENT bytes accepted, one more refused even when
            // digest and size agree.
            let snap = |bytes: &[u8]| {
                effect(
                    SNAPSHOT,
                    "big.bin",
                    json!({"digest": sha256(bytes), "size": bytes.len(), "content": b64::encode(bytes)}),
                )
            };
            assert!(inspect(&snap(&vec![b'a'; MAX_CONTENT as usize])).is_ok());
            assert!(inspect(&snap(&vec![b'a'; MAX_CONTENT as usize + 1])).is_err());
            // The encoded-length guard refuses before decoding, exactly past its bound.
            let bound = (MAX_CONTENT * 4 / 3 + 8) as usize;
            let encoded = |n: usize| {
                effect(
                    SNAPSHOT,
                    "big.bin",
                    json!({"digest": d, "size": 3, "content": "A".repeat(n)}),
                )
            };
            let over = inspect(&encoded(bound + 1)).unwrap_err();
            assert!(over.contains("exceeds"), "{over}");
            let at = inspect(&encoded(bound)).unwrap_err();
            assert!(!at.contains("exceeds"), "{at}");
        }

        /// Verifier outcomes: config shape, Inconclusive without file effects, and only the
        /// newest effect on the expected path counts.
        #[test]
        fn verifier_outcomes_are_exact() {
            let d = sha256(b"hi\n");
            let put = json!({"digest": d, "size": 3, "content": "aGkK"});
            let stale = json!({"digest": sha256(b"ho\n"), "size": 3, "content": "aG8K"});
            assert!(
                verify(Some(json!({"path": "a.txt"})), &[]).is_err(),
                "path alone"
            );
            assert!(
                verify(Some(json!({"digest": d})), &[]).is_err(),
                "digest alone"
            );
            assert!(verify(Some(json!({"x": 1})), &[]).is_err(), "unknown key");
            assert_eq!(
                verify(None, &[]).unwrap().status,
                VerificationStatus::Inconclusive
            );
            let one = [applied(effect(SNAPSHOT, "a.txt", put.clone()))];
            assert_eq!(verify(None, &one).unwrap().status, VerificationStatus::Pass);
            // Older mismatch, newer match: the newest wins.
            let config = Some(json!({"path": "a.txt", "digest": d}));
            let history = [
                applied(effect(SNAPSHOT, "a.txt", stale.clone())),
                applied(effect(SNAPSHOT, "a.txt", put.clone())),
            ];
            assert_eq!(
                verify(config.clone(), &history).unwrap().status,
                VerificationStatus::Pass
            );
            let reversed = [
                applied(effect(SNAPSHOT, "a.txt", put)),
                applied(effect(SNAPSHOT, "a.txt", stale)),
            ];
            assert_eq!(
                verify(config.clone(), &reversed).unwrap().status,
                VerificationStatus::Fail
            );
            // A newer effect on another path does not count against the expected one.
            let at = |p: &str| {
                applied(effect(
                    SNAPSHOT,
                    p,
                    json!({"digest": d, "size": 3, "content": "aGkK"}),
                ))
            };
            let mut moved = json!({"digest": d, "size": 3, "content": "aGkK"});
            moved["from"] = json!("b.txt");
            // ...nor does a newer rename between two other paths.
            let elsewhere = [
                at("a.txt"),
                at("b.txt"),
                applied(effect(RENAME, "c.txt", moved)),
            ];
            assert_eq!(
                verify(config, &elsewhere).unwrap().status,
                VerificationStatus::Pass
            );
        }

        /// Evaluator thresholds are strict (`>`), counted per file and per byte, with the
        /// documented defaults (16 files, 256 KiB) and only the two known options.
        #[test]
        fn evaluator_thresholds_and_metrics_are_exact() {
            let snap = |name: &str, bytes: &[u8]| {
                applied(effect(
                    SNAPSHOT,
                    name,
                    json!({"digest": sha256(bytes), "size": bytes.len(), "content": b64::encode(bytes)}),
                ))
            };
            let verdict =
                |config: Value, effects: &[AppliedEffect]| evaluate(Some(config), effects).unwrap();
            assert!(evaluate(Some(json!({"other": 1})), &[]).is_err());
            assert!(evaluate(Some(json!({"warn_after_files": 1})), &[]).is_ok());
            assert!(evaluate(Some(json!({"warn_after_bytes": 1})), &[]).is_ok());
            assert_eq!(verdict(json!({}), &[]).verdict, EvaluationVerdict::Unknown);
            let two = [snap("a", b"xx"), snap("b", b"yyy")];
            let out = verdict(json!({}), &two);
            assert_eq!(out.verdict, EvaluationVerdict::Allow);
            assert_eq!(out.metrics["org.calve.software.changed_files"], 2);
            assert_eq!(out.metrics["org.calve.software.changed_bytes"], 5);
            // Files: at the threshold allowed, past it warned.
            assert_eq!(
                verdict(json!({"warn_after_files": 2}), &two).verdict,
                EvaluationVerdict::Allow
            );
            assert_eq!(
                verdict(json!({"warn_after_files": 1}), &two).verdict,
                EvaluationVerdict::Warn
            );
            // Bytes: the same.
            assert_eq!(
                verdict(json!({"warn_after_bytes": 5}), &two).verdict,
                EvaluationVerdict::Allow
            );
            assert_eq!(
                verdict(json!({"warn_after_bytes": 4}), &two).verdict,
                EvaluationVerdict::Warn
            );
            // Default byte threshold, 256 KiB: at it allowed, one byte past it warned.
            let at = [snap("a", &vec![b'a'; 256 * 1024])];
            assert_eq!(verdict(json!({}), &at).verdict, EvaluationVerdict::Allow);
            let past = [snap("a", &vec![b'a'; 256 * 1024 + 1])];
            assert_eq!(verdict(json!({}), &past).verdict, EvaluationVerdict::Warn);
            // Default file threshold, 16.
            let files = |n: usize| {
                (0..n)
                    .map(|i| snap(&format!("f{i}"), b"x"))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                verdict(json!({}), &files(16)).verdict,
                EvaluationVerdict::Allow
            );
            assert_eq!(
                verdict(json!({}), &files(17)).verdict,
                EvaluationVerdict::Warn
            );
        }

        #[test]
        fn a_later_rename_away_fails_the_expected_digest() {
            let d = sha256(b"hi\n");
            let put = json!({"digest": d, "size": 3, "content": "aGkK"});
            let mut moved = put.clone();
            moved["from"] = json!("a.txt");
            let config = Some(json!({"path": "a.txt", "digest": d}));
            let only_put = [applied(effect(SNAPSHOT, "a.txt", put.clone()))];
            assert_eq!(
                verify(config.clone(), &only_put).unwrap().status,
                VerificationStatus::Pass
            );
            let renamed_away = [
                applied(effect(SNAPSHOT, "a.txt", put)),
                applied(effect(RENAME, "b.txt", moved)),
            ];
            let out = verify(config, &renamed_away).unwrap();
            assert_eq!(out.status, VerificationStatus::Fail);
            assert_eq!(out.findings[0].code, "org.calve.software.digest_mismatch");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calve_integration_contract::session::Member;
    use calve_integration_contract::wire::ClassifyEntry;
    use std::collections::BTreeMap;

    fn file(path: &str, digest: &str, size: u64) -> Entry {
        Entry {
            path: path.into(),
            kind: EntryKind::File,
            digest: Some(digest.into()),
            size: Some(size),
            mode: None,
            target: None,
        }
    }

    fn tuple(base: Option<Entry>, work: Option<Entry>) -> Tuple {
        let path = base.as_ref().or(work.as_ref()).unwrap().path.clone();
        Tuple { path, base, work }
    }

    #[test]
    fn capture_ops_by_tuple_shape() {
        let a = file("a", "11", 1);
        let op = |b: Option<&Entry>, w: Option<&Entry>| {
            capture_op(&tuple(b.cloned(), w.cloned())).unwrap()
        };
        assert_eq!(
            op(None, Some(&a)),
            CaptureOp::Add {
                path: "a".into(),
                group_key: Some("11".into())
            }
        );
        assert_eq!(
            op(Some(&a), None),
            CaptureOp::Delete {
                path: "a".into(),
                group_key: Some("11".into())
            }
        );
        assert_eq!(
            op(Some(&a), Some(&a)),
            CaptureOp::Unchanged { path: "a".into() }
        );
        assert_eq!(
            op(Some(&a), Some(&file("a", "22", 1))),
            CaptureOp::Modify { path: "a".into() }
        );
        // Over the inline limit the host chunks; only files over FILE_MAX are refused.
        let chunked = file("a", "33", MAX_CONTENT + 1);
        assert!(matches!(
            op(Some(&a), Some(&chunked)),
            CaptureOp::Modify { .. }
        ));
        let big = file("a", "33", calve_integration_contract::content::FILE_MAX + 1);
        assert!(matches!(op(Some(&a), Some(&big)), CaptureOp::Refuse { .. }));
        let mut link = a.clone();
        link.kind = EntryKind::Symlink;
        link.digest = None;
        link.target = Some("b".into());
        assert_eq!(
            op(None, Some(&link)),
            CaptureOp::Add {
                path: "a".into(),
                group_key: None
            }
        );
    }

    fn member(op: &str, i: u64, path: &str) -> Member {
        Member {
            op: json!({"op": op, "path": path}),
            op_index: i,
            path: path.into(),
        }
    }

    #[test]
    fn rename_is_exactly_one_delete_and_one_add() {
        let g = |ms: Vec<Member>| Group {
            count: ms.len() as u64,
            key: "k".into(),
            members: Some(ms),
            overflow: None,
        };
        let r = relate_group(&g(vec![
            member("add", 4, "new"),
            member("delete", 1, "old"),
        ]));
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].members.clone(), r[0].payload.clone()),
            (vec![1, 4], json!({"from": "old", "to": "new"}))
        );
        assert!(relate_group(&g(vec![member("add", 1, "a"), member("add", 2, "b")])).is_empty());
        assert!(
            relate_group(&g(vec![
                member("delete", 1, "a"),
                member("add", 2, "b"),
                member("add", 3, "c")
            ]))
            .is_empty()
        );
        assert!(
            relate_group(&Group {
                count: 9,
                key: "k".into(),
                members: None,
                overflow: Some(true)
            })
            .is_empty()
        );
    }

    proptest::proptest! {
        /// A group relates exactly when it is one delete plus one add, and the relation runs
        /// from the delete to the add.
        #[test]
        fn pairing_rule(adds in proptest::collection::vec(proptest::bool::ANY, 0..6), overflow in proptest::bool::ANY) {
            let ms: Vec<Member> = adds
                .iter()
                .enumerate()
                .map(|(i, add)| member(if *add { "add" } else { "delete" }, i as u64, &format!("p{i}")))
                .collect();
            let n = adds.iter().filter(|a| **a).count();
            let g = Group { count: ms.len() as u64, key: "k".into(), members: (!overflow).then_some(ms), overflow: overflow.then_some(true) };
            let r = relate_group(&g);
            let expected = !overflow && adds.len() == 2 && n == 1;
            proptest::prop_assert_eq!(r.len(), usize::from(expected));
            if let Some(rel) = r.first() {
                let from = adds.iter().position(|a| !*a).unwrap() as u64;
                let to = adds.iter().position(|a| *a).unwrap() as u64;
                proptest::prop_assert_eq!(&rel.members, &vec![from, to]);
                proptest::prop_assert_eq!(&rel.kind, RENAMED);
            }
        }
    }

    #[test]
    fn classify_applies_language_defaults_by_marker() {
        let x = |markers: Vec<String>| ClassifyIn {
            entries: ["dist", "src", ".git", ".calveignore"]
                .iter()
                .map(|p| ClassifyEntry {
                    path: (*p).into(),
                    kind: EntryKind::Dir,
                    size: None,
                })
                .collect(),
            ignore_sources: BTreeMap::from([(".calveignore".into(), "src/\n".into())]),
            markers,
        };
        let ignored =
            |out: ClassifyOut| out.decisions.iter().map(|d| d.ignored).collect::<Vec<_>>();
        assert_eq!(
            ignored(classify(x(vec![])).unwrap()),
            [false, true, true, false]
        );
        assert_eq!(
            ignored(classify(x(vec!["package.json".into()])).unwrap()),
            [true, true, true, false]
        );
        let bad = ClassifyIn {
            entries: vec![],
            ignore_sources: BTreeMap::from([(".calveignore".into(), "\\".into())]),
            markers: vec![],
        };
        assert!(classify(bad).is_err());
    }

    #[test]
    fn diff_hunks_binary_and_limits() {
        use base64::Engine;
        let b = |s: &[u8]| Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s));
        let d = |before, after| {
            diff(DiffIn {
                path: "f".into(),
                before,
                after,
                context: 1,
            })
            .unwrap()
        };
        let DiffOut::Hunks { hunks } = d(b(b"a\nb\nc\nd\n"), b(b"a\nb\nX\nd\n")) else {
            panic!()
        };
        assert_eq!(hunks.len(), 1);
        assert_eq!(
            (
                hunks[0].old_start,
                hunks[0].old_lines,
                hunks[0].new_start,
                hunks[0].new_lines
            ),
            (2, 3, 2, 3)
        );
        assert_eq!(hunks[0].lines, [" b", "-c", "+X", " d"]);
        let DiffOut::Hunks { hunks } = d(None, b(b"new\n")) else {
            panic!()
        };
        assert_eq!(
            (hunks[0].old_start, hunks[0].old_lines, hunks[0].new_start),
            (0, 0, 1)
        );
        assert_eq!(
            d(b(b"same\n"), b(b"same\n")),
            DiffOut::Hunks { hunks: vec![] }
        );
        assert_eq!(d(b(b"a\0"), None), DiffOut::Binary);
        assert_eq!(d(b(&[0xff, 0xfe]), None), DiffOut::Binary);
        assert_eq!(
            d(b(&vec![b'a'; MAX_DIFF_SIDE as usize + 1]), None),
            DiffOut::TooLarge
        );
        assert!(
            diff(DiffIn {
                path: "f".into(),
                before: Some("!".into()),
                after: None,
                context: 3
            })
            .is_err()
        );
    }

    /// Boundaries cargo-mutants found unkilled: a file of exactly FILE_MAX is captured, one
    /// byte more is refused; a diff side of exactly MAX_DIFF_SIDE is diffed, and either side
    /// over it is too large.
    #[test]
    fn capture_and_diff_limits_are_exact() {
        use base64::Engine;
        let max = calve_integration_contract::content::FILE_MAX;
        let at = file("a", "44", max);
        assert!(matches!(
            capture_op(&tuple(None, Some(at))).unwrap(),
            CaptureOp::Add { .. }
        ));
        let over = file("a", "44", max + 1);
        assert!(matches!(
            capture_op(&tuple(None, Some(over))).unwrap(),
            CaptureOp::Refuse { .. }
        ));
        let b = |s: &[u8]| Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s));
        let d = |before, after| {
            diff(DiffIn {
                path: "f".into(),
                before,
                after,
                context: 1,
            })
            .unwrap()
        };
        let side = vec![b'a'; MAX_DIFF_SIDE as usize];
        let longer = vec![b'a'; MAX_DIFF_SIDE as usize + 1];
        assert!(matches!(d(b(&side), b(&side)), DiffOut::Hunks { .. }));
        assert_eq!(d(None, b(&longer)), DiffOut::TooLarge);
        assert_eq!(d(b(b"x"), b(&longer)), DiffOut::TooLarge);
    }
}
