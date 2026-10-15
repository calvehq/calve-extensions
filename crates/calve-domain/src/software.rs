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
/// Recorded by Calve before CIC; still valid in history, never emitted.
pub const RENAME: &str = "org.calve.software.rename";
pub const RENAMED: &str = "org.calve.software.renamed";
pub const VERIFIER: &str = "org.calve.software.snapshot.verify";
pub const EVALUATOR: &str = "org.calve.software.change-size";
pub const WRITE_ACTION: &str = "org.calve.software.write";
/// Inline content limit per file (until chunked content).
pub const MAX_CONTENT: u64 = 1024 * 1024;

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
        (_, Some(w)) if w.kind == EntryKind::File && w.size.unwrap_or(0) > MAX_CONTENT => {
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
        base64::engine::general_purpose::STANDARD
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
    use std::path::{Component, Path};

    use openaevc::crypto::sha256;
    use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve as run};
    use openaevc::extension::wire::{
        ApplyOutput, EvaluateOutput, Operation, ValidateOutput, VerifyOutput, WireError,
    };
    use openaevc::protocol::*;
    use serde_json::{Value, json};

    use super::*;

    const FILE_KINDS: [&str; 3] = [SNAPSHOT, DELETE, RENAME];

    fn locator_ok(locator: &str) -> Result<(), String> {
        let path = Path::new(locator);
        if locator.contains('\\')
            || path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            || path
                .components()
                .next()
                .is_some_and(|part| part.as_os_str().eq_ignore_ascii_case(".calve"))
        {
            return Err("file locator must be a relative path outside .calve".into());
        }
        Ok(())
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
                    if let Some((path, expected_digest)) = expected.as_ref()
                        && effect.target.locator == *path
                        && !found_expected
                    {
                        found_expected = true;
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
                schemas: Default::default(),
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
            for bad in ["../x", ".calve/db", ".CALVE/db", "/abs", "a\\b", ""] {
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
        let big = file("a", "33", MAX_CONTENT + 1);
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
        let b = |s: &[u8]| Some(base64::engine::general_purpose::STANDARD.encode(s));
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
}
