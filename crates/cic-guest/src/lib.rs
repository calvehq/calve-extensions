//! CIC guest runtime (ABI 1): the session state machine shared by every first-party CIC module.
//! A module implements [`Domain`] (pure, safe code) and calls [`export!`] once; this crate does
//! the rest — `hello/0`, request sequencing, the capture and relate streaming protocols with
//! their running digests, and the five ABI exports.
//!
//! The only `unsafe` code in calve-extensions lives in [`abi`] (raw guest pointers ↔ owned
//! buffers; user-approved exemption for Wasm ABI glue, M0 review Decision 2). Every block states
//! its SAFETY invariant; `tests/abi.rs` drives the exports adversarially.

use calve_integration_contract::digest::LineHasher;
use calve_integration_contract::hello::{GuestHello, Hello, HelloRequest};
use calve_integration_contract::jcs;
use calve_integration_contract::metadata::Metadata;
use calve_integration_contract::session::*;
use calve_integration_contract::wire::*;
use serde_json::{Value, json};

pub use calve_integration_contract as contract;

/// `(code, message)` of a CIC error response.
pub type Fail = (&'static str, &'static str);
pub const INVALID: Fail = ("INVALID_INPUT", "invalid input");
pub const BAD_STATE: Fail = ("BAD_STATE", "bad state");
pub const UNSUPPORTED: Fail = ("UNSUPPORTED_OP", "unsupported op");

/// Extension semantics. Ops a module does not declare keep the `UNSUPPORTED_OP` default (the
/// host never calls undeclared ops).
pub trait Domain: Default + 'static {
    /// `calve-integration.json`, byte-identical to the published package metadata.
    const METADATA: &'static str;

    fn detect(&self, _: DetectIn) -> Result<DetectOut, Fail> {
        Err(UNSUPPORTED)
    }
    fn check_plan(&self, _: CheckPlanIn) -> Result<CheckPlanOut, Fail> {
        Err(UNSUPPORTED)
    }
    fn classify(&self, _: ClassifyIn) -> Result<ClassifyOut, Fail> {
        Err(UNSUPPORTED)
    }
    fn diff(&self, _: DiffIn) -> Result<DiffOut, Fail> {
        Err(UNSUPPORTED)
    }
    /// One op per tuple (path-local; the runtime checks order and totals).
    fn capture_op(&self, _: &Tuple) -> Result<CaptureOp, Fail> {
        Err(UNSUPPORTED)
    }
    /// Relations within one delivered group (members are `None` when the group overflowed).
    fn relate_group(&self, _: &Group) -> Vec<Relation> {
        vec![]
    }
}

#[derive(Default)]
struct Capture {
    next_index: u64,
    last_path: Option<String>,
    tuples: u64,
    expected: u64,
    ops: LineHasher,
}

#[derive(Default)]
struct Relate {
    begin: Option<RelateBegin>,
    next_index: u64,
    groups: u64,
    members: u64,
    groups_hash: LineHasher,
    rel_hash: LineHasher,
    relations: u64,
}

#[derive(Default)]
enum Mode {
    #[default]
    Ready,
    Capture(Capture),
    Relate(Box<Relate>),
    Finished,
}

/// One guest instance: request sequence, session mode and the domain.
#[derive(Default)]
pub struct Guest<D> {
    seq: u64,
    mode: Mode,
    domain: D,
}

fn body<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, Fail> {
    serde_json::from_value(v.clone()).map_err(|_| INVALID)
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, Fail> {
    serde_json::to_value(v).map_err(|_| ("INTERNAL", "encode"))
}

fn metadata<D: Domain>() -> Metadata {
    serde_json::from_str(D::METADATA).expect("METADATA is valid calve-integration.json")
}

impl<D: Domain> Guest<D> {
    /// `hello/0` response from the module's metadata.
    pub fn hello(req: &[u8]) -> Vec<u8> {
        let ok = serde_json::from_slice::<HelloRequest>(req).is_ok_and(|r| r.hello == 0);
        let m = metadata::<D>();
        let h = Hello {
            hello: 0,
            guest: GuestHello {
                // A malformed hello request gets ABI 0, which no host accepts.
                abi: if ok { m.abi } else { 0 },
                cic: m.cic.clone(),
                capabilities: m.capabilities.clone(),
                schema: m.schema_number().unwrap_or(0),
                extension_id: m.extension_id.clone(),
                version: m.version.clone(),
            },
            x: None,
        };
        jcs::to_vec(&serde_json::to_value(h).expect("hello")).expect("hello is integer-only")
    }

    fn dispatch(&mut self, op: &str, b: &Value) -> Result<Value, Fail> {
        let d = &self.domain;
        match (op, &mut self.mode) {
            ("describe", _) => serde_json::from_str(D::METADATA).map_err(|_| INVALID),
            ("detect", _) => to_value(d.detect(body(b)?)?),
            ("check_plan", _) => to_value(d.check_plan(body(b)?)?),
            ("classify", _) => {
                let x: ClassifyIn = body(b)?;
                let entries = x.entries.clone();
                let out = d.classify(x)?;
                validate_classify(&entries, &out.decisions)
                    .map_err(|_| ("INTERNAL", "classify"))?;
                to_value(out)
            }
            ("diff", _) => to_value(d.diff(body(b)?)?),
            ("capture.begin", Mode::Ready) => {
                let x: CaptureBegin = body(b)?;
                self.mode = Mode::Capture(Capture {
                    expected: x.expected_tuples,
                    ..Default::default()
                });
                Ok(json!({}))
            }
            ("capture.chunk", Mode::Capture(c)) => {
                let x: CaptureChunk = body(b)?;
                if x.index != c.next_index {
                    return Err(INVALID);
                }
                let mut ops = Vec::with_capacity(x.tuples.len());
                for t in &x.tuples {
                    if c.last_path
                        .as_deref()
                        .is_some_and(|p| p.as_bytes() >= t.path.as_bytes())
                    {
                        return Err(INVALID);
                    }
                    c.last_path = Some(t.path.clone());
                    let op = d.capture_op(t)?;
                    validate_capture_chunk(std::slice::from_ref(t), std::slice::from_ref(&op))
                        .map_err(|_| INVALID)?;
                    ops.push(to_value(op)?);
                }
                c.next_index += 1;
                c.tuples += x.tuples.len() as u64;
                for o in &ops {
                    c.ops.push(o).map_err(|_| INVALID)?;
                }
                Ok(json!({ "ops": ops }))
            }
            ("capture.finish", Mode::Capture(c)) => {
                let x: CaptureFinish = body(b)?;
                if x.total_tuples != c.tuples || x.total_tuples != c.expected {
                    return Err(INVALID);
                }
                let total = c.tuples;
                let o = std::mem::take(&mut c.ops).finish();
                self.mode = Mode::Finished;
                Ok(json!({"output_digest": o, "total_ops": total}))
            }
            ("relate.begin", Mode::Ready) => {
                let x: RelateBegin = body(b)?;
                self.mode = Mode::Relate(Box::new(Relate {
                    begin: Some(x),
                    ..Default::default()
                }));
                Ok(json!({}))
            }
            ("relate.groups", Mode::Relate(r)) => {
                let x: RelateGroups = body(b)?;
                if x.index != r.next_index {
                    return Err(INVALID);
                }
                let raw = b["groups"].as_array().ok_or(INVALID)?;
                let mut rels = vec![];
                for (g, raw) in x.groups.iter().zip(raw) {
                    if !g.is_well_formed() {
                        return Err(INVALID);
                    }
                    r.groups_hash.push(raw).map_err(|_| INVALID)?;
                    r.groups += 1;
                    r.members += g.delivered_members();
                    rels.extend(d.relate_group(g));
                }
                rels.sort_by(|a, b| a.members.cmp(&b.members));
                let ack = Ack {
                    groups_received: r.groups,
                    index: x.index,
                    members_received: r.members,
                    running_groups_digest: r.groups_hash.peek(),
                };
                r.next_index += 1;
                for rel in &rels {
                    r.rel_hash.push(&to_value(rel)?).map_err(|_| INVALID)?;
                    r.relations += 1;
                }
                Ok(json!({"ack": ack, "relations": rels}))
            }
            ("relate.finish", Mode::Relate(r)) => {
                let x: RelateFinish = body(b)?;
                let begin = r.begin.as_ref().ok_or(BAD_STATE)?;
                if x.total_groups != begin.total_groups
                    || x.total_members != begin.total_members
                    || r.groups != begin.total_groups
                    || r.members != begin.total_members
                {
                    return Err(INVALID);
                }
                let kinds = metadata::<D>()
                    .relations
                    .into_iter()
                    .map(|k| KindOutcome {
                        kind: k.kind,
                        status: KindStatus::Complete,
                    })
                    .collect();
                let out = RelateFinishOk {
                    groups_digest_seen: r.groups_hash.peek(),
                    kinds,
                    relations_digest: std::mem::take(&mut r.rel_hash).finish(),
                    total_groups_seen: r.groups,
                    total_members_seen: r.members,
                    total_relations: r.relations,
                };
                self.mode = Mode::Finished;
                to_value(out)
            }
            (
                "capture.begin" | "capture.chunk" | "capture.finish" | "relate.begin"
                | "relate.groups" | "relate.finish",
                _,
            ) => Err(BAD_STATE),
            _ => Err(UNSUPPORTED),
        }
    }

    /// One request frame → one canonical response frame.
    pub fn call(&mut self, req: &[u8]) -> Vec<u8> {
        let resp = match serde_json::from_slice::<Request>(req) {
            Err(_) => Response {
                seq: 0,
                ok: None,
                err: Some(err(INVALID)),
            },
            Ok(r) => {
                let out = if r.v != "1.0" {
                    Err(UNSUPPORTED)
                } else if r.seq != self.seq + 1 {
                    Err(BAD_STATE)
                } else {
                    self.seq += 1;
                    self.dispatch(&r.op, &r.body)
                };
                match out {
                    Ok(v) => Response {
                        seq: r.seq,
                        ok: Some(v),
                        err: None,
                    },
                    Err(e) => Response {
                        seq: r.seq,
                        ok: None,
                        err: Some(err(e)),
                    },
                }
            }
        };
        jcs::to_vec(&serde_json::to_value(resp).expect("response")).unwrap_or_else(|_| {
            // A domain result with a float cannot be canonical; report it instead.
            let e = Response {
                seq: self.seq,
                ok: None,
                err: Some(err(("INTERNAL", "non-canonical result"))),
            };
            jcs::to_vec(&serde_json::to_value(e).expect("error")).expect("error is canonical")
        })
    }
}

fn err((code, message): Fail) -> WireError {
    WireError {
        code: code.into(),
        message: message.into(),
        retryable: false,
    }
}

/// Buffer ownership across the ABI. Used only by [`export!`].
#[allow(unsafe_code)]
pub mod abi {
    /// Hands a response buffer to the host as `(ptr << 32) | len`; the host frees it once with
    /// `cic_free`.
    pub fn leak(v: Vec<u8>) -> i64 {
        let len = v.len() as u32;
        let ptr = Box::into_raw(v.into_boxed_slice()) as *mut u8 as usize as u32;
        crate::contract::abi::pack(ptr, len)
    }

    /// `cic_alloc`: a zeroed request buffer owned by the guest until `take`.
    pub fn alloc(len: i32) -> i32 {
        if len < 1 {
            return 0;
        }
        Box::into_raw(vec![0u8; len as u32 as usize].into_boxed_slice()) as *mut u8 as usize as u32
            as i32
    }

    /// Takes ownership of a buffer allocated by [`alloc`] or returned by [`leak`].
    ///
    /// # Safety
    /// `(ptr, len)` must be exactly a live `Box<[u8]>` produced by `alloc(len)` (request
    /// buffers, ABI §6.2) or by `leak` (response buffers freed once through `cic_free`), and must
    /// not be taken twice. The host guarantees both by the buffer lifecycle; a host that breaks
    /// it can only corrupt this instance's own linear memory (wasm isolation).
    pub unsafe fn take(ptr: i32, len: i32) -> Box<[u8]> {
        // SAFETY: guaranteed by the caller contract above.
        unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                ptr as u32 as usize as *mut u8,
                len as u32 as usize,
            ))
        }
    }
}

/// Exports the five ABI 1 functions for `Domain` type `$d` (a type at the crate root). Call
/// once, at a cdylib's root.
#[macro_export]
macro_rules! export {
    ($d:ident) => {
        #[allow(unsafe_code)]
        mod __cic_abi {
            use super::$d;
            use std::cell::RefCell;
            thread_local! {
                static GUEST: RefCell<$crate::Guest<$d>> = RefCell::new(Default::default());
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn cic_abi_version() -> i32 {
                1
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn cic_alloc(len: i32) -> i32 {
                $crate::abi::alloc(len)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn cic_free(ptr: i32, len: i32) {
                // SAFETY: the host frees each response exactly once with the pointer and length
                // `leak` gave it (ABI §6.2).
                drop(unsafe { $crate::abi::take(ptr, len) });
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn cic_init(ptr: i32, len: i32) -> i64 {
                // SAFETY: (ptr, len) is the request buffer from `cic_alloc`, owned by the guest
                // from entry.
                let req = unsafe { $crate::abi::take(ptr, len) };
                $crate::abi::leak($crate::Guest::<$d>::hello(&req))
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn cic_call(ptr: i32, len: i32) -> i64 {
                // SAFETY: (ptr, len) is the request buffer from `cic_alloc`, owned by the guest
                // from entry.
                let req = unsafe { $crate::abi::take(ptr, len) };
                $crate::abi::leak(GUEST.with(|g| g.borrow_mut().call(&req)))
            }
        }
    };
}
