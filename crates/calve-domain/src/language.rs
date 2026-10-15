//! First-party language domains. Each language ships as its own package: a CIC module that
//! detects the language and plans its checks, and a native OpenAEVC extension
//! (`calve_ext_<lang>`) whose verifier judges candidate-bound check evidence. Calve's check
//! runner produces that evidence by running the planned commands on the sealed candidate.

use calve_integration_contract::wire::{
    CheckPlanIn, CheckPlanOut, DetectIn, DetectOut, PlannedCheck,
};
use serde_json::Value;

pub const CHECK_EVIDENCE: &str = "org.calve.check-result/v1";

pub struct Check {
    pub name: &'static str,
    pub argv: &'static [&'static str],
}

impl Check {
    /// Tools such as shellcheck take the files to inspect as arguments.
    pub fn takes_files(&self) -> bool {
        self.argv == ["shellcheck"]
    }
}

pub struct Language {
    pub key: &'static str,
    pub display: &'static str,
    /// Any of these at the Project root marks the language as present.
    pub markers: &'static [&'static str],
    /// File extensions classified as this language's sources.
    pub sources: &'static [&'static str],
    pub checks: &'static [Check],
    /// Generated or dependency directories excluded from resource scans.
    pub ignore: &'static [&'static str],
    /// Environment the tools commonly need; everything else is cleared.
    pub env: &'static [&'static str],
}

impl Language {
    pub fn extension_id(&self) -> String {
        format!("org.calve.{}", self.key)
    }

    pub fn verifier(&self) -> String {
        format!("org.calve.{}.checks", self.key)
    }

    /// A root marker or a source file extension is present.
    pub fn detected(&self, markers: &[String], extensions: &[String]) -> bool {
        self.markers.iter().any(|m| markers.iter().any(|x| x == m))
            || self
                .sources
                .iter()
                .any(|s| extensions.iter().any(|x| x == s))
    }

    /// The checks to run: the language's defaults, or the build system the root markers name
    /// (Gradle without a `pom.xml`; CMake without a `Makefile`).
    pub fn checks(&self, markers: &[String]) -> &'static [Check] {
        let has = |m: &str| markers.iter().any(|x| x == m);
        match self.key {
            "java" if !has("pom.xml") && (has("build.gradle") || has("build.gradle.kts")) => GRADLE,
            "c-cpp" if has("CMakeLists.txt") && !has("Makefile") => CMAKE,
            _ => self.checks,
        }
    }
}

const GRADLE: &[Check] = &[Check {
    name: "test",
    argv: &["gradle", "--quiet", "test"],
}];

const CMAKE: &[Check] = &[
    Check {
        name: "configure",
        argv: &["cmake", "-S", ".", "-B", "build"],
    },
    Check {
        name: "build",
        argv: &["cmake", "--build", "build"],
    },
];

pub const LANGUAGES: &[Language] = &[
    Language {
        key: "rust",
        display: "Rust",
        markers: &["Cargo.toml"],
        sources: &["rs"],
        checks: &[
            Check {
                name: "check",
                argv: &["cargo", "check", "--all-targets"],
            },
            Check {
                name: "test",
                argv: &["cargo", "test"],
            },
            Check {
                name: "clippy",
                argv: &["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
            },
            Check {
                name: "fmt",
                argv: &["cargo", "fmt", "--check"],
            },
        ],
        ignore: &["target/"],
        env: &["CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"],
    },
    Language {
        key: "go",
        display: "Go",
        markers: &["go.mod", "go.work"],
        sources: &["go"],
        checks: &[
            Check {
                name: "test",
                argv: &["go", "test", "./..."],
            },
            Check {
                name: "vet",
                argv: &["go", "vet", "./..."],
            },
            Check {
                name: "fmt",
                argv: &["gofmt", "-l", "."],
            },
        ],
        ignore: &["vendor/"],
        env: &["GOPATH", "GOCACHE", "GOMODCACHE", "GOFLAGS", "GOPROXY"],
    },
    Language {
        key: "python",
        display: "Python",
        markers: &["pyproject.toml", "setup.py", "requirements.txt"],
        sources: &["py"],
        checks: &[Check {
            name: "test",
            argv: &["python3", "-m", "pytest", "-q"],
        }],
        ignore: &[
            ".venv/",
            "venv/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
        ],
        env: &["VIRTUAL_ENV", "PYTHONPATH"],
    },
    Language {
        key: "javascript-typescript",
        display: "JavaScript/TypeScript",
        markers: &["package.json"],
        sources: &["js", "mjs", "cjs", "jsx", "ts", "tsx"],
        checks: &[Check {
            name: "test",
            argv: &["npm", "test", "--silent"],
        }],
        ignore: &["node_modules/", "dist/", ".next/", "coverage/"],
        env: &["NODE_OPTIONS", "npm_config_cache"],
    },
    Language {
        key: "java",
        display: "Java",
        markers: &["pom.xml", "build.gradle", "build.gradle.kts"],
        sources: &["java", "kt"],
        checks: &[Check {
            name: "test",
            argv: &["mvn", "-q", "test"],
        }],
        ignore: &["target/", "build/", ".gradle/"],
        env: &["JAVA_HOME", "MAVEN_OPTS", "GRADLE_USER_HOME"],
    },
    Language {
        key: "c-cpp",
        display: "C/C++",
        markers: &["CMakeLists.txt", "Makefile", "meson.build"],
        sources: &["c", "h", "cc", "cpp", "hpp", "cxx"],
        checks: &[Check {
            name: "build",
            argv: &["make"],
        }],
        ignore: &["build/", "cmake-build-debug/", "cmake-build-release/"],
        env: &["CC", "CXX", "CFLAGS", "CXXFLAGS"],
    },
    Language {
        key: "shell",
        display: "Shell",
        markers: &[],
        sources: &["sh", "bash"],
        checks: &[Check {
            name: "shellcheck",
            argv: &["shellcheck"],
        }],
        ignore: &[],
        env: &[],
    },
    Language {
        key: "hcl",
        display: "HCL",
        markers: &[],
        sources: &["hcl", "tf", "tfvars"],
        checks: &[Check {
            name: "fmt",
            argv: &["terraform", "fmt", "-check", "-recursive"],
        }],
        ignore: &[".terraform/"],
        env: &["TF_CLI_CONFIG_FILE"],
    },
];

pub fn language(key: &str) -> Option<&'static Language> {
    LANGUAGES.iter().find(|language| language.key == key)
}

/// `detect` of the package for `key`: the language, when present.
pub fn detect(key: &str, x: &DetectIn) -> DetectOut {
    DetectOut {
        languages: language(key)
            .filter(|l| l.detected(&x.markers, &x.extensions))
            .map(|l| vec![l.key.to_owned()])
            .unwrap_or_default(),
    }
}

/// `check_plan` of the package for `key`: its checks when asked for its language. Calve adds
/// its base environment (`PATH`, `HOME`, `LANG`, `TMPDIR`) to `env`.
pub fn check_plan(key: &str, x: &CheckPlanIn) -> CheckPlanOut {
    let checks = match language(key) {
        Some(l) if x.languages.iter().any(|k| k == key) => l
            .checks(&x.markers)
            .iter()
            .map(|c| PlannedCheck {
                language: key.into(),
                name: c.name.into(),
                argv: c.argv.iter().map(|a| (*a).into()).collect(),
                takes_files: c.takes_files(),
                env: l.env.iter().map(|e| (*e).into()).collect(),
                sources: l.sources.iter().map(|e| (*e).into()).collect(),
            })
            .collect(),
        _ => vec![],
    };
    CheckPlanOut { checks }
}

/// The judgement shared by every language verifier: all checks passed, any check failed, or
/// the outcome is unknown because a tool was unavailable (never reported as a pass).
pub fn judge(language: &str, evidence: &[Value]) -> (&'static str, Vec<(String, String)>) {
    let mut findings = Vec::new();
    let mut failed = false;
    let mut unavailable = false;
    let mut seen = 0;
    for item in evidence.iter().filter(|item| item["language"] == language) {
        seen += 1;
        let check = item["check"].as_str().unwrap_or("check");
        if item["tool_available"] == false {
            unavailable = true;
            findings.push((
                format!("org.calve.{language}.tool_unavailable"),
                format!(
                    "{check}: {} is not installed",
                    item["argv"][0].as_str().unwrap_or("tool")
                ),
            ));
        } else if item["exit_code"] != 0 {
            failed = true;
            findings.push((
                format!("org.calve.{language}.check_failed"),
                format!("{check} exited with {}", item["exit_code"]),
            ));
        }
    }
    let status = if failed {
        "fail"
    } else if unavailable || seen == 0 {
        "inconclusive"
    } else {
        "pass"
    };
    (status, findings)
}

/// Serves one language as an OpenAEVC extension; each `calve_ext_<lang>` binary calls this.
#[cfg(feature = "native")]
pub fn serve_language(key: &str) -> std::process::ExitCode {
    use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
    use openaevc::extension::wire::{Operation, VerifyOutput, WireError};
    use openaevc::protocol::{
        Entrypoint, ExtensionManifest, Finding, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL,
        VerificationStatus,
    };
    use serde_json::json;

    struct Server(&'static Language);

    impl Extension for Server {
        fn manifest(&self) -> ExtensionManifest {
            ExtensionManifest {
                id: self.0.extension_id(),
                version: env!("CARGO_PKG_VERSION").into(),
                protocol: SUPPORTED_PROTOCOL,
                contract: SUPPORTED_CONTRACT,
                publisher: None,
                artifact_digest: self_artifact_digest(),
                resource_kinds: vec![],
                effect_kinds: vec![],
                verifier_kinds: vec![self.0.verifier()],
                evaluator_kinds: vec![],
                composition_validators: vec![],
                host_capabilities: vec![],
                schemas: Default::default(),
                execution_modes: vec!["subprocess".into()],
                entrypoint: Entrypoint {
                    command: format!("calve_ext_{}", self.0.key.replace('-', "_")),
                    args: vec![],
                },
            }
        }

        fn handle(
            &mut self,
            operation: Operation,
            _: &mut HostContext<'_>,
        ) -> Result<Value, WireError> {
            match operation {
                Operation::Verify {
                    kind,
                    candidate,
                    evidence,
                    ..
                } if kind == self.0.verifier() => {
                    let mut results = Vec::new();
                    for input in evidence.iter().filter(|input| input.kind == CHECK_EVIDENCE) {
                        let value: Value = serde_json::from_slice(&input.data)
                            .map_err(|e| WireError::new("invalid_evidence", e.to_string()))?;
                        // Evidence names the candidate it ran against; a mismatch is not accepted.
                        if value["candidate"] != json!(candidate) {
                            return Err(WireError::new(
                                "invalid_evidence",
                                "check evidence is bound to another candidate",
                            ));
                        }
                        results.push(value);
                    }
                    let (status, findings) = judge(self.0.key, &results);
                    serde_json::to_value(VerifyOutput {
                        status: match status {
                            "pass" => VerificationStatus::Pass,
                            "fail" => VerificationStatus::Fail,
                            _ => VerificationStatus::Inconclusive,
                        },
                        findings: findings
                            .into_iter()
                            .map(|(code, message)| Finding {
                                code,
                                message,
                                resource: None,
                            })
                            .collect(),
                        facts: Default::default(),
                    })
                    .map_err(|e| WireError::new("encode", e.to_string()))
                }
                other => Err(WireError::new(
                    "unsupported",
                    format!("{} is not supported", other.name()),
                )),
            }
        }
    }

    match language(key) {
        Some(language) => serve(Server(language)),
        None => std::process::ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn detection_by_marker_or_source_extension() {
        let x = |m: &[&str], e: &[&str]| DetectIn {
            markers: names(m),
            extensions: names(e),
        };
        assert_eq!(detect("rust", &x(&["Cargo.toml"], &[])).languages, ["rust"]);
        assert_eq!(detect("shell", &x(&[], &["sh"])).languages, ["shell"]);
        assert!(
            detect("go", &x(&["Cargo.toml"], &["rs"]))
                .languages
                .is_empty()
        );
        assert!(detect("cobol", &x(&[], &[])).languages.is_empty());
    }

    #[test]
    fn build_system_special_cases() {
        let plan = |key: &str, m: &[&str]| -> Vec<Vec<String>> {
            check_plan(
                key,
                &CheckPlanIn {
                    languages: vec![key.into()],
                    markers: names(m),
                },
            )
            .checks
            .into_iter()
            .map(|c| c.argv)
            .collect()
        };
        assert_eq!(plan("java", &["pom.xml", "build.gradle"])[0][0], "mvn");
        assert_eq!(plan("java", &["build.gradle.kts"])[0][0], "gradle");
        assert_eq!(
            plan("java", &[])[0][0],
            "mvn",
            "the host asks with no markers"
        );
        assert_eq!(plan("c-cpp", &["CMakeLists.txt"]).len(), 2);
        assert_eq!(plan("c-cpp", &["CMakeLists.txt", "Makefile"]), [["make"]]);
        assert!(
            check_plan(
                "rust",
                &CheckPlanIn {
                    languages: vec!["go".into()],
                    markers: vec![]
                }
            )
            .checks
            .is_empty()
        );
        let shell = check_plan(
            "shell",
            &CheckPlanIn {
                languages: vec!["shell".into()],
                markers: vec![],
            },
        );
        assert!(shell.checks[0].takes_files);
    }

    #[test]
    fn missing_tool_is_never_a_pass() {
        let ok = json!({"language":"rust","check":"test","tool_available":true,"exit_code":0,"argv":["cargo"]});
        let missing = json!({"language":"rust","check":"clippy","tool_available":false,"exit_code":null,"argv":["cargo"]});
        let failed = json!({"language":"rust","check":"fmt","tool_available":true,"exit_code":1,"argv":["cargo"]});
        assert_eq!(judge("rust", std::slice::from_ref(&ok)).0, "pass");
        assert_eq!(
            judge("rust", &[ok.clone(), missing.clone()]).0,
            "inconclusive"
        );
        assert_eq!(judge("rust", &[ok, missing, failed]).0, "fail");
        assert_eq!(judge("rust", &[]).0, "inconclusive");
    }
}
