//! Deterministic resource ignore rules (`.calveignore`), independent of Git. Pure: the host
//! passes the text of each applicable ignore file; nothing here touches the filesystem.
//!
//! Grammar: one pattern per line; `#` comments; `!` negates; a leading `/` anchors to the file's
//! directory; a trailing `/` limits a rule to directories (and everything below); `*` and `?`
//! stay within a path segment; `**` crosses separators (`**/` also matches zero levels); `\`
//! escapes the next character. Evaluated in order, the last matching rule wins. A file applies to
//! paths below its own directory.

const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 512;
const MAX_PATTERN_CHARS: usize = 512;

/// Ignored everywhere (software defaults).
pub const DEFAULTS: &[&str] = &[".git", "target", "node_modules", ".venv"];

#[derive(Clone, Copy, Debug)]
enum Token {
    Literal(char),
    One,
    Star,
    GlobStar,
    GlobStarDir,
}

#[derive(Debug, Clone)]
pub struct Rule {
    tokens: Vec<Token>,
    pub text: String,
    /// `software default`, `language default`, or the ignore file's path.
    pub source: String,
    pub line: Option<usize>,
    /// Directory the rule is relative to (`""` = root).
    base: String,
    anchored: bool,
    directory: bool,
    pub ignored: bool,
}

#[derive(Debug, Clone, Default)]
pub struct IgnoreRules {
    rules: Vec<Rule>,
}

fn parse_tokens(pattern: &str) -> Result<Vec<Token>, String> {
    let mut chars = pattern.chars().peekable();
    let mut out = Vec::new();
    while let Some(ch) = chars.next() {
        out.push(match ch {
            '\\' => Token::Literal(chars.next().ok_or("trailing escape")?),
            '?' => Token::One,
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    Token::GlobStarDir
                } else {
                    Token::GlobStar
                }
            }
            '*' => Token::Star,
            _ => Token::Literal(ch),
        });
    }
    Ok(out)
}

fn parse_rule(raw: &str, line: usize, source: &str, base: &str) -> Result<Option<Rule>, String> {
    let raw = raw.trim_end_matches('\r');
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(None);
    }
    let (ignored, text) = match raw.strip_prefix('!') {
        Some(rest) => (false, rest),
        None => (true, raw),
    };
    let anchored = text.starts_with('/');
    let text = text.strip_prefix('/').unwrap_or(text);
    let directory = text.ends_with('/') && !text.ends_with("\\/");
    let text = if directory {
        &text[..text.len() - 1]
    } else {
        text
    };
    if text.is_empty() || text.chars().count() > MAX_PATTERN_CHARS {
        return Err(format!("{source}: invalid pattern on line {line}"));
    }
    Ok(Some(Rule {
        tokens: parse_tokens(text).map_err(|e| format!("{source}:{line}: {e}"))?,
        text: raw.into(),
        source: source.into(),
        line: Some(line),
        base: base.into(),
        anchored,
        directory,
        ignored,
    }))
}

fn matches_tokens(tokens: &[Token], path: &str) -> bool {
    let chars: Vec<char> = path.chars().collect();
    let mut states = vec![false; chars.len() + 1];
    states[0] = true;
    for token in tokens {
        let mut next = vec![false; chars.len() + 1];
        match token {
            Token::Literal(expected) => {
                for i in 0..chars.len() {
                    if states[i] && chars[i] == *expected {
                        next[i + 1] = true;
                    }
                }
            }
            Token::One => {
                for i in 0..chars.len() {
                    if states[i] && chars[i] != '/' {
                        next[i + 1] = true;
                    }
                }
            }
            Token::Star | Token::GlobStar => {
                next.clone_from(&states);
                for i in 0..chars.len() {
                    if next[i] && (matches!(token, Token::GlobStar) || chars[i] != '/') {
                        next[i + 1] = true;
                    }
                }
            }
            Token::GlobStarDir => {
                next.clone_from(&states);
                let mut reachable = false;
                for i in 0..chars.len() {
                    reachable |= states[i];
                    if reachable && chars[i] == '/' {
                        next[i + 1] = true;
                    }
                }
            }
        }
        states = next;
    }
    states[chars.len()]
}

impl Rule {
    fn matches(&self, path: &str, is_dir: bool) -> bool {
        let rel = if self.base.is_empty() {
            path
        } else {
            match path
                .strip_prefix(&self.base)
                .and_then(|r| r.strip_prefix('/'))
            {
                Some(r) => r,
                None => return false,
            }
        };
        let mut candidates = vec![(rel, is_dir)];
        for (index, byte) in rel.bytes().enumerate() {
            if byte == b'/' {
                candidates.push((&rel[..index], true));
            }
        }
        candidates.into_iter().any(|(candidate, directory)| {
            if self.directory && !directory {
                return false;
            }
            if matches_tokens(&self.tokens, candidate) {
                return true;
            }
            !self.anchored
                && candidate
                    .match_indices('/')
                    .any(|(index, _)| matches_tokens(&self.tokens, &candidate[index + 1..]))
        })
    }
}

/// A decision: whether `path` is ignored and the rule that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub ignored: bool,
    /// `software default: target/`, `language default: dist/`, or `<source>:<line>`.
    pub rule: Option<String>,
}

impl IgnoreRules {
    /// Defaults (always) + language defaults for languages whose root markers are present +
    /// every ignore file (`path → text`, applied relative to its directory, outer first).
    pub fn new(
        markers: &[String],
        sources: &std::collections::BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let mut rules = Vec::new();
        let default = |name: &str, source: &str| Rule {
            tokens: parse_tokens(name).expect("plain name"),
            text: format!("{name}/"),
            source: source.into(),
            line: None,
            base: String::new(),
            anchored: false,
            directory: true,
            ignored: true,
        };
        for name in DEFAULTS {
            rules.push(default(name, "software default"));
        }
        for language in crate::language::LANGUAGES
            .iter()
            .filter(|l| l.markers.iter().any(|m| markers.iter().any(|x| x == m)))
        {
            for pattern in language.ignore {
                if rules.iter().all(|r: &Rule| r.text != *pattern) {
                    rules.push(default(pattern.trim_end_matches('/'), "language default"));
                }
            }
        }
        let mut ordered: Vec<(&String, &String)> = sources.iter().collect();
        ordered.sort_by_key(|(p, _)| p.matches('/').count());
        for (path, text) in ordered {
            let base = path.rsplit_once('/').map_or("", |(d, _)| d);
            rules.extend(Self::parse_source(text, path, base)?.rules);
        }
        Ok(IgnoreRules { rules })
    }

    /// Parses one ignore file alone.
    pub fn parse_source(text: &str, source: &str, base: &str) -> Result<Self, String> {
        if text.len() > MAX_FILE_BYTES {
            return Err(format!("{source} exceeds 64 KiB"));
        }
        let mut rules = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if let Some(rule) = parse_rule(line, index + 1, source, base)? {
                rules.push(rule);
            }
            if rules.len() > MAX_RULES {
                return Err(format!("{source} exceeds 512 rules"));
            }
        }
        Ok(IgnoreRules { rules })
    }

    pub fn decide(&self, path: &str, is_dir: bool) -> Decision {
        match self.rules.iter().rfind(|rule| rule.matches(path, is_dir)) {
            Some(r) => Decision {
                ignored: r.ignored,
                rule: Some(match r.line {
                    Some(line) => format!("{}:{line}", r.source),
                    None => format!("{}: {}", r.source, r.text),
                }),
            },
            None => Decision {
                ignored: false,
                rule: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn rules(text: &str) -> IgnoreRules {
        IgnoreRules::new(
            &[],
            &BTreeMap::from([(".calveignore".to_owned(), text.to_owned())]),
        )
        .unwrap()
    }

    #[test]
    fn negation_directories_root_escapes_and_globstars() {
        let r = rules("*.log\n!keep.log\nbuild/\n/root.txt\n\\#literal\nsrc/**/generated?.rs\n");
        assert!(r.decide("nested/debug.log", false).ignored);
        assert!(!r.decide("nested/keep.log", false).ignored);
        assert!(r.decide("a/build/file.rs", false).ignored);
        assert!(r.decide("root.txt", false).ignored);
        assert!(!r.decide("a/root.txt", false).ignored);
        assert!(r.decide("#literal", false).ignored);
        assert!(r.decide("src/generated1.rs", false).ignored);
        assert!(r.decide("src/a/b/generated2.rs", false).ignored);
        assert_eq!(
            r.decide("x.log", false).rule.as_deref(),
            Some(".calveignore:1")
        );
    }

    #[test]
    fn defaults_language_defaults_and_nested_sources() {
        let none = IgnoreRules::new(&[], &BTreeMap::new()).unwrap();
        assert!(none.decide("target/x", false).ignored);
        assert!(
            !none.decide("dist/app.js", false).ignored,
            "dist/ only with package.json"
        );
        let js = IgnoreRules::new(&["package.json".into()], &BTreeMap::new()).unwrap();
        assert_eq!(
            js.decide("dist/app.js", false).rule.as_deref(),
            Some("language default: dist/")
        );
        let nested = IgnoreRules::new(
            &[],
            &BTreeMap::from([("src/.calveignore".to_owned(), "*.tmp\n".to_owned())]),
        )
        .unwrap();
        assert!(nested.decide("src/a.tmp", false).ignored);
        assert!(
            !nested.decide("a.tmp", false).ignored,
            "a file applies below its directory only"
        );
        assert!(
            !rules("!target/\n").decide("target/x", false).ignored,
            "a file can override a default"
        );
    }

    #[test]
    fn invalid_input_is_refused() {
        assert!(IgnoreRules::parse_source("\\", "x", "").is_err());
        assert!(IgnoreRules::parse_source(&"a\n".repeat(600), "x", "").is_err());
    }

    proptest::proptest! {
        /// §48.2: the last matching rule wins whatever comes before it: a later negation of any
        /// rule undoes it for that path.
        #[test]
        fn the_last_matching_rule_wins(
            name in "[a-z]{1,6}(/[a-z]{1,6}){0,2}",
            noise in proptest::collection::vec("[a-z*]{1,6}", 0..4),
        ) {
            let leading = noise.join("\n");
            let decide = |text: String| {
                super::IgnoreRules::parse_source(&text, ".calveignore", "")
                    .unwrap()
                    .decide(&name, false)
                    .ignored
            };
            let (ignored, kept) = (
                format!("{leading}\n/{name}\n"),
                format!("{leading}\n/{name}\n!/{name}\n"),
            );
            proptest::prop_assert!(decide(ignored));
            proptest::prop_assert!(!decide(kept));
        }
    }
}
