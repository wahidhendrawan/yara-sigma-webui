//! YARA rule parser: rule name, tags, meta fields, string declarations with modifiers, and a
//! best-effort condition expression. Supports multiple rules per file.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::Error;

pub const DEFAULT_MAX_PATTERNS: usize = 500;
pub const DEFAULT_MAX_PATTERN_LENGTH: usize = 10_000;

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}

// Header prefixes stay on one line and tags stop at ':'/braces so every scan is bounded;
// spanning newlines made these quadratic on hostile 1 MB input.
macro_rules! header {
    () => {
        r"(?m)^[^\S\n]*(?:(?:private|global)[^\S\n]+)*rule\s+"
    };
}
re!(
    RULE_RE,
    concat!(header!(), r"[A-Za-z0-9_]+\s*(?::[^{}:]*)?\{")
);
re!(
    NAME_RE,
    concat!(header!(), r"([A-Za-z0-9_]+)\s*(?::\s*([^{}:]*))?\{")
);
re!(STRING_DECL_RE, r"^(\$[A-Za-z0-9_]+)\s*=\s*(.+)"); // input is pre-stripped
re!(HEX_RE, r"^\{([0-9a-fA-F\s?\[\]\-()|]+)\}\s*(.*)$");
re!(REGEX_RE, r"^/(.+)/([a-z]*)\s*(.*)$");
re!(TEXT_RE, r#"^"((?:[^"\\]|\\.)*)"\s*(.*)$"#);
re!(HEX_ESCAPE_RE, r"\\x([0-9a-fA-F]{2})");
re!(
    MODIFIER_RE,
    r"(?i)\b(?:ascii|wide|nocase|fullword|xor|base64|base64wide|private)\b"
);
re!(INT_RE, r"^-?\d+$");
re!(WS_RE, r"\s+");
re!(ALL_OF_RE, r"(?i)\ball\s+of\b");
re!(META_HEADER, r"(?i)\bmeta\s*:\s*");
re!(STRINGS_HEADER, r"(?i)\bstrings\s*:\s*");
re!(CONDITION_HEADER, r"(?i)\bcondition\s*:\s*");
re!(LOOSE_CONDITION_HEADER, r"(?i)condition\s*:\s*");
re!(STOP_STRINGS_CONDITION, r"(?i)\b(?:strings|condition)\s*:");
re!(STOP_CONDITION, r"(?i)\bcondition\s*:");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringEntry {
    pub id: String,
    pub value: String,
    /// `text`, `regex` or `hex`.
    pub kind: String,
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRule {
    pub name: String,
    pub meta: Map<String, Value>,
    pub strings: Vec<StringEntry>,
    /// `all` or `any`.
    pub cond_type: String,
    pub tags: Vec<String>,
    pub condition_raw: String,
}

impl ParsedRule {
    pub fn values(&self) -> Vec<String> {
        self.strings.iter().map(|s| s.value.clone()).collect()
    }
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Strip comments while preserving comment-like text inside strings. Byte-wise: every
/// delimiter is ASCII, so removed ranges always end on character boundaries.
fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let (mut i, mut in_quote, mut escaped) = (0, false, false);
    while i < bytes.len() {
        let ch = bytes[i];
        let nxt = bytes.get(i + 1).copied();
        if in_quote {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == b'\\' {
                escaped = true;
            } else if ch == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        if ch == b'"' {
            in_quote = true;
            out.push(ch);
            i += 1;
            continue;
        }
        if ch == b'/' && nxt == Some(b'*') {
            i = find(bytes, b"*/", i + 2).map_or(bytes.len(), |end| end + 2);
            continue;
        }
        if ch == b'/' && nxt == Some(b'/') {
            let Some(end) = find(bytes, b"\n", i + 2) else {
                break;
            };
            out.push(b'\n');
            i = end + 1;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn find_matching_brace(bytes: &[u8], brace_start: usize) -> Option<usize> {
    let (mut depth, mut in_quote, mut escaped, mut in_regex) = (0i64, false, false, false);
    let mut i = brace_start;
    while i < bytes.len() {
        let ch = bytes[i];
        let prev = if i > 0 { Some(bytes[i - 1]) } else { None };
        if in_quote {
            if escaped {
                escaped = false;
            } else if ch == b'\\' {
                escaped = true;
            } else if ch == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        if in_regex {
            if escaped {
                escaped = false;
            } else if ch == b'\\' {
                escaped = true;
            } else if ch == b'/' {
                in_regex = false;
            }
            i += 1;
            continue;
        }
        if ch == b'"' {
            in_quote = true;
        } else if ch == b'/' && prev.is_none_or(|p| matches!(p, b'=' | b' ' | b'\t')) {
            in_regex = true;
        } else if ch == b'{' {
            depth += 1;
        } else if ch == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Split a multi-rule YARA file into individual rule blocks.
pub fn split_rules(text: &str) -> Vec<String> {
    let text = strip_comments(text);
    let mut blocks = Vec::new();
    let mut pos = 0;
    while let Some(m) = RULE_RE.find_at(&text, pos) {
        // unterminated: the scan already hit EOF, rescanning per header is quadratic
        let Some(end) = find_matching_brace(text.as_bytes(), m.end() - 1) else {
            break;
        };
        blocks.push(text[m.start()..=end].to_string());
        pos = end + 1;
    }
    if blocks.is_empty() && !text.trim().is_empty() {
        blocks.push(text);
    }
    blocks
}

/// Text after `name:` up to the next stop section or the rule's closing brace. Forward scans only.
fn section<'a>(text: &'a str, header: &Regex, stop: Option<&Regex>) -> &'a str {
    let Some(h) = header.find(text) else {
        return "";
    };
    let start = h.end();
    if let Some(s) = stop.and_then(|stop| stop.find_at(text, start)) {
        return &text[start..s.start()];
    }
    let trimmed = text.trim_end();
    if trimmed.len() > start && trimmed.ends_with('}') {
        &text[start..trimmed.len() - 1]
    } else {
        ""
    }
}

fn decode_text(value: &str) -> String {
    let mut out = HEX_ESCAPE_RE
        .replace_all(value, |caps: &regex::Captures| {
            u32::from_str_radix(&caps[1], 16)
                .ok()
                .and_then(char::from_u32)
                .map_or_else(|| caps[0].to_string(), String::from)
        })
        .into_owned();
    for (src, dst) in [
        (r"\\", "\\"),
        (r#"\""#, "\""),
        (r"\n", "\n"),
        (r"\r", "\r"),
        (r"\t", "\t"),
    ] {
        out = out.replace(src, dst);
    }
    out
}

fn parse_modifiers(text: &str) -> Vec<String> {
    MODIFIER_RE
        .find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .collect()
}

fn parse_meta(meta_text: &str) -> Map<String, Value> {
    let mut meta = Map::new();
    for line in meta_text.lines() {
        let Some((key, raw)) = line.trim().split_once('=') else {
            continue;
        };
        let raw = raw.trim();
        let value = if raw.eq_ignore_ascii_case("true") {
            Value::Bool(true)
        } else if raw.eq_ignore_ascii_case("false") {
            Value::Bool(false)
        } else if INT_RE.is_match(raw) {
            // shortcut: integers beyond i64 stay strings, upgrade if a YARA meta ever needs them
            raw.parse::<i64>()
                .map_or_else(|_| Value::String(raw.to_string()), Value::from)
        } else {
            Value::String(raw.trim_matches(|c| c == '"' || c == '\'').to_string())
        };
        meta.insert(key.trim().to_string(), value);
    }
    meta
}

fn parse_strings(
    strings_text: &str,
    max_patterns: usize,
    max_pattern_length: usize,
) -> Result<Vec<StringEntry>, Error> {
    let mut declarations = Vec::new();
    for line in strings_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(m) = STRING_DECL_RE.captures(line) else {
            continue;
        };
        if declarations.len() >= max_patterns {
            return Err(Error(format!(
                "Rule exceeds maximum pattern count ({max_patterns})"
            )));
        }
        let (ident, raw_value) = (&m[1], &m[2]);
        // Avoid decoding or normalizing an already overlong declaration.
        if raw_value.chars().count() > max_pattern_length + 256 {
            return Err(Error(format!(
                "Pattern {ident} exceeds maximum length ({max_pattern_length} chars)"
            )));
        }
        let (kind, value, modifiers) = if let Some(t) = TEXT_RE.captures(raw_value) {
            ("text", decode_text(&t[1]), parse_modifiers(&t[2]))
        } else if let Some(r) = REGEX_RE.captures(raw_value) {
            let mut mods = parse_modifiers(&format!("{} {}", &r[2], &r[3]));
            mods.sort();
            mods.dedup();
            ("regex", r[1].to_string(), mods)
        } else if let Some(h) = HEX_RE.captures(raw_value) {
            (
                "hex",
                WS_RE.replace_all(h[1].trim(), " ").into_owned(),
                parse_modifiers(&h[2]),
            )
        } else {
            continue;
        };
        if value.chars().count() > max_pattern_length {
            return Err(Error(format!(
                "Pattern {ident} exceeds maximum length ({max_pattern_length} chars)"
            )));
        }
        declarations.push(StringEntry {
            id: ident.to_string(),
            value,
            kind: kind.to_string(),
            modifiers,
        });
    }
    Ok(declarations)
}

/// Parse the first YARA rule found in `text`; errors when a complexity bound is exceeded.
pub fn parse_yara_rule(
    text: &str,
    max_patterns: usize,
    max_pattern_length: usize,
) -> Result<ParsedRule, Error> {
    let text = strip_comments(text);
    let text = split_rules(&text).into_iter().next().unwrap_or(text);

    let (name, tags) = match NAME_RE.captures(&text) {
        Some(c) => (
            c[1].to_string(),
            c.get(2)
                .map(|t| t.as_str().split_whitespace().map(String::from).collect())
                .unwrap_or_default(),
        ),
        None => ("ConvertedRule".to_string(), Vec::new()),
    };

    let meta = parse_meta(section(&text, &META_HEADER, Some(&STOP_STRINGS_CONDITION)));
    if max_patterns < 1 || max_pattern_length < 1 {
        return Err(Error("Pattern limits must be positive".into()));
    }
    let strings = parse_strings(
        section(&text, &STRINGS_HEADER, Some(&STOP_CONDITION)),
        max_patterns,
        max_pattern_length,
    )?;

    let mut condition_raw = section(&text, &CONDITION_HEADER, None).trim().to_string();
    if condition_raw.is_empty() {
        // Unterminated rule: everything after the header, minus a trailing '}'.
        if let Some(h) = LOOSE_CONDITION_HEADER.find(&text) {
            let rest = &text[h.end()..];
            let trimmed = rest.trim_end();
            let body = trimmed.strip_suffix('}').unwrap_or(rest);
            condition_raw = body.trim().to_string();
        }
    }
    let cond_type = if ALL_OF_RE.is_match(&condition_raw) {
        "all"
    } else {
        "any"
    };

    Ok(ParsedRule {
        name,
        meta,
        strings,
        cond_type: cond_type.to_string(),
        tags,
        condition_raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    pub const BASIC: &str = r#"
rule TestRule : malware {
  meta:
    author = "tester"
    description = "test desc"
    reference = "T1059.003"
  strings:
    $a = "cmd.exe /c"
    $url = "http://evil.example.com/x"
    $ip = "10.0.0.5"
    $h = "44d88612fea8a8f36de82e1278abb02f"
  condition:
    any of them
}
"#;

    fn parse(text: &str) -> ParsedRule {
        parse_yara_rule(text, DEFAULT_MAX_PATTERNS, DEFAULT_MAX_PATTERN_LENGTH).unwrap()
    }

    #[test]
    fn parse_basic() {
        let parsed = parse(BASIC);
        assert_eq!(parsed.name, "TestRule");
        assert_eq!(parsed.meta["author"], "tester");
        assert!(parsed.tags.contains(&"malware".to_string()));
        assert_eq!(parsed.strings.len(), 4);
        assert_eq!(parsed.cond_type, "any");
    }

    #[test]
    fn modifiers_escapes_and_meta_types() {
        let parsed = parse(
            r#"
rule Modded {
  meta:
    enabled = true
    score = 42
    note = 'single'
  strings:
    $a = "powershell\x20-enc" wide nocase
    $b = /cmd\.exe\s+\/c/i
    $c = { 4D 5A   90 } ascii
  condition:
    $a and $b
}
"#,
        );
        assert_eq!(parsed.strings[0].value, "powershell -enc");
        assert_eq!(parsed.strings[0].modifiers, ["wide", "nocase"]);
        assert_eq!(parsed.strings[1].kind, "regex");
        assert_eq!(parsed.strings[1].value, r"cmd\.exe\s+\/c");
        assert_eq!(parsed.strings[2].kind, "hex");
        assert_eq!(parsed.strings[2].value, "4D 5A 90");
        assert_eq!(parsed.strings[2].modifiers, ["ascii"]);
        assert_eq!(parsed.condition_raw, "$a and $b");
        assert_eq!(parsed.meta["enabled"], true);
        assert_eq!(parsed.meta["score"], 42);
        assert_eq!(parsed.meta["note"], "single");
    }

    #[test]
    fn split_multi() {
        let text =
            format!("{BASIC}\nrule Second {{\n strings:\n  $a=\"x\"\n condition:\n  $a\n}}\n");
        assert_eq!(split_rules(&text).len(), 2);
    }

    #[test]
    fn limits() {
        let lines: Vec<String> = (0..60).map(|i| format!("    $s{i} = \"v{i}\"")).collect();
        let rule = format!(
            "rule Big {{\n  strings:\n{}\n  condition:\n    any of them\n}}",
            lines.join("\n")
        );
        assert!(parse_yara_rule(&rule, 50, DEFAULT_MAX_PATTERN_LENGTH)
            .unwrap_err()
            .0
            .contains("pattern count"));
        let rule = format!(
            "rule Long {{\n  strings:\n    $a = \"{}\"\n  condition:\n    $a\n}}",
            "A".repeat(200)
        );
        assert!(parse_yara_rule(&rule, DEFAULT_MAX_PATTERNS, 100)
            .unwrap_err()
            .0
            .contains("maximum length"));
        assert!(parse_yara_rule(BASIC, 0, 10)
            .unwrap_err()
            .0
            .contains("must be positive"));
        assert_eq!(parse(BASIC).strings.len(), 4);
    }

    #[test]
    fn linear_on_adversarial_1mb_input() {
        let cases = [
            format!("rule a {{\n{}", "meta: ".repeat(160_000)),
            format!("rule a {{\n{}", "condition: ".repeat(90_000)),
            format!("x{}y", "\n".repeat(1_000_000)),
            "rule a {\n".repeat(110_000),
            "rule a : t\n".repeat(90_000),
            format!(
                "rule a {{\n strings:\n $a = \"{}",
                "strings: ".repeat(110_000)
            ),
            format!(
                "rule a {{\n strings:\n $a = x{}y\n condition: any of them\n}}",
                " ".repeat(1_000_000)
            ),
        ];
        for case in cases {
            let started = Instant::now();
            let _ = parse_yara_rule(&case, DEFAULT_MAX_PATTERNS, DEFAULT_MAX_PATTERN_LENGTH);
            assert!(started.elapsed() < Duration::from_secs(10));
        }
    }

    #[test]
    fn braces_inside_strings_hex_and_regex() {
        let text = r#"
rule Braces {
  strings:
    $s = "}{ not a brace"
    $h = { 4D 5A [2-4] 90 }
    $r = /a{2,3}\}/
  condition:
    any of them
}
rule Next { condition: true }
"#;
        assert_eq!(split_rules(text).len(), 2);
        let parsed = parse(text);
        assert_eq!(parsed.name, "Braces");
        assert_eq!(
            parsed.values(),
            ["}{ not a brace", "4D 5A [2-4] 90", r"a{2,3}\}"]
        );
        assert_eq!(parsed.condition_raw, "any of them");
    }

    #[test]
    fn tolerates_unterminated_string_and_malformed_input() {
        let parsed = parse("rule Broken {\n strings:\n  $a = \"abc\n condition:\n  any of them\n}");
        assert_eq!(parsed.name, "Broken");
        assert!(parsed.strings.is_empty());
        assert_eq!(parsed.condition_raw, "any of them");

        let parsed = parse("rule Open {\n strings:\n  $a = \"x\"\n condition:\n  $a");
        assert_eq!(parsed.values(), ["x"]);
        assert_eq!(parsed.condition_raw, "$a");

        assert_eq!(parse("not a yara rule").name, "ConvertedRule");
        assert_eq!(parse("rule C { condition: all of them }").cond_type, "all");
    }

    #[test]
    fn comments_are_stripped_but_not_inside_strings() {
        let parsed = parse("rule C { // comment\n strings:\n /* block */ $a = \"http://x/y\" // trailing\n condition: $a }");
        assert_eq!(parsed.values(), ["http://x/y"]);
    }
}
