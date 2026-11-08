//! Best-effort Sigma-to-YARA conversion.
//!
//! Sigma describes log events while YARA scans bytes, so conversion cannot be generally
//! exact. This module converts safe scalar/list detection values, preserves basic boolean
//! selection semantics where possible, and reports every approximation that needs review.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

use crate::Error;

pub const MAX_PATTERNS: usize = 500;
pub const MAX_PATTERN_LENGTH: usize = 10_000;
pub const MAX_RULE_NAME_LENGTH: usize = 128;

const YARA_RESERVED: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "condition",
    "contains",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "import",
    "in",
    "include",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "wide",
    "xor",
];
const UNREPRESENTABLE_MODIFIERS: &[&str] =
    &["cidr", "exists", "fieldref", "gt", "gte", "lt", "lte"];
const KNOWN_MODIFIERS: &[&str] = &[
    "all",
    "ascii",
    "base64",
    "base64offset",
    "base64wide",
    "cased",
    "contains",
    "endswith",
    "expand",
    "iendswith",
    "re",
    "startswith",
    "utf16",
    "utf16be",
    "utf16le",
    "wide",
    "windash",
];
const APPROXIMATE_MODIFIERS: &[&str] = &[
    "base64",
    "base64offset",
    "base64wide",
    "expand",
    "utf16be",
    "windash",
];

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}
re!(NON_IDENT_RE, r"[^A-Za-z0-9_]");
re!(UNDERSCORES_RE, r"_+");
re!(QUANTIFIED_RE, r"(?i)^(all|any|\d+)\s+of\s+(them|\S+)$");
re!(
    UNSUPPORTED_REGEX_RE,
    r"\(\?[=!<]|\(\?P|\\[1-9]|\(\?\(|\*\+|\+\+|\?\+"
);

#[derive(Debug, Clone, Copy)]
pub struct ReverseOptions {
    pub max_patterns: usize,
    pub max_pattern_length: usize,
    pub include_comments: bool,
}

impl Default for ReverseOptions {
    fn default() -> Self {
        Self {
            max_patterns: MAX_PATTERNS,
            max_pattern_length: MAX_PATTERN_LENGTH,
            include_comments: true,
        }
    }
}

struct Pattern {
    identifier: String,
    value: String,
    regex: bool,
    modifiers: Vec<&'static str>,
}

fn warn(report: &mut Vec<String>, message: String) {
    let warning = format!("WARNING: {message}");
    if !report.contains(&warning) {
        report.push(warning);
    }
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

/// Python `str()` of a YAML scalar.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => match n.as_f64() {
            // shortcut: Python repr only for whole floats, upgrade if exponent forms ever matter
            Some(f) if n.is_f64() && f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 => {
                format!("{f:.1}")
            }
            _ => n.to_string(),
        },
        Value::Null => "None".into(),
        other => serde_yaml_ng::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn sanitize_identifier(value: &str, max_length: usize) -> String {
    let text = NON_IDENT_RE.replace_all(value, "_");
    let text = UNDERSCORES_RE.replace_all(&text, "_");
    let mut text = text.trim_matches('_').to_string();
    if text.is_empty() {
        text = "unnamed".into();
    }
    if text.starts_with(|c: char| c.is_ascii_digit()) {
        text.insert(0, '_');
    }
    text.truncate(max_length);
    if YARA_RESERVED.contains(&text.to_lowercase().as_str()) {
        text = if max_length > 5 {
            format!("{}_rule", truncate(&text, max_length - 5))
        } else {
            "_rule".into()
        };
    }
    text
}

/// Escape text as printable ASCII plus UTF-8 byte escapes.
fn escape_yara_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x09 => out.push_str("\\t"),
            0x0A => out.push_str("\\n"),
            0x0D => out.push_str("\\r"),
            0x20..=0x7E => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

fn escape_comment(value: &str) -> String {
    value.replace("*/", "* /").replace(['\r', '\n'], " ")
}

/// Python 3.7+ `re.escape` for one character.
fn py_re_escape(c: char, out: &mut String) {
    if "()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c".contains(c) {
        out.push('\\');
    }
    out.push(c);
}

/// A YARA regex for a Sigma wildcard string, or None if literal.
fn wildcard_regex(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut result = String::new();
    let mut wildcard = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() && matches!(chars[i + 1], '*' | '?') {
            py_re_escape(chars[i + 1], &mut result);
            i += 2;
            continue;
        }
        match c {
            '*' => {
                result.push_str(".*");
                wildcard = true;
            }
            '?' => {
                result.push('.');
                wildcard = true;
            }
            _ => py_re_escape(c, &mut result),
        }
        i += 1;
    }
    wildcard.then_some(result)
}

fn prepare_regex(value: &str, report: &mut Vec<String>, source: &str) -> Option<String> {
    if UNSUPPORTED_REGEX_RE.is_match(value) {
        warn(
            report,
            format!("regex from '{source}' uses syntax unsupported by YARA and was skipped"),
        );
        return None;
    }
    // shortcut: validated with the regex crate's dialect, not Python's; upgrade if a valid
    // Python regex is ever reported as invalid
    if let Err(exc) = Regex::new(value) {
        let exc = exc.to_string().replace('\n', " ");
        warn(
            report,
            format!("invalid regex from '{source}' was skipped ({exc})"),
        );
        return None;
    }
    let mut output = String::with_capacity(value.len());
    let mut escaped = false;
    for c in value.chars() {
        if c == '\r' || c == '\n' {
            output.push_str(&format!("\\x{:02x}", c as u32));
            escaped = false;
        } else if c == '/' && !escaped {
            output.push_str("\\/");
            escaped = false;
        } else if c as u32 > 0x7E {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                output.push_str(&format!("\\x{byte:02x}"));
            }
            escaped = false;
        } else {
            output.push(c);
            escaped = if c == '\\' { !escaped } else { false };
        }
    }
    Some(output)
}

struct Builder {
    max_patterns: usize,
    max_pattern_length: usize,
    report: Vec<String>,
    patterns: Vec<Pattern>,
    selection_ids: Vec<(String, String)>,
    used_ids: Vec<String>,
    limit_reached: bool,
}

impl Builder {
    fn selection_id(&mut self, name: &str) -> String {
        if let Some((_, id)) = self.selection_ids.iter().find(|(n, _)| n == name) {
            return id.clone();
        }
        let base = sanitize_identifier(name, 32);
        let mut candidate = base.clone();
        let mut suffix = 2;
        while self.used_ids.contains(&candidate.to_lowercase()) {
            let trailer = format!("_{suffix}");
            candidate = format!("{}{trailer}", truncate(&base, 32 - trailer.len()));
            suffix += 1;
        }
        self.selection_ids
            .push((name.to_string(), candidate.clone()));
        self.used_ids.push(candidate.to_lowercase());
        candidate
    }

    fn add(
        &mut self,
        selection: &str,
        field: &str,
        modifiers: &[String],
        value: &Value,
    ) -> Option<String> {
        let source = if field.is_empty() {
            selection.to_string()
        } else {
            format!("{selection}.{field}")
        };
        if value.is_null() {
            warn(
                &mut self.report,
                format!("null value in '{source}' cannot become a YARA pattern and was skipped"),
            );
            return None;
        }
        if !is_scalar(value) {
            warn(
                &mut self.report,
                format!("non-scalar value in '{source}' was skipped"),
            );
            return None;
        }
        if self.limit_reached {
            return None;
        }
        if self.patterns.len() >= self.max_patterns {
            self.limit_reached = true;
            warn(
                &mut self.report,
                format!(
                    "pattern limit ({}) reached; remaining values were skipped",
                    self.max_patterns
                ),
            );
            return None;
        }

        let text = scalar_text(value);
        if text.is_empty() {
            warn(
                &mut self.report,
                format!("empty value in '{source}' was skipped"),
            );
            return None;
        }
        if text.len() > self.max_pattern_length {
            let limit = self.max_pattern_length;
            warn(
                &mut self.report,
                format!("pattern from '{source}' exceeds {limit} UTF-8 bytes and was skipped"),
            );
            return None;
        }
        if !matches!(value, Value::String(_)) {
            warn(
                &mut self.report,
                format!("non-string scalar from '{source}' was converted to text"),
            );
        }

        let has = |m: &str| modifiers.iter().any(|x| x == m);
        let mut blocked: Vec<&str> = UNREPRESENTABLE_MODIFIERS
            .iter()
            .copied()
            .filter(|m| has(m))
            .collect();
        if !blocked.is_empty() {
            blocked.sort_unstable();
            let list = blocked.join(", ");
            warn(&mut self.report, format!("modifier(s) {list} on '{source}' cannot be represented and the value was skipped"));
            return None;
        }
        let mut unknown: Vec<&str> = modifiers
            .iter()
            .map(String::as_str)
            .filter(|m| !KNOWN_MODIFIERS.contains(m))
            .collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            unknown.dedup();
            warn(
                &mut self.report,
                format!(
                    "modifier(s) {} on '{source}' were ignored",
                    unknown.join(", ")
                ),
            );
        }
        let mut approximate: Vec<&str> = APPROXIMATE_MODIFIERS
            .iter()
            .copied()
            .filter(|m| has(m))
            .collect();
        approximate.sort_unstable();
        for modifier in approximate {
            warn(
                &mut self.report,
                format!("modifier '{modifier}' on '{source}' is only approximated"),
            );
        }

        let (pattern_value, regex) = if has("re") {
            (prepare_regex(&text, &mut self.report, &source)?, true)
        } else if let Some(wildcard) = wildcard_regex(&text) {
            let prepared = prepare_regex(&wildcard, &mut self.report, &source)?;
            warn(
                &mut self.report,
                format!("Sigma wildcards from '{source}' were converted to a YARA regex"),
            );
            (prepared, true)
        } else {
            (text, false)
        };

        let mut yara_modifiers = Vec::new();
        if !has("cased") {
            yara_modifiers.push("nocase");
        }
        if has("utf16") || has("utf16le") || has("wide") || has("utf16be") {
            yara_modifiers.push("wide");
        } else {
            yara_modifiers.extend(["ascii", "wide"]);
        }

        let selection_id = self.selection_id(selection);
        let identifier = format!("$s_{selection_id}_{}", self.patterns.len() + 1);
        self.patterns.push(Pattern {
            identifier: identifier.clone(),
            value: pattern_value,
            regex,
            modifiers: yara_modifiers,
        });
        Some(identifier)
    }
}

fn modifier_parts(field: &str) -> (String, Vec<String>) {
    let mut parts = field.split('|');
    let name = parts.next().unwrap_or_default().to_string();
    let mut modifiers: Vec<String> = parts
        .filter(|p| !p.is_empty())
        .map(str::to_lowercase)
        .collect();
    modifiers.sort();
    modifiers.dedup();
    (name, modifiers)
}

fn join(expressions: Vec<String>, operator: &str) -> Option<String> {
    let mut values: Vec<String> = expressions.into_iter().filter(|v| !v.is_empty()).collect();
    match values.len() {
        0 => None,
        1 => values.pop(),
        _ => Some(format!("({})", values.join(&format!(" {operator} ")))),
    }
}

fn mapping_expression(
    selection_name: &str,
    mapping: &Mapping,
    builder: &mut Builder,
) -> Option<String> {
    let mut field_expressions = Vec::new();
    for (raw_field, raw_value) in mapping {
        let Some(raw_field) = raw_field.as_str() else {
            warn(
                &mut builder.report,
                format!("non-string field key in selection '{selection_name}' was skipped"),
            );
            continue;
        };
        let (field, modifiers) = modifier_parts(raw_field);
        let single = [raw_value.clone()];
        let values: &[Value] = match raw_value {
            Value::Sequence(items) => items,
            _ => &single,
        };
        let mut identifiers = Vec::new();
        for value in values {
            if matches!(value, Value::Mapping(_) | Value::Sequence(_)) {
                let msg = format!("nested value in '{selection_name}.{field}' was skipped instead of being stringified");
                warn(&mut builder.report, msg);
                continue;
            }
            if let Some(identifier) = builder.add(selection_name, &field, &modifiers, value) {
                identifiers.push(identifier);
            }
        }
        let operator = if modifiers.iter().any(|m| m == "all") {
            "and"
        } else {
            "or"
        };
        if let Some(expression) = join(identifiers, operator) {
            field_expressions.push(expression);
        }
    }
    // Fields in a Sigma selection mapping are ANDed.
    join(field_expressions, "and")
}

fn selection_expression(name: &str, value: &Value, builder: &mut Builder) -> Option<String> {
    match value {
        Value::Mapping(mapping) => mapping_expression(name, mapping, builder),
        Value::Sequence(items) => {
            let mut alternatives = Vec::new();
            for item in items {
                match item {
                    Value::Mapping(mapping) => {
                        if let Some(expression) = mapping_expression(name, mapping, builder) {
                            alternatives.push(expression);
                        }
                    }
                    Value::Sequence(_) => warn(
                        &mut builder.report,
                        format!("nested list in selection '{name}' was skipped"),
                    ),
                    other => {
                        if let Some(identifier) = builder.add(name, "", &[], other) {
                            alternatives.push(identifier);
                        }
                    }
                }
            }
            join(alternatives, "or")
        }
        other => builder.add(name, "", &[], other),
    }
}

fn selection_matches<'a>(pattern: &str, names: &'a [(String, String)]) -> Vec<&'a str> {
    let regex = Regex::new(&format!(
        "^{}$",
        regex::escape(pattern).replace("\\*", ".*")
    ))
    .ok();
    names
        .iter()
        .filter(|(name, _)| regex.as_ref().is_some_and(|r| r.is_match(name)))
        .map(|(n, _)| n.as_str())
        .collect()
}

fn quantified_condition(
    condition: &str,
    expressions: &[(String, String)],
    report: &mut Vec<String>,
) -> Option<String> {
    let caps = QUANTIFIED_RE.captures(condition.trim())?;
    let (quantity, target) = (&caps[1], &caps[2]);
    let selected: Vec<&str> = if target.eq_ignore_ascii_case("them") {
        expressions.iter().map(|(n, _)| n.as_str()).collect()
    } else {
        selection_matches(target, expressions)
    };
    if selected.is_empty() {
        warn(
            report,
            format!("condition target '{target}' matched no usable selection"),
        );
        return Some("false".into());
    }
    let lookup = |name: &str| {
        expressions
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.clone())
            .unwrap_or_default()
    };
    let values: Vec<String> = selected.iter().map(|n| lookup(n)).collect();
    if quantity.eq_ignore_ascii_case("all") {
        return join(values, "and");
    }
    if quantity.eq_ignore_ascii_case("any") || quantity == "1" {
        return join(values, "or");
    }
    let requested: usize = quantity.parse().unwrap_or(usize::MAX);
    if requested > values.len() {
        let msg = format!("'{quantity} of {target}' exceeds the number of usable selections and was converted to false");
        warn(report, msg);
        return Some("false".into());
    }
    if requested == values.len() {
        return join(values, "and");
    }
    let msg = format!(
        "'{quantity} of {target}' cannot be exactly applied to compound selections; using any matching selection"
    );
    warn(report, msg);
    join(values, "or")
}

/// Tokens: parentheses and maximal runs of non-space, non-parenthesis characters.
fn tokenize(condition: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for c in condition.chars() {
        if c.is_whitespace() || c == '(' || c == ')' {
            if !word.is_empty() {
                tokens.push(std::mem::take(&mut word));
            }
            if c == '(' || c == ')' {
                tokens.push(c.to_string());
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        tokens.push(word);
    }
    tokens
}

struct ConditionParser<'a> {
    tokens: &'a [String],
    position: usize,
    expressions: &'a [(String, String)],
    /// Warnings from quantified terms, merged into the report afterwards.
    warnings: Vec<String>,
}

impl<'a> ConditionParser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.position).map(String::as_str)
    }

    fn parse_primary(&mut self) -> Result<String, String> {
        let Some(token) = self.peek() else {
            return Err("unexpected end".into());
        };
        if token == "(" {
            self.position += 1;
            let value = self.parse_or()?;
            if self.peek() != Some(")") {
                return Err("missing closing parenthesis".into());
            }
            self.position += 1;
            return Ok(value);
        }
        if token.eq_ignore_ascii_case("not") {
            return Err("negation is not safely representable".into());
        }
        // `1 of sel*`, `all of them`, ... as a term inside a boolean expression.
        let quantity = token.eq_ignore_ascii_case("all")
            || token.eq_ignore_ascii_case("any")
            || token.chars().all(|c| c.is_ascii_digit());
        if quantity
            && self
                .tokens
                .get(self.position + 1)
                .is_some_and(|t| t.eq_ignore_ascii_case("of"))
        {
            let Some(target) = self.tokens.get(self.position + 2) else {
                return Err("unexpected end".into());
            };
            let phrase = format!("{token} of {target}");
            self.position += 3;
            return quantified_condition(&phrase, self.expressions, &mut self.warnings)
                .ok_or_else(|| format!("unusable quantifier '{phrase}'"));
        }
        self.position += 1;
        self.expressions
            .iter()
            .find(|(n, _)| n == token)
            .map(|(_, e)| e.clone())
            .ok_or_else(|| format!("unknown or unusable selection '{token}'"))
    }

    fn parse_and(&mut self) -> Result<String, String> {
        let mut values = vec![self.parse_primary()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("and")) {
            self.position += 1;
            values.push(self.parse_primary()?);
        }
        Ok(join(values, "and").unwrap_or_else(|| "false".into()))
    }

    fn parse_or(&mut self) -> Result<String, String> {
        let mut values = vec![self.parse_and()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("or")) {
            self.position += 1;
            values.push(self.parse_and()?);
        }
        Ok(join(values, "or").unwrap_or_else(|| "false".into()))
    }
}

fn boolean_condition(
    condition: &str,
    expressions: &[(String, String)],
    report: &mut Vec<String>,
) -> Option<String> {
    let tokens = tokenize(condition);
    if tokens.iter().all(|t| t == "(" || t == ")") {
        return None;
    }
    let mut parser = ConditionParser {
        tokens: &tokens,
        position: 0,
        expressions,
        warnings: Vec::new(),
    };
    let result = parser.parse_or().and_then(|result| {
        if parser.position != tokens.len() {
            return Err(format!("unexpected token '{}'", tokens[parser.position]));
        }
        Ok(result)
    });
    for warning in parser.warnings {
        if !report.contains(&warning) {
            report.push(warning);
        }
    }
    match result {
        Ok(result) => Some(result),
        Err(exc) => {
            warn(
                report,
                format!("condition '{condition}' was not preserved ({exc})"),
            );
            None
        }
    }
}

fn condition_expression(
    raw_condition: Option<&Value>,
    expressions: &[(String, String)],
    report: &mut Vec<String>,
) -> String {
    if expressions.is_empty() {
        return "false".into();
    }
    let single = [raw_condition.cloned().unwrap_or(Value::Null)];
    let conditions: &[Value] = match raw_condition {
        Some(Value::Sequence(items)) => items,
        _ => &single,
    };
    let mut converted = Vec::new();
    for raw in conditions {
        let Some(raw) = raw.as_str().filter(|s| !s.trim().is_empty()) else {
            warn(
                report,
                "missing or non-string condition; using any usable selection".into(),
            );
            continue;
        };
        let expression = quantified_condition(raw, expressions, report)
            .or_else(|| boolean_condition(raw, expressions, report));
        if let Some(expression) = expression {
            converted.push(expression);
        }
    }
    if !converted.is_empty() {
        if converted.len() > 1 {
            warn(
                report,
                "multiple Sigma conditions were combined with OR".into(),
            );
        }
        return join(converted, "or").unwrap_or_else(|| "false".into());
    }
    warn(
        report,
        "condition was approximated as any usable selection".into(),
    );
    join(expressions.iter().map(|(_, e)| e.clone()).collect(), "or")
        .unwrap_or_else(|| "false".into())
}

fn metadata(rule: &Mapping, report: &mut Vec<String>) -> Vec<(String, String)> {
    let mut output = Vec::new();
    let fields = [
        ("description", "description", 500),
        ("author", "author", 200),
        ("date", "date", 40),
        ("id", "sigma_id", 100),
        ("status", "sigma_status", 40),
        ("level", "sigma_level", 40),
    ];
    for (source, target, limit) in fields {
        let Some(value) = rule.get(source).filter(|v| !v.is_null()) else {
            continue;
        };
        if !is_scalar(value) {
            warn(
                report,
                format!("non-scalar metadata field '{source}' was omitted"),
            );
            continue;
        }
        output.push((target.to_string(), truncate(&scalar_text(value), limit)));
    }
    match rule.get("references") {
        None | Some(Value::Null) => {}
        Some(Value::Sequence(references)) => {
            for (index, reference) in references.iter().take(5).enumerate() {
                if is_scalar(reference) {
                    output.push((
                        format!("reference_{}", index + 1),
                        truncate(&scalar_text(reference), 300),
                    ));
                } else {
                    warn(report, "non-scalar reference was omitted".into());
                }
            }
        }
        Some(other) => {
            if yaml_truthy(other) {
                warn(report, "non-list 'references' metadata was omitted".into());
            }
        }
    }
    output.push((
        "converted_by".into(),
        "yar2sig Sigma-to-YARA reverse converter".into(),
    ));
    output.push((
        "conversion_note".into(),
        "Best-effort conversion; review before deployment".into(),
    ));
    output
}

fn yaml_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Sequence(s) => !s.is_empty(),
        Value::Mapping(m) => !m.is_empty(),
        Value::Tagged(_) => true,
    }
}

/// Convert one Sigma rule mapping into `(YARA source, report)`.
pub fn convert_sigma_to_yara(
    sigma_rule: &Value,
    options: &ReverseOptions,
) -> Result<(String, Vec<String>), Error> {
    let Value::Mapping(rule) = sigma_rule else {
        return Err(Error("Sigma rule must be a mapping".into()));
    };
    if options.max_patterns < 1 {
        return Err(Error("max_patterns must be a positive integer".into()));
    }
    if options.max_pattern_length < 1 {
        return Err(Error(
            "max_pattern_length must be a positive integer".into(),
        ));
    }

    let mut report = Vec::new();
    warn(
        &mut report,
        "Sigma event-field semantics cannot be equivalent to YARA byte matching; analyst review is required".into(),
    );
    let scalar_title = |key: &str| {
        rule.get(key)
            .filter(|v| is_scalar(v))
            .map(scalar_text)
            .filter(|t| !t.trim().is_empty())
    };
    let title = scalar_title("title")
        .or_else(|| scalar_title("id"))
        .unwrap_or_else(|| {
            warn(
                &mut report,
                "rule has no scalar title or id; a fallback identifier was used".into(),
            );
            "UnnamedSigmaRule".into()
        });
    let rule_name = sanitize_identifier(&title, MAX_RULE_NAME_LENGTH);

    let Some(Value::Mapping(detection)) = rule.get("detection") else {
        return Err(Error("Sigma rule 'detection' must be a mapping".into()));
    };

    let mut builder = Builder {
        max_patterns: options.max_patterns,
        max_pattern_length: options.max_pattern_length,
        report,
        patterns: Vec::new(),
        selection_ids: Vec::new(),
        used_ids: Vec::new(),
        limit_reached: false,
    };
    let mut expressions: Vec<(String, String)> = Vec::new();
    for (raw_name, selection) in detection {
        let Some(name) = raw_name.as_str() else {
            warn(
                &mut builder.report,
                "non-string detection selection name was skipped".into(),
            );
            continue;
        };
        if name == "condition" || name == "timeframe" {
            continue;
        }
        match selection_expression(name, selection, &mut builder) {
            Some(expression) => expressions.push((name.to_string(), expression)),
            None => warn(
                &mut builder.report,
                format!("selection '{name}' produced no usable patterns"),
            ),
        }
    }

    let mut report = builder.report;
    let condition = condition_expression(detection.get("condition"), &expressions, &mut report);
    let meta = metadata(rule, &mut report);

    let mut lines: Vec<String> = Vec::new();
    if options.include_comments {
        lines.push("/*".into());
        lines.push(" * Sigma-to-YARA conversion report:".into());
        lines.extend(report.iter().map(|m| format!(" * {}", escape_comment(m))));
        lines.push(" */".into());
        lines.push(String::new());
    }
    lines.push(format!("rule {rule_name}"));
    lines.push("{".into());
    lines.push("    meta:".into());
    for (key, value) in meta {
        lines.push(format!("        {key} = \"{}\"", escape_yara_text(&value)));
    }
    if !builder.patterns.is_empty() {
        lines.push(String::new());
        lines.push("    strings:".into());
        for pattern in &builder.patterns {
            let modifiers = pattern.modifiers.join(" ");
            let declaration = if pattern.regex {
                format!("{} = /{}/ {modifiers}", pattern.identifier, pattern.value)
            } else {
                format!(
                    "{} = \"{}\" {modifiers}",
                    pattern.identifier,
                    escape_yara_text(&pattern.value)
                )
            };
            lines.push(format!("        {}", declaration.trim_end()));
        }
    }
    lines.push(String::new());
    lines.push("    condition:".into());
    lines.push(format!("        {condition}"));
    lines.push("}".into());
    Ok((lines.join("\n") + "\n", report))
}

/// Convert all Sigma mappings in a YAML stream. Empty documents are ignored; invalid YAML or
/// non-mapping documents are errors.
pub fn convert_sigma_text(
    yaml_text: &str,
    options: &ReverseOptions,
) -> Result<Vec<(String, Vec<String>)>, Error> {
    let mut documents = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(yaml_text) {
        documents.push(
            Value::deserialize(document).map_err(|e| Error(format!("Invalid Sigma YAML: {e}")))?,
        );
    }
    let mut results = Vec::new();
    for (index, document) in documents.iter().enumerate() {
        match document {
            Value::Null => continue,
            Value::Mapping(_) => results.push(convert_sigma_to_yara(document, options)?),
            _ => {
                return Err(Error(format!(
                    "Sigma YAML document {} must be a mapping",
                    index + 1
                )))
            }
        }
    }
    if results.is_empty() {
        return Err(Error("Sigma YAML contains no rule documents".into()));
    }
    Ok(results)
}

/// Read and convert all Sigma documents in `path`.
pub fn convert_sigma_file(
    path: &Path,
    options: &ReverseOptions,
) -> Result<Vec<(String, Vec<String>)>, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error(format!(
            "Unable to read Sigma file '{}': {e}",
            path.display()
        ))
    })?;
    convert_sigma_text(&text, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(yaml: &str) -> (String, Vec<String>) {
        convert_sigma_to_yara(
            &serde_yaml_ng::from_str(yaml).unwrap(),
            &ReverseOptions::default(),
        )
        .unwrap()
    }

    fn rule(title: &str, selection: &str, condition: &str) -> String {
        format!("title: {title}\ndetection:\n{selection}\n  condition: {condition}\n")
    }

    #[test]
    fn basic_rule_and_multiple_values() {
        let (yara, report) = convert("title: Suspicious Process\ndescription: Test rule\ndetection:\n  selection:\n    CommandLine: powershell.exe\n  condition: selection\n");
        assert!(yara.contains("rule Suspicious_Process"));
        assert!(yara.contains("description = \"Test rule\""));
        assert!(yara.contains("$s_selection_1 = \"powershell.exe\" nocase ascii wide"));
        assert!(yara.contains("condition:\n        $s_selection_1\n}"));
        assert!(!report.is_empty());

        let (yara, _) = convert(&rule(
            "MultiPattern",
            "  selection:\n    Image: [cmd.exe, powershell.exe]",
            "selection",
        ));
        assert!(
            yara.contains("$s_selection_1 = \"cmd.exe\"")
                && yara.contains("$s_selection_2 = \"powershell.exe\"")
        );
        assert!(yara.contains("($s_selection_1 or $s_selection_2)"));
    }

    #[test]
    fn wildcards_and_regex() {
        let (yara, report) = convert(&rule(
            "WildcardTest",
            "  selection:\n    CommandLine: '*.exe *suspicious*'",
            "selection",
        ));
        assert!(yara.contains("= /.*\\.exe\\ .*suspicious.*/ nocase ascii wide"));
        assert!(report.iter().any(|m| m.to_lowercase().contains("wildcard")));

        let (yara, _) = convert(&rule(
            "RegexTest",
            "  selection:\n    CommandLine|re: 'powershell\\.exe\\s+-enc/x'",
            "selection",
        ));
        assert!(yara.contains("= /powershell\\.exe\\s+-enc\\/x/"));

        let (_, report) = convert(&rule(
            "Bad",
            "  selection:\n    f|re: '(?=a)b'",
            "selection",
        ));
        assert!(report.iter().any(|m| m.contains("unsupported by YARA")));
        let (_, report) = convert(&rule(
            "Bad",
            "  selection:\n    f|re: '(unclosed'",
            "selection",
        ));
        assert!(report.iter().any(|m| m.contains("invalid regex")));
    }

    #[test]
    fn conditions() {
        let two = "  sel1:\n    Image: cmd.exe\n  sel2:\n    CommandLine: -enc";
        let (yara, _) = convert(&rule("AllCondition", two, "all of them"));
        assert!(yara.contains("($s_sel1_1 and $s_sel2_2)"));
        let (yara, _) = convert(&rule("AnyCondition", two, "sel1 or sel2"));
        assert!(yara.contains("($s_sel1_1 or $s_sel2_2)"));
        let (yara, _) = convert(&rule("Pat", two, "1 of sel*"));
        assert!(yara.contains("($s_sel1_1 or $s_sel2_2)"));
        let (yara, report) = convert(&rule("Pat", two, "3 of sel*"));
        assert!(
            yara.contains("        false\n")
                && report.iter().any(|m| m.contains("exceeds the number"))
        );
        let (yara, report) = convert(&rule("Pat", two, "1 of nope*"));
        assert!(
            yara.contains("        false\n")
                && report
                    .iter()
                    .any(|m| m.contains("matched no usable selection"))
        );

        let three = format!("{two}\n  sel3:\n    User: admin");
        let (yara, _) = convert(&rule("Complex", &three, "(sel1 and sel2) or sel3"));
        assert!(yara.contains("(($s_sel1_1 and $s_sel2_2) or $s_sel3_3)"));
        let (_, report) = convert(&rule("Neg", two, "not sel1"));
        assert!(report.iter().any(|m| m.contains("negation")));
        let (yara, report) = convert(&rule("Unknown", two, "sel1 and selX"));
        assert!(report
            .iter()
            .any(|m| m.contains("unknown or unusable selection 'selX'")));
        assert!(yara.contains("($s_sel1_1 or $s_sel2_2)")); // approximated as any usable selection
        let grouped = "  sel1_1:\n    Image: cmd.exe\n  sel1_2:\n    CommandLine: cmd.exe\n  sel2:\n    User: admin";
        let (yara, _) = convert(&rule("Grouped", grouped, "1 of sel1_* or sel2"));
        assert!(yara.contains("(($s_sel1_1_1 or $s_sel1_2_2) or $s_sel2_3)"));
        let (yara, _) = convert(&rule("Grouped", grouped, "all of sel1_* and sel2"));
        assert!(yara.contains("(($s_sel1_1_1 and $s_sel1_2_2) and $s_sel2_3)"));
        let (yara, report) = convert(&rule("Grouped", grouped, "1 of nope_* or sel2"));
        assert!(
            yara.contains("(false or $s_sel2_3)")
                && report
                    .iter()
                    .any(|m| m.contains("matched no usable selection"))
        );
        let (_, report) = convert(&rule("Multi", two, "[sel1, sel2]"));
        assert!(report.iter().any(|m| m.contains("combined with OR")));
        let (_, report) = convert(&rule("Missing", two, "42"));
        assert!(report
            .iter()
            .any(|m| m.contains("missing or non-string condition")));
    }

    #[test]
    fn identifiers_and_escaping() {
        let (yara, _) = convert(&rule("rule", "  sel:\n    CommandLine: test", "sel"));
        assert!(yara.contains("rule rule_rule"));
        assert_eq!(sanitize_identifier("123 abc!!", 128), "_123_abc");
        assert_eq!(sanitize_identifier("", 128), "unnamed");
        assert_eq!(sanitize_identifier("and", 3), "_rule");
        assert_eq!(sanitize_identifier("strings", 3), "str");

        let (yara, _) = convert(&rule(
            "EscapeTest",
            "  selection:\n    CommandLine: \"test\\\"quote\\\\backslash\\n\\r\\t\\u00e9\"",
            "selection",
        ));
        assert!(yara.contains(r#"test\"quote\\backslash\n\r\t\xc3\xa9"#));

        let (yara, _) = convert(
            "title: T\ndetection:\n  a b: {x: 1}\n  a-b: {x: 2}\n  condition: all of them\n",
        );
        assert!(yara.contains("$s_a_b_1") && yara.contains("$s_a_b_2_2"));
    }

    #[test]
    fn values_and_modifiers() {
        let (yara, report) = convert(&rule(
            "NonString",
            "  selection:\n    EventID: 4688\n    Flag: true\n    Ratio: 1.0",
            "selection",
        ));
        assert!(yara.contains("\"4688\"") && yara.contains("\"True\"") && yara.contains("\"1.0\""));
        assert!(report.iter().any(|m| m.contains("non-string scalar")));

        let (_, report) = convert(&rule(
            "Nested",
            "  selection:\n    field: {nested: value}",
            "selection",
        ));
        assert!(report.iter().any(|m| m.contains("nested value")));
        let (yara, report) = convert(&rule(
            "NullTest",
            "  selection:\n    field: null",
            "selection",
        ));
        assert!(
            report.iter().any(|m| m.contains("null value")) && yara.contains("        false\n")
        );
        assert!(report
            .iter()
            .any(|m| m.contains("produced no usable patterns")));

        let (yara, _) = convert(&rule(
            "CaseSensitive",
            "  selection:\n    field|cased: Value",
            "selection",
        ));
        assert!(!yara.contains("nocase"));
        let (yara, _) = convert(&rule(
            "UTF16",
            "  selection:\n    field|utf16: value",
            "selection",
        ));
        assert!(yara.contains("\"value\" nocase wide\n"));
        let (_, report) = convert(&rule(
            "Cidr",
            "  selection:\n    field|cidr: 10.0.0.0/8",
            "selection",
        ));
        assert!(report
            .iter()
            .any(|m| m.contains("cidr") && m.contains("skipped")));
        let (_, report) = convert(&rule(
            "Odd",
            "  selection:\n    field|windash|bogus: a",
            "selection",
        ));
        assert!(report
            .iter()
            .any(|m| m.contains("bogus") && m.contains("ignored")));
        assert!(report
            .iter()
            .any(|m| m.contains("'windash'") && m.contains("approximated")));
        let (yara, _) = convert(&rule("All", "  selection:\n    f|all: [a, b]", "selection"));
        assert!(yara.contains("($s_selection_1 and $s_selection_2)"));
    }

    #[test]
    fn limits() {
        let values: Vec<String> = (0..15).map(|i| format!("value{i}")).collect();
        let sigma = serde_yaml_ng::from_str(&rule(
            "LimitTest",
            &format!("  selection:\n    field: [{}]", values.join(", ")),
            "selection",
        ))
        .unwrap();
        let options = ReverseOptions {
            max_patterns: 10,
            ..Default::default()
        };
        let (yara, report) = convert_sigma_to_yara(&sigma, &options).unwrap();
        let strings = yara
            .split("strings:")
            .nth(1)
            .unwrap()
            .split("condition:")
            .next()
            .unwrap();
        assert_eq!(strings.matches("$s_selection_").count(), 10);
        assert!(report.iter().any(|m| m.contains("limit")));

        let sigma = serde_yaml_ng::from_str(&rule(
            "LengthTest",
            &format!("  selection:\n    field: {}", "A".repeat(200)),
            "selection",
        ))
        .unwrap();
        let options = ReverseOptions {
            max_pattern_length: 100,
            ..Default::default()
        };
        let (_, report) = convert_sigma_to_yara(&sigma, &options).unwrap();
        assert!(report.iter().any(|m| m.contains("exceeds")));

        let sigma =
            serde_yaml_ng::from_str("title: T\ndetection:\n  s: {f: v}\n  condition: s\n").unwrap();
        let err = convert_sigma_to_yara(
            &sigma,
            &ReverseOptions {
                max_patterns: 0,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.0.contains("positive integer"));
        let err = convert_sigma_to_yara(
            &sigma,
            &ReverseOptions {
                max_pattern_length: 0,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.0.contains("positive integer"));
    }

    #[test]
    fn metadata_and_comments() {
        let (yara, _) = convert("title: MetadataTest\nid: 12345678-1234-1234-1234-123456789012\nstatus: experimental\ndescription: Test description\nauthor: Test Author\ndate: 2024/01/01\nlevel: high\nreferences: [https://example.com/ref1, https://example.com/ref2]\ndetection:\n  selection:\n    field: value\n  condition: selection\n");
        for expected in [
            "description = \"Test description\"",
            "author = \"Test Author\"",
            "sigma_id = \"12345678-1234-1234-1234-123456789012\"",
            "sigma_status = \"experimental\"",
            "sigma_level = \"high\"",
            "reference_1 = \"https://example.com/ref1\"",
            "reference_2",
            "date = \"2024/01/01\"",
        ] {
            assert!(yara.contains(expected), "{expected}");
        }
        let (_, report) = convert(
            "title: T\nreferences: nope\nauthor: [x]\ndetection:\n  s: {f: v}\n  condition: s\n",
        );
        assert!(report.iter().any(|m| m.contains("non-list 'references'")));
        assert!(report
            .iter()
            .any(|m| m.contains("non-scalar metadata field 'author'")));

        let sigma = serde_yaml_ng::from_str(&rule(
            "CommentTest",
            "  selection:\n    field: value",
            "selection",
        ))
        .unwrap();
        let (yara, report) = convert_sigma_to_yara(
            &sigma,
            &ReverseOptions {
                include_comments: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!yara.contains("/*") && !yara.contains("*/") && !report.is_empty());
        let (yara, _) = convert(&rule(
            "CommentTest",
            "  selection:\n    field: value",
            "selection",
        ));
        assert!(yara
            .starts_with("/*\n * Sigma-to-YARA conversion report:\n * WARNING: Sigma event-field"));
    }

    #[test]
    fn documents_and_errors() {
        let results = convert_sigma_text("---\ntitle: Rule1\ndetection:\n  selection:\n    field: value1\n  condition: selection\n---\ntitle: Rule2\ndetection:\n  selection:\n    field: value2\n  condition: selection\n", &ReverseOptions::default()).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].0.contains("rule Rule1") && results[0].0.contains("\"value1\""));
        assert!(results[1].0.contains("rule Rule2") && results[1].0.contains("\"value2\""));

        let err = |text: &str| {
            convert_sigma_text(text, &ReverseOptions::default())
                .unwrap_err()
                .0
        };
        assert!(err("{ invalid yaml: [").starts_with("Invalid Sigma YAML"));
        assert!(err("").contains("no rule documents"));
        assert!(err("- 1\n- 2\n").contains("document 1 must be a mapping"));
        let bad = |yaml: &str| {
            convert_sigma_to_yara(
                &serde_yaml_ng::from_str(yaml).unwrap(),
                &ReverseOptions::default(),
            )
            .unwrap_err()
            .0
        };
        assert!(bad("[1, 2, 3]").contains("must be a mapping"));
        assert!(bad("title: NoDetection").contains("detection"));
        let missing = convert_sigma_file(
            Path::new("/nonexistent/does-not-exist.yml"),
            &ReverseOptions::default(),
        )
        .unwrap_err();
        assert!(missing.0.contains("Unable to read"));

        let (yara, report) = convert("title: ''\nid: 7\ndetection:\n  s: {f: v}\n  condition: s\n");
        assert!(yara.contains("rule _7"));
        let (yara, report2) = convert("title: ''\ndetection:\n  s: {f: v}\n  condition: s\n");
        assert!(
            yara.contains("rule UnnamedSigmaRule")
                && report2.iter().any(|m| m.contains("fallback identifier"))
        );
        assert!(!report.iter().any(|m| m.contains("fallback identifier")));
    }
}
