//! yar2sig — YARA <-> Sigma conversion library.
//!
//! YARA -> Sigma: [`parser::parse_yara_rule`], [`emitter::emit_sigma`], [`convert`],
//! [`convert_all`], [`backends::generate_query`]. Sigma -> YARA (best-effort):
//! [`sig2yar::convert_sigma_to_yara`], [`sig2yar::convert_sigma_text`],
//! [`sig2yar::convert_sigma_file`]. Mapping pipelines are embedded from `mappings/`.

pub mod backends;
pub mod cli;
pub mod emitter;
pub mod ioc;
pub mod parser;
pub mod progress;
pub mod sig2yar;
pub mod web;

use std::fmt;
use std::sync::LazyLock;

use serde_json::Value;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

include!(concat!(env!("OUT_DIR"), "/pipelines.rs"));

/// Invalid input or a bound violation (the Python ValueError / SigmaConversionError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

static MAPPINGS: LazyLock<Vec<(&'static str, Value)>> = LazyLock::new(|| {
    PIPELINES
        .iter()
        .map(|(name, text)| {
            let mapping = serde_yaml_ng::from_str(text)
                .unwrap_or_else(|e| panic!("mappings/{name}.yaml: {e}"));
            (
                *name,
                if mapping == Value::Null {
                    Value::Object(Default::default())
                } else {
                    mapping
                },
            )
        })
        .collect()
});

/// Sorted names of the embedded mapping pipelines.
pub fn available_pipelines() -> Vec<&'static str> {
    MAPPINGS.iter().map(|(name, _)| *name).collect()
}

pub fn load_mapping(name: &str) -> Result<Value, Error> {
    MAPPINGS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, mapping)| mapping.clone())
        .ok_or_else(|| {
            Error(format!(
                "Pipeline not found. Available: {:?}",
                available_pipelines()
            ))
        })
}

/// Parse the FIRST YARA rule in `text` and emit a Sigma rule via `pipeline`.
pub fn convert(text: &str, pipeline: &str) -> Result<(Value, Vec<String>), Error> {
    let parsed = parser::parse_yara_rule(
        text,
        parser::DEFAULT_MAX_PATTERNS,
        parser::DEFAULT_MAX_PATTERN_LENGTH,
    )?;
    Ok(emitter::emit_sigma(&parsed, &load_mapping(pipeline)?))
}

/// Convert EVERY YARA rule in `text`; one `(sigma_rule, report)` per rule.
pub fn convert_all(text: &str, pipeline: &str) -> Result<Vec<(Value, Vec<String>)>, Error> {
    let mapping = load_mapping(pipeline)?;
    parser::split_rules(text)
        .iter()
        .map(|block| {
            let parsed = parser::parse_yara_rule(
                block,
                parser::DEFAULT_MAX_PATTERNS,
                parser::DEFAULT_MAX_PATTERN_LENGTH,
            )?;
            Ok(emitter::emit_sigma(&parsed, &mapping))
        })
        .collect()
}

/// Python `str(value)` for the JSON scalars that reach text output.
pub(crate) fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

/// Python truthiness.
pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelines_exist_and_untrusted_names_are_rejected() {
        let pipelines = available_pipelines();
        for expected in ["sysmon", "winsec", "linux", "proxy"] {
            assert!(pipelines.contains(&expected));
            assert!(load_mapping(expected).unwrap().get("mappings").is_some());
        }
        for bad in ["../sysmon", "sysmon/../../etc/passwd", "/etc/passwd", ""] {
            assert!(load_mapping(bad)
                .unwrap_err()
                .0
                .starts_with("Pipeline not found"));
        }
    }
}
