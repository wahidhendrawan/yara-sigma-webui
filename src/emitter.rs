//! Sigma rule emitter: a parsed YARA rule plus a mapping pipeline -> a Sigma rule
//! (`serde_json::Value` with keys in emission order, ready for YAML) and a conversion report.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::ioc::classify_pattern;
use crate::parser::ParsedRule;
use crate::{py_str, truthy, Error};

static MITRE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bT\d{4}(?:\.\d{3})?\b").unwrap());
static ATTACK_TECHNIQUE_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^attack\.t\d{4}(?:\.\d{3})?$").unwrap());
static COMPLEX_CONDITION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b\d+\s+of\b|\$[A-Za-z0-9_]*\*|for\s+any|for\s+all").unwrap()
});
/// Key order of templates/sigma.yml in github.com/wahidhendrawan/Detection-Rules.
pub const DETECTION_RULES_ORDER: &[&str] = &[
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "references",
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "tags",
];
const REVIEW_MODIFIERS: &[&str] = &["wide", "xor", "base64", "base64wide", "fullword"];

fn default_fields(mapping: &Value, ioc_type: &str) -> Vec<String> {
    let logsource = |key: &str| {
        mapping
            .get("logsource")
            .and_then(|l| l.get(key))
            .map(py_str)
            .unwrap_or_default()
    };
    let fallback = || {
        vec![mapping
            .get("fallback_field")
            .map_or_else(|| "message".to_string(), py_str)]
    };
    match ioc_type {
        "user_agent" if logsource("category") == "proxy" => {
            vec!["c-useragent".into(), "UserAgent".into()]
        }
        "user_agent" => vec!["CommandLine".into()],
        "named_pipe" if logsource("product") == "windows" && logsource("service") == "sysmon" => {
            vec!["PipeName".into(), "CommandLine".into()]
        }
        _ => fallback(),
    }
}

fn select_fields(mapping: &Value, ioc_type: &str) -> (Vec<String>, String) {
    if let Some(Value::Object(spec)) = mapping.get("mappings").and_then(|m| m.get(ioc_type)) {
        if let Some(fields) = spec.get("fields").filter(|f| truthy(f)) {
            let fields = match fields {
                Value::Array(items) => items.iter().map(py_str).collect(),
                other => vec![py_str(other)],
            };
            return (
                fields,
                spec.get("op")
                    .map_or_else(|| "contains".to_string(), py_str),
            );
        }
    }
    (default_fields(mapping, ioc_type), "contains".to_string())
}

fn mitre_tags(meta: &Map<String, Value>) -> Vec<String> {
    let blob = meta.values().map(py_str).collect::<Vec<_>>().join(" ");
    let mut tags: Vec<String> = Vec::new();
    for technique in MITRE_RE.find_iter(&blob) {
        let tag = format!("attack.{}", technique.as_str().to_lowercase());
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags
}

fn selection_key(field: &str, op: &str, ptype: &str) -> String {
    match (ptype, op) {
        ("regex", _) => format!("{field}|re"),
        (_, "contains" | "startswith" | "endswith") => format!("{field}|{op}"),
        _ => field.to_string(),
    }
}

fn add_warning(warnings: &mut Vec<String>, report: &mut Vec<String>, message: String) {
    if !warnings.contains(&message) {
        warnings.push(message.clone());
    }
    report.push(message);
}

fn py_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|i| format!("'{i}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Return `(sigma_rule, report)`.
pub fn emit_sigma(parsed: &ParsedRule, mapping: &Value) -> (Value, Vec<String>) {
    let mut report: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut detection = Map::new();
    let mut condition_groups: Vec<String> = Vec::new();

    for (idx, entry) in parsed.strings.iter().enumerate() {
        let pattern = &entry.value;
        let ioc_type = match entry.kind.as_str() {
            "hex" => {
                let msg = format!(
                    "Hex pattern #{} needs manual review; Sigma cannot match raw bytes directly.",
                    idx + 1
                );
                add_warning(&mut warnings, &mut report, msg);
                "hash"
            }
            "regex" => {
                let msg = format!(
                    "Regex pattern '{pattern}' mapped with |re modifier; backend support may vary."
                );
                add_warning(&mut warnings, &mut report, msg);
                "generic"
            }
            _ => classify_pattern(pattern),
        };

        let mut review_mods: Vec<&str> = entry
            .modifiers
            .iter()
            .map(String::as_str)
            .filter(|m| REVIEW_MODIFIERS.contains(m))
            .collect();
        review_mods.sort_unstable();
        review_mods.dedup();
        if !review_mods.is_empty() {
            let msg = format!(
                "Modifiers {} on pattern '{pattern}' require analyst validation.",
                review_mods.join(", ")
            );
            add_warning(&mut warnings, &mut report, msg);
        }

        let (fields, op) = select_fields(mapping, ioc_type);
        let mut group_names: Vec<String> = Vec::new();
        for (field_idx, field) in fields.iter().enumerate() {
            let sel_name = if fields.len() > 1 {
                format!("sel{}_{}", idx + 1, field_idx + 1)
            } else {
                format!("sel{}", idx + 1)
            };
            detection.insert(
                sel_name.clone(),
                json!({ selection_key(field, &op, &entry.kind): pattern }),
            );
            group_names.push(sel_name);
        }
        // `1 of selN_*` instead of `(selN_1 or selN_2)`: pySigma 0.11 crashes on parenthesised groups.
        match group_names.len() {
            0 => {}
            1 => condition_groups.push(group_names.remove(0)),
            _ => condition_groups.push(format!("1 of sel{}_*", idx + 1)),
        }
        report.push(format!(
            "Pattern '{pattern}' -> {ioc_type} -> fields {} (op: {op}).",
            py_list(&fields)
        ));
    }

    if condition_groups.is_empty() {
        add_warning(
            &mut warnings,
            &mut report,
            "No usable patterns extracted; review the source rule.".into(),
        );
        detection.insert("condition".into(), "selection".into());
    } else {
        let joiner = if parsed.cond_type == "all" {
            " and "
        } else {
            " or "
        };
        detection.insert("condition".into(), condition_groups.join(joiner).into());
    }

    if COMPLEX_CONDITION_RE.is_match(&parsed.condition_raw) {
        let msg = format!(
            "Complex YARA condition preserved only approximately: {}",
            parsed.condition_raw
        );
        add_warning(&mut warnings, &mut report, msg);
    }

    // Quality score.
    let mut score: i64 = 100;
    if parsed.strings.is_empty() {
        score -= 70;
    }
    let complex_patterns = parsed
        .strings
        .iter()
        .filter(|s| s.kind == "hex" || s.kind == "regex")
        .count() as i64;
    score -= (complex_patterns * 15).min(40);
    score -= (warnings.len() as i64 * 5).min(25);
    if COMPLEX_CONDITION_RE.is_match(&parsed.condition_raw) {
        score -= 20;
    }
    let score = score.clamp(0, 100);
    let label = if score >= 80 {
        "high"
    } else if score >= 55 {
        "medium"
    } else {
        "low"
    };
    let review_required = score < 80 || !warnings.is_empty();
    report.push(format!("Conversion confidence: {label} ({score}/100)."));

    let meta = &parsed.meta;
    let first_truthy = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| meta.get(*k).filter(|v| truthy(v)).cloned())
    };
    let mut tags = mitre_tags(meta);
    tags.extend(parsed.tags.iter().map(|t| format!("yara.{t}")));
    let references: Vec<Value> = ["reference", "ref", "url"]
        .iter()
        .filter_map(|k| meta.get(*k).filter(|v| truthy(v)).cloned())
        .collect();

    let rule = json!({
        "title": first_truthy(&["title", "description"]).unwrap_or_else(|| parsed.name.clone().into()),
        "id": uuid::Uuid::new_v4().to_string(),
        "status": "experimental",
        "description": first_truthy(&["description"]).unwrap_or_else(|| format!("Converted from YARA rule {}", parsed.name).into()),
        "author": meta.get("author").cloned().unwrap_or_else(|| "yar2sig".into()),
        "date": meta.get("date").cloned().unwrap_or_else(|| chrono::Local::now().format("%Y/%m/%d").to_string().into()),
        "references": references,
        "tags": tags,
        "logsource": mapping.get("logsource").cloned().unwrap_or_else(|| json!({"category": "process_creation", "product": "windows"})),
        "detection": detection,
        "falsepositives": ["Unknown - review generated rule before deployment."],
        "level": meta.get("level").cloned().unwrap_or_else(|| "medium".into()),
        "x_yar2sig": {
            "source_rule": parsed.name,
            "confidence": label,
            "confidence_score": score,
            "review_required": review_required,
            "warnings": warnings,
        },
    });
    (rule, report)
}

/// Reshape an emitted rule into the Detection-Rules repository layout: template key order,
/// `modified` and `fields` added, the `x_yar2sig` block dropped, and at least one
/// `attack.tNNNN` tag (from the rule or `techniques`), which that repository's lint requires.
pub fn to_detection_rules(rule: &Value, techniques: &[String]) -> Result<Value, Error> {
    let mut tags: Vec<String> = rule
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(py_str).collect())
        .unwrap_or_default();
    for technique in techniques {
        let tag = format!("attack.{}", technique.trim().to_lowercase());
        if !ATTACK_TECHNIQUE_TAG_RE.is_match(&tag) {
            return Err(Error(format!(
                "not a MITRE ATT&CK technique ID: '{technique}' (expected e.g. T1059 or T1059.001)"
            )));
        }
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    if !tags.iter().any(|t| ATTACK_TECHNIQUE_TAG_RE.is_match(t)) {
        return Err(Error("no MITRE ATT&CK technique tag; put the technique ID in the YARA meta or pass --attack T1059".into()));
    }

    let mut fields: Vec<String> = Vec::new();
    if let Some(Value::Object(detection)) = rule.get("detection") {
        for selection in detection.values() {
            if let Value::Object(selection) = selection {
                for key in selection.keys() {
                    let field = key.split('|').next().unwrap_or_default().to_string();
                    if !fields.contains(&field) {
                        fields.push(field);
                    }
                }
            }
        }
    }

    let mut out = rule.as_object().cloned().unwrap_or_default();
    out.insert(
        "modified".into(),
        out.get("date").cloned().unwrap_or(Value::Null),
    );
    out.insert("fields".into(), fields.into());
    out.insert("tags".into(), tags.into());
    out.remove("x_yar2sig");
    let ordered: Map<String, Value> = DETECTION_RULES_ORDER
        .iter()
        .filter_map(|k| out.get(*k).map(|v| (k.to_string(), v.clone())))
        .collect();
    Ok(Value::Object(ordered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{convert, load_mapping};

    const BASIC: &str = r#"
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

    #[test]
    fn convert_and_tags() {
        let (rule, report) = convert(BASIC, "sysmon").unwrap();
        assert_eq!(rule["title"], "test desc");
        assert!(rule["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("attack.t1059.003")));
        assert!(rule["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("yara.malware")));
        assert!(truthy(&rule["detection"]["condition"]));
        assert!(
            ["high", "medium", "low"].contains(&rule["x_yar2sig"]["confidence"].as_str().unwrap())
        );
        assert!(report.len() >= 4);
        assert_eq!(
            rule["detection"]["sel3"],
            json!({"DestinationIp": "10.0.0.5"})
        );
        assert_eq!(rule["author"], "tester");
        assert_eq!(rule["level"], "medium");
        assert_eq!(rule["references"], json!(["T1059.003"]));
        let keys: Vec<&String> = rule.as_object().unwrap().keys().collect();
        assert_eq!(keys[0], "title");
        assert_eq!(keys[keys.len() - 1], "x_yar2sig");
    }

    #[test]
    fn uses_all_mapped_fields() {
        let (rule, _) = convert("rule UrlRule {\n strings:\n  $url = \"http://evil.example.com/path\"\n condition:\n  $url\n}", "sysmon").unwrap();
        assert_eq!(rule["detection"]["condition"], "1 of sel1_*");
        assert!(rule["detection"]["sel1_1"].get("Image|contains").is_some());
        assert!(rule["detection"]["sel1_2"]
            .get("CommandLine|contains")
            .is_some());
    }

    #[test]
    fn complex_condition_lowers_confidence() {
        let (rule, report) = convert(
            "rule Complex {\n strings:\n  $a1 = \"rundll32.exe\"\n  $a2 = \"regsvr32.exe\"\n  $b = /powershell\\s+-enc/\n condition:\n  1 of ($a*) and $b\n}",
            "sysmon",
        )
        .unwrap();
        assert_eq!(rule["x_yar2sig"]["review_required"], true);
        assert!(report.iter().any(|l| l.contains("Complex YARA condition")));
        assert_eq!(
            rule["detection"]["sel3"],
            json!({"CommandLine|re": "powershell\\s+-enc"})
        );
    }

    #[test]
    fn empty_rule_and_hex_and_review_modifiers() {
        let (rule, report) = convert("rule Empty { condition: true }", "sysmon").unwrap();
        assert_eq!(rule["detection"]["condition"], "selection");
        assert_eq!(rule["x_yar2sig"]["confidence"], "low");
        assert!(report.iter().any(|l| l.contains("No usable patterns")));
        assert_eq!(rule["title"], "Empty");
        assert_eq!(rule["description"], "Converted from YARA rule Empty");

        let (rule, report) =
            convert("rule H {\n strings:\n  $h = { 4D 5A }\n  $w = \"abc\" wide xor\n condition: all of them\n}", "winsec").unwrap();
        assert!(report.iter().any(|l| l.contains("Hex pattern #1")));
        assert!(report
            .iter()
            .any(|l| l.contains("Modifiers wide, xor on pattern 'abc'")));
        assert_eq!(rule["detection"]["condition"], "sel1 and sel2");
        assert_eq!(
            rule["logsource"],
            load_mapping("winsec").unwrap()["logsource"]
        );
    }

    #[test]
    fn default_fields_depend_on_pipeline() {
        let (rule, _) = convert(
            "rule P { strings: $p = \"\\\\\\\\.\\\\pipe\\\\x\" condition: $p }",
            "sysmon",
        )
        .unwrap();
        assert_eq!(rule["detection"]["condition"], "1 of sel1_*");
        assert!(rule["detection"]["sel1_1"]
            .get("PipeName|contains")
            .is_some());
        let (rule, _) = convert(
            "rule U { strings: $u = \"Mozilla/5.0\" condition: $u }",
            "proxy",
        )
        .unwrap();
        assert!(rule["detection"]["sel1_1"]
            .get("c-useragent|contains")
            .is_some());
        let (rule, _) = convert(
            "rule U { strings: $u = \"Mozilla/5.0\" condition: $u }",
            "linux",
        )
        .unwrap();
        assert!(rule["detection"]["sel1"]
            .get("CommandLine|contains")
            .is_some());
    }

    const WITH_TECHNIQUE: &str = r#"
rule Dropper : malware {
  meta:
    description = "drops a payload"
    reference = "https://attack.mitre.org/techniques/T1059/003/ T1059.003"
  strings:
    $a = "cmd.exe /c"
    $url = "http://evil.example.com/x"
  condition:
    all of them
}
"#;

    #[test]
    fn detection_rules_layout() {
        let (rule, _) = convert(WITH_TECHNIQUE, "sysmon").unwrap();
        let out = to_detection_rules(&rule, &[]).unwrap();
        let keys: Vec<&str> = out
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: Vec<&str> = DETECTION_RULES_ORDER
            .iter()
            .copied()
            .filter(|k| out.get(*k).is_some())
            .collect();
        assert_eq!(keys, expected);
        assert_eq!(out["modified"], out["date"]);
        assert!(out.get("x_yar2sig").is_none());
        let fields = out["fields"].as_array().unwrap();
        assert!(
            fields.contains(&json!("CommandLine"))
                && fields.iter().all(|f| !f.as_str().unwrap().contains('|'))
        );
        let tags = out["tags"].as_array().unwrap();
        assert!(tags.contains(&json!("attack.t1059.003")) && tags.contains(&json!("yara.malware")));
        assert!(rule.get("x_yar2sig").is_some()); // input untouched

        let no_technique = WITH_TECHNIQUE.replace(
            "reference = \"https://attack.mitre.org/techniques/T1059/003/ T1059.003\"",
            "author = \"x\"",
        );
        let (rule, _) = convert(&no_technique, "sysmon").unwrap();
        assert!(to_detection_rules(&rule, &[])
            .unwrap_err()
            .0
            .contains("no MITRE ATT&CK technique"));
        let out = to_detection_rules(
            &rule,
            &["T1059".into(), " t1059.001 ".into(), "T1059".into()],
        )
        .unwrap();
        let tags = out["tags"].as_array().unwrap();
        assert_eq!(
            &tags[tags.len() - 2..],
            &[json!("attack.t1059"), json!("attack.t1059.001")]
        );
        assert!(to_detection_rules(&rule, &["1059".into()])
            .unwrap_err()
            .0
            .contains("not a MITRE ATT&CK technique"));
    }
}
