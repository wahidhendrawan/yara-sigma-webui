//! End-to-end tests of the `yar2sig` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

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
const SECOND: &str = "\nrule Second { strings: $a = \"x\" condition: $a }\n";
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

fn no_technique() -> String {
    WITH_TECHNIQUE.replace(
        "reference = \"https://attack.mitre.org/techniques/T1059/003/ T1059.003\"",
        "author = \"x\"",
    )
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("yar2sig-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_env(args: &[&str], path: Option<&Path>) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_yar2sig"));
    cmd.args(args);
    if let Some(path) = path {
        cmd.env("PATH", path);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run(args: &[&str]) -> (i32, String, String) {
    run_env(args, None)
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn yaml(text: &str) -> Value {
    serde_yaml_ng::from_str(text).unwrap()
}

fn files(dir: &Path, ext: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(ext))
        .collect();
    names.sort();
    names
}

/// The checks of Detection-Rules' `detection_rules lint`.
fn assert_lint_clean(rule: &Value) {
    for field in [
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "logsource",
        "detection",
        "level",
        "tags",
    ] {
        let value = rule
            .get(field)
            .unwrap_or_else(|| panic!("missing required field: {field}"));
        assert!(!matches!(value, Value::Null), "{field}");
        assert!(
            value.as_str().is_none_or(|s| !s.is_empty())
                && value.as_array().is_none_or(|a| !a.is_empty()),
            "{field}"
        );
    }
    let id = rule["id"].as_str().unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(id).unwrap().to_string(),
        id.to_lowercase()
    );
    assert!([
        "stable",
        "test",
        "experimental",
        "deprecated",
        "unsupported"
    ]
    .contains(&rule["status"].as_str().unwrap()));
    assert!(["informational", "low", "medium", "high", "critical"]
        .contains(&rule["level"].as_str().unwrap()));
    for field in ["title", "description", "author", "date"] {
        assert!(rule[field].is_string(), "{field}");
    }
    let tags = rule["tags"].as_array().unwrap();
    assert!(tags
        .iter()
        .all(|t| t.as_str().is_some_and(|t| !t.trim().is_empty())));
    let technique = regex::Regex::new(r"(?i)^attack\.t\d{4}(?:\.\d{3})?$").unwrap();
    assert!(tags.iter().any(|t| technique.is_match(t.as_str().unwrap())));
    assert!(rule["logsource"].is_object() && rule["detection"].is_object());
    assert!(rule["detection"]["condition"]
        .as_str()
        .is_some_and(|c| !c.is_empty()));
    assert!(rule["detection"]
        .as_object()
        .unwrap()
        .iter()
        .any(|(k, v)| k != "condition" && v.is_object()));
}

#[test]
fn convert_json_stdout_is_a_single_machine_readable_document() {
    let dir = tmp("json-stdout");
    let source = dir.join("rules.yar");
    fs::write(&source, format!("{BASIC}{SECOND}")).unwrap();
    let (code, out, _) = run(&["convert", s(&source), "--format", "json"]);
    assert_eq!(code, 0);
    let payload: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(payload["schema_version"], "1.0");
    assert_eq!(payload["pipeline"], "sysmon");
    let results = payload["results"].as_array().unwrap();
    let titles: Vec<&str> = results
        .iter()
        .map(|r| r["rule"]["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["test desc", "Second"]);
    assert!(results
        .iter()
        .all(|r| r["source"] == s(&source) && r["report"].is_array()));
}

#[test]
fn convert_json_output_writes_one_json_file_per_rule() {
    let dir = tmp("json-files");
    let source = dir.join("rules.yar");
    let output = dir.join("converted");
    fs::write(&source, format!("{BASIC}{SECOND}")).unwrap();
    let (code, out, _) = run(&["convert", s(&source), "--format", "json", "-o", s(&output)]);
    assert_eq!(code, 0);
    assert_eq!(files(&output, ".json"), ["rules_1.json", "rules_2.json"]);
    let title = |name: &str| {
        let doc: Value =
            serde_json::from_str(&fs::read_to_string(output.join(name)).unwrap()).unwrap();
        doc["results"][0]["rule"]["title"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(title("rules_1.json"), "test desc");
    assert_eq!(title("rules_2.json"), "Second");
    assert!(out.contains("->"));
}

#[test]
fn convert_defaults_to_yaml_stdout() {
    let dir = tmp("yaml-stdout");
    let source = dir.join("rule.yar");
    fs::write(&source, BASIC).unwrap();
    let (code, out, _) = run(&["convert", s(&source)]);
    assert_eq!(code, 0);
    assert_eq!(yaml(&out)["title"], "test desc");
    assert!(out.starts_with("title:"));

    fs::write(&source, format!("{BASIC}{SECOND}")).unwrap();
    let (_, out, err) = run(&["convert", s(&source), "-v", "-p", "linux"]);
    assert!(out.contains("\n---\n") && err.contains("    # Pattern 'cmd.exe /c'"));
    assert!(out.contains("product: linux"));
}

#[test]
fn convert_directory_and_errors() {
    let dir = tmp("dir");
    let rules = dir.join("rules");
    fs::create_dir_all(rules.join("nested")).unwrap();
    fs::write(rules.join("b.yar"), BASIC).unwrap();
    fs::write(rules.join("nested").join("a.yara"), SECOND).unwrap();
    fs::write(rules.join("ignored.txt"), BASIC).unwrap();
    let out_dir = dir.join("out");
    let (code, out, err) = run(&[
        "convert",
        s(&rules),
        "--dir",
        "-o",
        s(&out_dir),
        "--no-progress",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(files(&out_dir, ".yml"), ["a.yml", "b.yml"]);
    assert!(out.contains("[+] a.yara [Second] -> ") && out.contains("[+] b.yar [test desc] -> "));

    let (code, _, err) = run(&["convert", s(&rules), "-o", s(&out_dir)]);
    assert_eq!(code, 0);
    assert!(err.contains("processed 2/2"));

    let empty = dir.join("empty");
    fs::create_dir_all(&empty).unwrap();
    let (code, _, err) = run(&["convert", s(&empty)]);
    assert_eq!(code, 1);
    assert!(err.contains("No YARA files found at"));

    let (code, _, err) = run(&["convert", s(&rules.join("b.yar")), "-p", "nope"]);
    assert_eq!(code, 1);
    assert!(err.contains("Pipeline not found"));

    let (code, _, err) = run(&["convert", s(&dir.join("missing.yar"))]);
    assert_eq!(code, 1);
    assert!(err.contains("missing.yar"));

    let (code, _, err) = run(&["convert", s(&rules.join("b.yar")), "--format", "xml"]);
    assert_eq!(code, 2);
    assert!(err.contains("invalid value"));
}

#[test]
fn detection_rules_format() {
    let dir = tmp("detection-rules");
    let src = dir.join("dropper.yar");
    fs::write(
        &src,
        format!(
            "{WITH_TECHNIQUE}{}",
            no_technique().replace("rule Dropper", "rule Other")
        ),
    )
    .unwrap();
    let out = dir.join("sigma");
    let (code, _, err) = run(&[
        "convert",
        s(&src),
        "--format",
        "detection-rules",
        "-o",
        s(&out),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("Other") && err.contains("no MITRE ATT&CK technique"));
    assert_eq!(files(&out, ".yml"), ["dropper_1.yml"]);
    assert_lint_clean(&yaml(
        &fs::read_to_string(out.join("dropper_1.yml")).unwrap(),
    ));

    let (code, _, _) = run(&[
        "convert",
        s(&src),
        "--format",
        "detection-rules",
        "--attack",
        "T1204.002",
        "-o",
        s(&out),
    ]);
    assert_eq!(code, 0);
    assert_eq!(files(&out, ".yml"), ["dropper_1.yml", "dropper_2.yml"]);
    for name in ["dropper_1.yml", "dropper_2.yml"] {
        let rule = yaml(&fs::read_to_string(out.join(name)).unwrap());
        assert_lint_clean(&rule);
        assert!(rule["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "attack.t1204.002"));
    }

    fs::write(&src, WITH_TECHNIQUE).unwrap();
    let (code, text, _) = run(&["convert", s(&src), "--format", "detection-rules"]);
    assert_eq!(code, 0);
    assert!(text.starts_with("title:"));
    let at = |key: &str| text.find(&format!("\n{key}:")).unwrap();
    assert!(at("modified") < at("references") && at("references") < at("fields"));
    assert!(!text.contains("x_yar2sig"));
}

#[test]
fn pipelines_and_version() {
    let (code, out, _) = run(&["pipelines"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "linux        linux/process_creation",
            "proxy        ?/proxy",
            "sysmon       windows/sysmon",
            "winsec       windows/security"
        ]
    );
    let (code, out, _) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.contains(env!("CARGO_PKG_VERSION")));
    let (code, _, err) = run(&[]);
    assert_eq!(code, 2);
    assert!(err.contains("Usage"));
}

#[test]
fn query_fallback_and_native() {
    let dir = tmp("query");
    let (code, out, _) = run_env(
        &["query", "samples/malware.yar", "-b", "splunk"],
        Some(&dir),
    );
    assert_eq!(code, 0);
    assert!(out.starts_with(
        "_raw=\"*http://cdn.example-c2.com/jquery-3.3.1.min.js*\" OR _raw=\"*Mozilla/5.0"
    ));
    let (code, out, _) = run_env(
        &["query", "samples/malware.yar", "-b", "kusto", "-p", "linux"],
        Some(&dir),
    );
    assert_eq!(code, 0);
    assert!(out.starts_with("DeviceProcessEvents | where ProcessCommandLine contains"));
    let (code, _, err) = run(&["query", "samples/malware.yar", "-b", "nope"]);
    assert_eq!(code, 2);
    assert!(err.contains("possible values"));
    let (code, _, err) = run(&["query", s(&dir.join("missing.yar"))]);
    assert_eq!(code, 1);
    assert!(err.contains("missing.yar"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sigma = dir.join("sigma");
        fs::write(&sigma, "#!/bin/sh\n[ \"$1\" = convert ] && [ \"$3\" = splunk ] && echo \"native query from ${4##*/}\"\n").unwrap();
        fs::set_permissions(&sigma, fs::Permissions::from_mode(0o755)).unwrap();
        let (code, out, _) = run_env(
            &["query", "samples/malware.yar", "-b", "splunk"],
            Some(&dir),
        );
        assert_eq!(code, 0);
        assert!(out.starts_with("native query from yar2sig-") && out.trim_end().ends_with(".yml"));
        // no native target: sigma is not used
        let (_, out, _) = run_env(
            &["query", "samples/malware.yar", "-b", "crowdstrike"],
            Some(&dir),
        );
        assert!(out.starts_with("CommandLine:*http\\:\\/\\/cdn.example\\-c2.com"));
    }
}

const SIGMA: &str =
    "title: CliTest\ndetection:\n  selection:\n    Image: cmd.exe\n  condition: selection\n";

#[test]
fn reverse_writes_yar_and_stdout_formats() {
    let dir = tmp("reverse");
    let source = dir.join("input.yml");
    fs::write(&source, SIGMA).unwrap();
    let outdir = dir.join("out");
    let (code, out, _) = run(&["reverse", s(&source), "-o", s(&outdir)]);
    assert_eq!(code, 0);
    assert_eq!(files(&outdir, ".yar"), ["input.yar"]);
    let body = fs::read_to_string(outdir.join("input.yar")).unwrap();
    assert!(
        body.contains("rule CliTest") && body.contains("\"cmd.exe\"") && body.starts_with("/*")
    );
    assert!(out.contains("[+] input.yml -> "));

    let (code, out, err) = run(&["reverse", s(&source), "-v", "--no-comments"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("rule CliTest") && out.contains("\"cmd.exe\""));
    assert!(err.contains("    # WARNING: Sigma event-field semantics"));

    let (code, out, _) = run(&["reverse", s(&source), "--format", "json"]);
    assert_eq!(code, 0);
    let envelope: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(envelope["schema_version"], "1.0");
    assert_eq!(envelope["direction"], "sigma-to-yara");
    assert_eq!(envelope["results"].as_array().unwrap().len(), 1);
    assert!(envelope["results"][0]["yara"]
        .as_str()
        .unwrap()
        .contains("rule CliTest"));
    assert!(envelope["results"][0]["report"].is_array());

    let bad = dir.join("bad.yml");
    fs::write(&bad, "{ this: is: not: valid: yaml").unwrap();
    let (code, _, err) = run(&["reverse", s(&bad)]);
    assert_eq!(code, 1);
    assert!(err.contains("bad.yml"));
}

#[test]
fn reverse_directory_processes_all_files() {
    let dir = tmp("reverse-dir");
    let rules = dir.join("rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("one.yml"),
        "title: One\ndetection:\n  s:\n    F: a\n  condition: s\n",
    )
    .unwrap();
    fs::write(
        rules.join("two.yaml"),
        "title: Two\ndetection:\n  s:\n    F: b\n  condition: s\n",
    )
    .unwrap();
    fs::write(
        rules.join("multi.yml"),
        format!("{SIGMA}---\n{}", SIGMA.replace("CliTest", "Other")),
    )
    .unwrap();
    let outdir = dir.join("out");
    let (code, _, err) = run(&["reverse", s(&rules), "-o", s(&outdir), "--no-progress"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        files(&outdir, ".yar"),
        ["multi_1.yar", "multi_2.yar", "one.yar", "two.yar"]
    );
    let (code, _, err) = run(&["reverse", s(&dir.join("nope"))]);
    assert_eq!(code, 1);
    assert!(err.contains("nope"));
}
