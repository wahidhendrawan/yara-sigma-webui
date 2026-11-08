//! Multi-backend query generation: `sigma-cli` for native conversion when it is on PATH,
//! otherwise a simple escaped wildcard search expression per backend.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use std::{env, fmt, fs, thread};

use serde_json::Value;

pub struct Backend {
    pub id: &'static str,
    pub label: &'static str,
    pub field: &'static str,
    /// sigma-cli target, when native conversion exists.
    pub target: Option<&'static str>,
}

pub const BACKENDS: [Backend; 7] = [
    Backend {
        id: "elasticsearch",
        label: "Elastic (Lucene/KQL)",
        field: "message",
        target: Some("lucene"),
    },
    Backend {
        id: "splunk",
        label: "Splunk SPL",
        field: "_raw",
        target: Some("splunk"),
    },
    Backend {
        id: "kusto",
        label: "Microsoft Sentinel / Defender (KQL)",
        field: "ProcessCommandLine",
        target: Some("kusto"),
    },
    Backend {
        id: "qradar",
        label: "IBM QRadar AQL",
        field: "payload",
        target: Some("qradar"),
    },
    Backend {
        id: "carbonblack",
        label: "VMware Carbon Black",
        field: "process_cmdline",
        target: None,
    },
    Backend {
        id: "sentinelone",
        label: "SentinelOne Deep Visibility",
        field: "SrcProcCmdLine",
        target: None,
    },
    Backend {
        id: "crowdstrike",
        label: "CrowdStrike Falcon",
        field: "CommandLine",
        target: None,
    },
];

const SIGMA_TIMEOUT: Duration = Duration::from_secs(30);

pub fn backend_ids() -> Vec<&'static str> {
    BACKENDS.iter().map(|b| b.id).collect()
}

pub fn backend(id: &str) -> Option<&'static Backend> {
    BACKENDS.iter().find(|b| b.id == id)
}

/// Every sigma-cli slot is in use; the caller should retry later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendBusy;

impl fmt::Display for BackendBusy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Native query backend is busy, retry shortly")
    }
}

impl std::error::Error for BackendBusy {}

/// `YAR2SIG_SIGMA_CONCURRENCY` (at least 1), or the CPU count when unset or not a number.
pub fn slots_from(value: Option<&str>) -> usize {
    match value.and_then(|v| v.parse::<i64>().ok()) {
        Some(n) => n.max(1) as usize,
        None => thread::available_parallelism().map_or(1, |n| n.get()),
    }
}

// Each `sigma convert` is a separate Python process (up to 30 s); cap them per server process.
static FREE_SLOTS: LazyLock<Mutex<usize>> = LazyLock::new(|| {
    Mutex::new(slots_from(
        env::var("YAR2SIG_SIGMA_CONCURRENCY").ok().as_deref(),
    ))
});

/// One sigma-cli slot, released on drop.
pub struct SlotGuard(());

impl SlotGuard {
    pub fn try_acquire() -> Option<SlotGuard> {
        let mut free = FREE_SLOTS.lock().unwrap_or_else(|e| e.into_inner());
        if *free == 0 {
            return None;
        }
        *free -= 1;
        Some(SlotGuard(()))
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        *FREE_SLOTS.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    }
}

/// `sigma` on PATH (what `shutil.which("sigma")` returns).
pub fn find_sigma() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["sigma.exe", "sigma"]
    } else {
        &["sigma"]
    };
    env::split_paths(&env::var_os("PATH")?)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

fn escape_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_lucene(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if "+-&|!(){}[]^\"~*?:\\/".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn escape_qradar_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\'', "''")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn fallback_query(backend: &Backend, patterns: &[String]) -> String {
    let field = backend.field;
    let values: Vec<&String> = patterns.iter().filter(|p| !p.trim().is_empty()).collect();
    if values.is_empty() {
        return format!("{field}:*");
    }
    match backend.id {
        "splunk" => values
            .iter()
            .map(|v| format!("{field}=\"*{}*\"", escape_quoted(v)))
            .collect::<Vec<_>>()
            .join(" OR "),
        "kusto" => {
            let conds = values
                .iter()
                .map(|v| format!("{field} contains \"{}\"", escape_quoted(v)))
                .collect::<Vec<_>>()
                .join(" or ");
            format!("DeviceProcessEvents | where {conds}")
        }
        "qradar" => {
            let conds = values
                .iter()
                .map(|v| {
                    format!(
                        "\"{field}\" ILIKE '%{}%' ESCAPE '\\\\'",
                        escape_qradar_like(v)
                    )
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            format!("SELECT * FROM events WHERE {conds}")
        }
        _ => values
            .iter()
            .map(|v| format!("{field}:*{}*", escape_lucene(v)))
            .collect::<Vec<_>>()
            .join(" OR "),
    }
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(text.as_bytes())
}

fn run_sigma(sigma: &Path, target: &str, rule_file: &Path) -> Option<String> {
    let mut child = Command::new(sigma)
        .args(["convert", "-t", target])
        .arg(rule_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + SIGMA_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = reader.join().ok()?;
    if !status?.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn native_query(sigma: &Path, target: &str, rule: &Value) -> Option<String> {
    let path = env::temp_dir().join(format!("yar2sig-{}.yml", uuid::Uuid::new_v4()));
    let yaml = serde_yaml_ng::to_string(rule).ok()?;
    write_private(&path, &yaml).ok()?;
    let result = run_sigma(sigma, target, &path);
    let _ = fs::remove_file(&path);
    result
}

/// Generate a native query for `backend_id`: sigma-cli first when a native target exists and
/// `sigma` is given, then a best-effort escaped wildcard query.
pub fn generate_query_with(
    sigma: Option<&Path>,
    backend_id: &str,
    rule: &Value,
    patterns: &[String],
) -> Result<String, BackendBusy> {
    let Some(backend) = backend(backend_id) else {
        return Ok(format!("# Unknown backend: {backend_id}"));
    };
    if let (Some(target), Some(sigma)) = (backend.target, sigma) {
        let _slot = SlotGuard::try_acquire().ok_or(BackendBusy)?;
        if let Some(query) = native_query(sigma, target, rule) {
            return Ok(query);
        }
    }
    Ok(fallback_query(backend, patterns))
}

/// [`generate_query_with`] using `sigma` from PATH.
pub fn generate_query(
    backend_id: &str,
    rule: &Value,
    patterns: &[String],
) -> Result<String, BackendBusy> {
    generate_query_with(find_sigma().as_deref(), backend_id, rule, patterns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn fallback_queries_escape_special_characters() {
        let rule = json!({"title": "t"});
        let q = generate_query_with(
            None,
            "splunk",
            &rule,
            &strings(&["cmd.exe", "evil\"quoted\\path", " "]),
        )
        .unwrap();
        assert_eq!(q, r#"_raw="*cmd.exe*" OR _raw="*evil\"quoted\\path*""#);
        assert_eq!(
            generate_query_with(None, "splunk", &rule, &[]).unwrap(),
            "_raw:*"
        );
        assert_eq!(
            generate_query_with(None, "kusto", &rule, &strings(&["a\"b"])).unwrap(),
            r#"DeviceProcessEvents | where ProcessCommandLine contains "a\"b""#
        );
        assert_eq!(
            generate_query_with(None, "qradar", &rule, &strings(&["50%_'x"])).unwrap(),
            r#"SELECT * FROM events WHERE "payload" ILIKE '%50\%\_''x%' ESCAPE '\\'"#
        );
        assert_eq!(
            generate_query_with(None, "elasticsearch", &rule, &strings(&["a+b:c/d"])).unwrap(),
            r"message:*a\+b\:c\/d*"
        );
        assert_eq!(
            generate_query_with(None, "crowdstrike", &rule, &strings(&["x"])).unwrap(),
            "CommandLine:*x*"
        );
        assert_eq!(
            generate_query_with(None, "nope", &rule, &[]).unwrap(),
            "# Unknown backend: nope"
        );
    }

    #[test]
    fn slot_count_from_env_value() {
        assert_eq!(slots_from(Some("3")), 3);
        assert_eq!(slots_from(Some("0")), 1);
        assert_eq!(slots_from(Some("-2")), 1);
        let cpus = thread::available_parallelism().map_or(1, |n| n.get());
        assert_eq!(slots_from(Some("junk")), cpus);
        assert_eq!(slots_from(Some("")), cpus);
        assert_eq!(slots_from(None), cpus);
    }

    #[cfg(unix)]
    fn fake_sigma(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn native_path_then_fallback_and_slot_release() {
        let dir = env::temp_dir().join(format!("yar2sig-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let rule = json!({"title": "t", "detection": {"sel": {"a": "b"}, "condition": "sel"}});

        let ok = fake_sigma(&dir, "sigma-ok", "echo native query");
        assert_eq!(
            generate_query_with(Some(&ok), "splunk", &rule, &strings(&["x"])).unwrap(),
            "native query"
        );
        // no native target: sigma is never run
        assert_eq!(
            generate_query_with(Some(&ok), "crowdstrike", &rule, &strings(&["x"])).unwrap(),
            "CommandLine:*x*"
        );

        let failing = fake_sigma(&dir, "sigma-fail", "exit 3");
        assert_eq!(
            generate_query_with(Some(&failing), "splunk", &rule, &strings(&["x"])).unwrap(),
            r#"_raw="*x*""#
        );
        let silent = fake_sigma(&dir, "sigma-silent", "exit 0");
        assert_eq!(
            generate_query_with(Some(&silent), "splunk", &rule, &strings(&["x"])).unwrap(),
            r#"_raw="*x*""#
        );

        // every slot busy -> BackendBusy, and the slots come back once the guards drop
        let guards: Vec<SlotGuard> = std::iter::from_fn(SlotGuard::try_acquire).collect();
        assert!(!guards.is_empty());
        assert_eq!(
            generate_query_with(Some(&ok), "splunk", &rule, &[]).unwrap_err(),
            BackendBusy
        );
        drop(guards);
        assert_eq!(
            generate_query_with(Some(&ok), "splunk", &rule, &[]).unwrap(),
            "native query"
        );
        assert!(SlotGuard::try_acquire().is_some());
        fs::remove_dir_all(&dir).unwrap();
    }
}
