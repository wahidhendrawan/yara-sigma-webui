//! IOC classification heuristics: a plain-text YARA pattern -> indicator type used by the
//! mapping engine to pick Sigma fields.

use std::sync::LazyLock;

use regex::Regex;

macro_rules! re {
    ($name:ident, $pattern:literal) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}

re!(
    HASH_RE,
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$"
);
re!(IPV4_RE, r"^(?:\d{1,3}\.){3}\d{1,3}$");
re!(IPV6_RE, r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");
// The Python lookahead `(?=.{1,253}$)` is the length check in `classify_pattern`.
re!(DOMAIN_RE, r"^(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}$");
re!(EMAIL_RE, r"^[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$");
re!(REG_RE, r"(?i)^(?:HKLM|HKCU|HKCR|HKU|HKEY_)");
re!(URL_RE, r"(?i)^[a-z]+://");
re!(NAMED_PIPE_RE, r"(?i)^\\\\(?:\.\\)?pipe\\");
re!(EXT_RE, r"\.([A-Za-z0-9]{1,5})$");

const FILE_EXTS: &[&str] = &[
    "bat", "bin", "cmd", "dat", "dll", "dmp", "elf", "exe", "hta", "jar", "js", "jse", "lnk",
    "msi", "ocx", "pdb", "ps1", "psm1", "py", "scr", "sh", "so", "sys", "tmp", "vbe", "vbs", "wsf",
];
const MUTEX_HINTS: &[&str] = &["global\\", "local\\", "mutex", "\\sessions\\"];
const USER_AGENT_HINTS: &[&str] = &[
    "mozilla/", "chrome/", "firefox/", "safari/", "trident/", "edge/", "edg/", "opera/", "curl/",
    "wget/",
];

/// Return a normalized IOC type for mapping selection.
pub fn classify_pattern(pattern: &str) -> &'static str {
    let value = pattern.trim();
    if value.is_empty() {
        return "generic";
    }
    let low = value.to_lowercase();
    if URL_RE.is_match(value) {
        return "url";
    }
    if REG_RE.is_match(value)
        || low.contains("\\software\\")
        || low.contains("\\system\\currentcontrolset")
    {
        return "registry";
    }
    if NAMED_PIPE_RE.is_match(value) {
        return "named_pipe";
    }
    if IPV4_RE.is_match(value) || IPV6_RE.is_match(value) {
        return "ip";
    }
    if HASH_RE.is_match(value) {
        return "hash";
    }
    if EMAIL_RE.is_match(value) {
        return "email";
    }
    if MUTEX_HINTS.iter().any(|hint| low.contains(hint)) {
        return "mutex";
    }
    if USER_AGENT_HINTS.iter().any(|hint| low.contains(hint)) {
        return "user_agent";
    }
    if value.contains('/') || value.contains('\\') {
        return "path_or_filename";
    }
    if let Some(ext) = EXT_RE.captures(value) {
        if FILE_EXTS.contains(&ext[1].to_lowercase().as_str()) {
            return "path_or_filename";
        }
    }
    if value.chars().count() <= 253
        && !value.contains('\n')
        && DOMAIN_RE.is_match(value)
        && !value.contains(' ')
    {
        return "domain";
    }
    "generic"
}

#[cfg(test)]
mod tests {
    use super::classify_pattern;

    #[test]
    fn classify() {
        assert_eq!(classify_pattern("http://x.com"), "url");
        assert_eq!(classify_pattern("10.0.0.5"), "ip");
        assert_eq!(classify_pattern("44d88612fea8a8f36de82e1278abb02f"), "hash");
        assert_eq!(classify_pattern("evil.example.com"), "domain");
        assert_eq!(
            classify_pattern("C:\\Users\\Public\\x.exe"),
            "path_or_filename"
        );
        assert_eq!(classify_pattern("HKLM\\Software\\Run"), "registry");
        assert_eq!(classify_pattern("user@evil.com"), "email");
        assert_eq!(
            classify_pattern("Mozilla/5.0 (Windows NT 10.0)"),
            "user_agent"
        );
        assert_eq!(classify_pattern("\\\\.\\pipe\\msagent_"), "named_pipe");
        assert_eq!(classify_pattern("just some text"), "generic");
        assert_eq!(classify_pattern("payload.exe"), "path_or_filename");
        assert_eq!(classify_pattern("Global\\MyMutex"), "mutex");
        assert_eq!(classify_pattern(""), "generic");
        assert_eq!(
            classify_pattern(&format!("{}.com", "a".repeat(260))),
            "generic"
        );
    }
}
