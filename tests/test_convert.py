"""Tests for yar2sig."""

import json
import os
import subprocess
import threading
import time
import yaml

import pytest

import yar2sig.backends as backends
from app import app
from yar2sig import (
    available_pipelines,
    classify_pattern,
    convert,
    generate_query,
    load_mapping,
)
from yar2sig.cli import main as cli_main
from yar2sig.parser import parse_yara_rule, split_rules

BASIC = """
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
"""


def test_classify():
    assert classify_pattern("http://x.com") == "url"
    assert classify_pattern("10.0.0.5") == "ip"
    assert classify_pattern("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert classify_pattern("evil.example.com") == "domain"
    assert classify_pattern("C:\\Users\\Public\\x.exe") == "path_or_filename"
    assert classify_pattern("HKLM\\Software\\Run") == "registry"
    assert classify_pattern("user@evil.com") == "email"
    assert classify_pattern("Mozilla/5.0 (Windows NT 10.0)") == "user_agent"
    assert classify_pattern("\\\\.\\pipe\\msagent_") == "named_pipe"
    assert classify_pattern("just some text") == "generic"


def test_parse():
    parsed = parse_yara_rule(BASIC)
    assert parsed["name"] == "TestRule"
    assert parsed["meta"]["author"] == "tester"
    assert "malware" in parsed["tags"]
    assert len(parsed["strings"]) == 4
    assert parsed["cond_type"] == "any"


def test_parse_modifiers_and_escaped_text():
    parsed = parse_yara_rule(
        r'''
rule Modded {
  strings:
    $a = "powershell\x20-enc" wide nocase
    $b = /cmd\.exe\s+\/c/i
  condition:
    $a and $b
}
'''
    )
    assert parsed["strings"][0] == "powershell -enc"
    assert parsed["string_modifiers"][0] == ["wide", "nocase"]
    assert parsed["string_types"][1] == "regex"
    assert parsed["condition_raw"] == "$a and $b"


def test_split_multi():
    text = BASIC + "\nrule Second {\n strings:\n  $a=\"x\"\n condition:\n  $a\n}\n"
    assert len(split_rules(text)) == 2


def test_convert_and_tags():
    rule, report = convert(BASIC, "sysmon")
    assert rule["title"] == "test desc"
    assert "attack.t1059.003" in rule["tags"]
    assert rule["detection"]["condition"]
    assert rule["x_yar2sig"]["confidence"] in {"high", "medium", "low"}
    assert len(report) >= 4


def test_convert_uses_all_mapped_fields():
    rule, _ = convert(
        """
rule UrlRule {
  strings:
    $url = "http://evil.example.com/path"
  condition:
    $url
}
""",
        "sysmon",
    )
    assert rule["detection"]["condition"] == "(sel1_1 or sel1_2)"
    assert "Image|contains" in rule["detection"]["sel1_1"]
    assert "CommandLine|contains" in rule["detection"]["sel1_2"]


def test_complex_condition_lowers_confidence():
    rule, report = convert(
        """
rule Complex {
  strings:
    $a1 = "rundll32.exe"
    $a2 = "regsvr32.exe"
    $b = /powershell\\s+-enc/
  condition:
    1 of ($a*) and $b
}
""",
        "sysmon",
    )
    assert rule["x_yar2sig"]["review_required"] is True
    assert any("Complex YARA condition" in line for line in report)


def test_pipelines_exist():
    pipelines = available_pipelines()
    for expected in ("sysmon", "winsec", "linux", "proxy"):
        assert expected in pipelines
        assert "mappings" in load_mapping(expected)


@pytest.mark.parametrize("pipeline", ("../sysmon", "sysmon/../../etc/passwd", "/etc/passwd"))
def test_load_mapping_rejects_untrusted_paths(pipeline):
    with pytest.raises(FileNotFoundError):
        load_mapping(pipeline)


def test_load_mapping_rejects_non_string_name():
    with pytest.raises(ValueError, match="must be a string"):
        load_mapping(None)


def test_parser_rejects_too_many_patterns():
    lines = "\n".join(f'    $s{i} = "v{i}"' for i in range(60))
    rule = f"rule Big {{\n  strings:\n{lines}\n  condition:\n    any of them\n}}"
    with pytest.raises(ValueError, match="pattern count"):
        parse_yara_rule(rule, max_patterns=50)


def test_parser_rejects_overlong_pattern():
    rule = f'rule Long {{\n  strings:\n    $a = "{"A" * 200}"\n  condition:\n    $a\n}}'
    with pytest.raises(ValueError, match="maximum length"):
        parse_yara_rule(rule, max_pattern_length=100)


def test_parser_rejects_non_positive_limits():
    with pytest.raises(ValueError, match="must be positive"):
        parse_yara_rule(BASIC, max_patterns=0)


def test_parser_default_limits_allow_basic_rule():
    parsed = parse_yara_rule(BASIC)
    assert len(parsed["strings"]) == 4


def test_query_fallback_escapes_special_characters(monkeypatch):
    monkeypatch.setattr(backends, "_sigma_cli_available", lambda: False)
    parsed = parse_yara_rule(BASIC)
    rule, _ = convert(BASIC, "sysmon")
    query = generate_query("splunk", rule, parsed["strings"] + ['evil"quoted\\path'])
    assert r'evil\"quoted\\path' in query


def test_api_validates_backend():
    client = app.test_client()
    response = client.post("/api/convert", json={"rule": BASIC, "backend": "missing"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Unknown backend"


def test_api_returns_quality():
    client = app.test_client()
    response = client.post("/api/convert", json={"rule": BASIC, "pipeline": "sysmon", "backend": "splunk"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["quality"]["confidence"] in {"high", "medium", "low"}
    assert payload["parsed"]["patterns"] == 4
    assert payload["query"]


def test_api_hides_unexpected_exception_details(monkeypatch):
    secret = "internal-sensitive-detail"

    def fail_conversion(*args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr("app.generate_query", fail_conversion)
    client = app.test_client()
    response = client.post("/api/convert", json={"rule": BASIC, "pipeline": "sysmon", "backend": "splunk"})
    payload = response.get_json()
    assert response.status_code == 500
    assert payload == {"error": "Conversion failed"}
    assert secret not in response.get_data(as_text=True)


def test_api_sets_security_headers():
    client = app.test_client()
    response = client.get("/healthz")
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert response.headers.get("Cross-Origin-Opener-Policy") == "same-origin"


def test_api_convert_sets_no_store_cache():
    client = app.test_client()
    response = client.post("/api/convert", json={"rule": BASIC, "pipeline": "sysmon", "backend": "splunk"})
    assert response.headers.get("Cache-Control") == "no-store"


def test_api_rejects_non_string_rule():
    client = app.test_client()
    response = client.post("/api/convert", json={"rule": 123, "pipeline": "sysmon", "backend": "splunk"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Rule must be a string"


def test_api_rejects_non_object_json():
    client = app.test_client()
    response = client.post(
        "/api/convert",
        data="[1, 2, 3]",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "JSON object expected"


def test_api_rejects_oversized_rule_text():
    client = app.test_client()
    huge = "rule R {\n  strings:\n    $a = \"" + ("A" * 1_000_050) + "\"\n  condition:\n    $a\n}"
    response = client.post(
        "/api/convert",
        json={"rule": huge, "pipeline": "sysmon", "backend": "splunk"},
    )
    assert response.status_code == 413
    assert response.get_json()["error"] in {"Request body is too large", "Rule text exceeds maximum size"}


def test_api_enforces_rule_limit_in_utf8_bytes():
    client = app.test_client()
    rule = 'rule R {\n  strings:\n    $a = "' + ("é" * 500_000) + '"\n  condition:\n    $a\n}'
    body = json.dumps(
        {"rule": rule, "pipeline": "sysmon", "backend": "splunk"},
        ensure_ascii=False,
    ).encode("utf-8")
    response = client.post("/api/convert", data=body, content_type="application/json")
    assert response.status_code == 413
    assert response.get_json()["error"] == "Rule text exceeds maximum size"


def test_api_rejects_oversized_body_via_content_length():
    client = app.test_client()
    payload = b"x" * 1_200_000
    response = client.post(
        "/api/convert",
        data=payload,
        content_type="application/json",
    )
    assert response.status_code == 413
    assert response.get_json()["error"] == "Request body is too large"


def test_cli_convert_json_stdout_is_a_single_machine_readable_document(tmp_path, capsys):
    source = tmp_path / "rules.yar"
    source.write_text(
        BASIC + '\nrule Second { strings: $a = "x" condition: $a }\n',
        encoding="utf-8",
    )

    assert cli_main(["convert", str(source), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema_version"] == "1.0"
    assert payload["pipeline"] == "sysmon"
    assert [result["rule"]["title"] for result in payload["results"]] == [
        "test desc",
        "Second",
    ]
    assert all(result["source"] == str(source) for result in payload["results"])
    assert all(isinstance(result["report"], list) for result in payload["results"])


def test_cli_convert_json_output_writes_one_json_file_per_rule(tmp_path, capsys):
    source = tmp_path / "rules.yar"
    output = tmp_path / "converted"
    source.write_text(
        BASIC + '\nrule Second { strings: $a = "x" condition: $a }\n',
        encoding="utf-8",
    )

    assert cli_main(["convert", str(source), "--format", "json", "-o", str(output)]) == 0
    files = sorted(output.glob("*.json"))

    assert [file.name for file in files] == ["rules_1.json", "rules_2.json"]
    assert [json.loads(file.read_text(encoding="utf-8"))["results"][0]["rule"]["title"] for file in files] == [
        "test desc",
        "Second",
    ]
    assert "->" in capsys.readouterr().out


def test_cli_convert_defaults_to_yaml_stdout(tmp_path, capsys):
    source = tmp_path / "rule.yar"
    source.write_text(BASIC, encoding="utf-8")

    assert cli_main(["convert", str(source)]) == 0
    output = capsys.readouterr().out

    assert yaml.safe_load(output)["title"] == "test desc"
    assert not output.lstrip().startswith("{")


ADVERSARIAL_RULES = {
    "repeated_meta_unterminated": "rule a {\n" + "meta: " * 160_000,
    "repeated_condition_unterminated": "rule a {\n" + "condition: " * 90_000,
    "blank_lines": "x" + "\n" * 1_000_000 + "y",
    "nested_unterminated_braces": "rule a {\n" * 110_000,
    "headers_without_brace": "rule a : t\n" * 90_000,
    "unterminated_string": 'rule a {\n strings:\n $a = "' + "strings: " * 110_000,
    "inner_whitespace": "rule a {\n strings:\n $a = x" + " " * 1_000_000 + "y\n condition: any of them\n}",
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_RULES))
def test_parser_is_linear_on_adversarial_1mb_input(name):
    started = time.perf_counter()
    try:
        parse_yara_rule(ADVERSARIAL_RULES[name])
    except ValueError:
        pass  # bound violations are fine; hanging is not
    # The old regexes took minutes to hours on these inputs.
    assert time.perf_counter() - started < 10


def test_parser_handles_braces_inside_strings_hex_and_regex():
    text = r'''
rule Braces {
  strings:
    $s = "}{ not a brace"
    $h = { 4D 5A [2-4] 90 }
    $r = /a{2,3}\}/
  condition:
    any of them
}
rule Next { condition: true }
'''
    assert len(split_rules(text)) == 2
    parsed = parse_yara_rule(text)
    assert parsed["name"] == "Braces"
    assert parsed["strings"] == ["}{ not a brace", "4D 5A [2-4] 90", r"a{2,3}\}"]
    assert parsed["condition_raw"] == "any of them"


def test_parser_tolerates_unterminated_string_and_malformed_input():
    parsed = parse_yara_rule('rule Broken {\n strings:\n  $a = "abc\n condition:\n  any of them\n}')
    assert parsed["name"] == "Broken"
    assert parsed["strings"] == []
    assert parsed["condition_raw"] == "any of them"

    parsed = parse_yara_rule("rule Open {\n strings:\n  $a = \"x\"\n condition:\n  $a")
    assert parsed["strings"] == ["x"]
    assert parsed["condition_raw"] == "$a"

    assert parse_yara_rule("not a yara rule")["name"] == "ConvertedRule"


def _fake_sigma(monkeypatch, run):
    monkeypatch.setattr(backends, "_sigma_cli_available", lambda: True)
    monkeypatch.setattr(backends, "_SIGMA_SLOTS", threading.BoundedSemaphore(1))
    monkeypatch.setattr(backends.subprocess, "run", run)


def test_sigma_slot_is_released_after_success_and_failure(monkeypatch):
    rule, _ = convert(BASIC, "sysmon")
    done = subprocess.CompletedProcess([], 0, "native query", "")
    _fake_sigma(monkeypatch, lambda *a, **k: done)
    assert generate_query("splunk", rule, []) == "native query"
    assert generate_query("splunk", rule, []) == "native query"

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("sigma", 30)

    monkeypatch.setattr(backends.subprocess, "run", timeout)
    assert generate_query("splunk", rule, ["x"]) == '_raw="*x*"'
    assert backends._SIGMA_SLOTS.acquire(blocking=False)


def test_api_returns_503_when_sigma_slots_are_busy(monkeypatch):
    _fake_sigma(monkeypatch, lambda *a, **k: pytest.fail("sigma ran while saturated"))
    backends._SIGMA_SLOTS.acquire()
    response = app.test_client().post(
        "/api/convert", json={"rule": BASIC, "pipeline": "sysmon", "backend": "splunk"}
    )
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert "busy" in response.get_json()["error"]


@pytest.mark.parametrize(("value", "expected"), [("3", 3), ("0", 1), ("junk", None), (None, None)])
def test_sigma_slot_count_from_env(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("YAR2SIG_SIGMA_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("YAR2SIG_SIGMA_CONCURRENCY", value)
    assert backends._sigma_slots() == (expected or os.cpu_count() or 1)
