"""Tests for yar2sig."""

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
