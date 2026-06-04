"""Tests for yar2sig."""

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
    assert classify_pattern("just some text") == "generic"


def test_parse():
    p = parse_yara_rule(BASIC)
    assert p["name"] == "TestRule"
    assert p["meta"]["author"] == "tester"
    assert "malware" in p["tags"]
    assert len(p["strings"]) == 4
    assert p["cond_type"] == "any"


def test_split_multi():
    text = BASIC + "\nrule Second {\n strings:\n  $a=\"x\"\n condition:\n  $a\n}\n"
    assert len(split_rules(text)) == 2


def test_convert_and_tags():
    rule, report = convert(BASIC, "sysmon")
    assert rule["title"] == "test desc" or rule["title"] == "TestRule"
    assert "attack.t1059.003" in rule["tags"]
    assert rule["detection"]["condition"]
    assert len(report) >= 4


def test_pipelines_exist():
    pls = available_pipelines()
    for expected in ("sysmon", "winsec", "linux", "proxy"):
        assert expected in pls
        assert "mappings" in load_mapping(expected)


def test_query_fallback():
    parsed = parse_yara_rule(BASIC)
    rule, _ = convert(BASIC, "sysmon")
    q = generate_query("splunk", rule, parsed["strings"])
    assert q  # non-empty
