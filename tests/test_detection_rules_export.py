"""--format detection-rules: rules in the layout the Detection-Rules repository lint accepts."""
import re
from uuid import UUID

import pytest
import yaml

from yar2sig import convert
from yar2sig.cli import main as cli_main
from yar2sig.emitter import DETECTION_RULES_ORDER, to_detection_rules

WITH_TECHNIQUE = """
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
"""
NO_TECHNIQUE = WITH_TECHNIQUE.replace('reference = "https://attack.mitre.org/techniques/T1059/003/ T1059.003"', 'author = "x"')

# The checks of Detection-Rules' `detection_rules lint` (scripts/detection_rules/commands/lint.py).
REQUIRED = ("title", "id", "status", "description", "author", "date", "logsource", "detection", "level", "tags")
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def assert_lint_clean(rule):
    for field in REQUIRED:
        assert rule.get(field) not in (None, "", [], {}), f"missing required field: {field}"
    assert str(UUID(rule["id"])) == rule["id"].lower()
    assert rule["status"] in {"stable", "test", "experimental", "deprecated", "unsupported"}
    assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
    for field in ("title", "description", "author", "date"):
        assert isinstance(rule[field], str)
    assert isinstance(rule["tags"], list) and all(isinstance(t, str) and t.strip() for t in rule["tags"])
    assert any(TECHNIQUE_RE.fullmatch(t) for t in rule["tags"])
    assert isinstance(rule["logsource"], dict) and isinstance(rule["detection"], dict)
    assert isinstance(rule["detection"]["condition"], str) and rule["detection"]["condition"]
    assert any(isinstance(v, dict) for k, v in rule["detection"].items() if k != "condition")


def test_layout_matches_the_template():
    rule, _ = convert(WITH_TECHNIQUE)
    tags_before = list(rule["tags"])
    out = to_detection_rules(rule)
    assert list(out) == [k for k in DETECTION_RULES_ORDER if k in out]
    assert out["modified"] == out["date"] and "x_yar2sig" not in out
    assert "CommandLine" in out["fields"] and all("|" not in f for f in out["fields"])
    assert "attack.t1059.003" in out["tags"] and "yara.malware" in out["tags"]
    assert_lint_clean(out)
    assert rule["tags"] == tags_before and "x_yar2sig" in rule  # input rule untouched


def test_technique_comes_from_meta_or_attack_option():
    rule, _ = convert(NO_TECHNIQUE)
    with pytest.raises(ValueError, match="no MITRE ATT&CK technique"):
        to_detection_rules(rule)
    out = to_detection_rules(rule, ["T1059", " t1059.001 ", "T1059"])
    assert out["tags"][-2:] == ["attack.t1059", "attack.t1059.001"]
    assert_lint_clean(out)
    with pytest.raises(ValueError, match="not a MITRE ATT&CK technique"):
        to_detection_rules(rule, ["1059"])


def test_cli_writes_lint_clean_yaml_files(tmp_path, capsys):
    src = tmp_path / "dropper.yar"
    src.write_text(WITH_TECHNIQUE + NO_TECHNIQUE.replace("rule Dropper", "rule Other"), encoding="utf-8")
    out = tmp_path / "sigma"
    assert cli_main(["convert", str(src), "--format", "detection-rules", "-o", str(out)]) == 1
    err = capsys.readouterr().err
    assert "Other" in err and "no MITRE ATT&CK technique" in err
    written = sorted(out.glob("*.yml"))
    assert [p.name for p in written] == ["dropper_1.yml"]
    assert_lint_clean(yaml.safe_load(written[0].read_text(encoding="utf-8")))

    assert cli_main(["convert", str(src), "--format", "detection-rules", "--attack", "T1204.002", "-o", str(out)]) == 0
    paths = sorted(out.glob("*.yml"))
    assert [p.name for p in paths] == ["dropper_1.yml", "dropper_2.yml"]
    for path in paths:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert_lint_clean(rule)
        assert "attack.t1204.002" in rule["tags"]


def test_cli_stdout_keeps_template_order(tmp_path, capsys):
    src = tmp_path / "d.yar"
    src.write_text(WITH_TECHNIQUE, encoding="utf-8")
    assert cli_main(["convert", str(src), "--format", "detection-rules"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("title:") and text.index("modified:") < text.index("references:") < text.index("fields:")


def test_api_detection_rules_layout(capsys):
    from app import app

    client = app.test_client()
    ok = client.post("/api/convert", json={"rule": WITH_TECHNIQUE, "layout": "detection-rules"})
    assert ok.status_code == 200
    payload = ok.get_json()
    assert payload["layout"] == "detection-rules" and payload["quality"]["confidence"]
    rule = yaml.safe_load(payload["sigma"])
    assert list(rule) == [k for k in DETECTION_RULES_ORDER if k in rule] and "x_yar2sig" not in rule
    assert_lint_clean(rule)

    missing = client.post("/api/convert", json={"rule": NO_TECHNIQUE, "layout": "detection-rules"})
    assert missing.status_code == 422 and "technique" in missing.get_json()["error"]
    added = client.post("/api/convert", json={"rule": NO_TECHNIQUE, "layout": "detection-rules", "attack": ["T1204.002"]})
    assert added.status_code == 200 and "attack.t1204.002" in yaml.safe_load(added.get_json()["sigma"])["tags"]

    plain = client.post("/api/convert", json={"rule": WITH_TECHNIQUE})
    assert plain.get_json()["layout"] == "default" and "x_yar2sig" in yaml.safe_load(plain.get_json()["sigma"])
    assert client.post("/api/convert", json={"rule": WITH_TECHNIQUE, "layout": "nope"}).status_code == 400
    assert client.post("/api/convert", json={"rule": WITH_TECHNIQUE, "attack": "T1"}).status_code == 400
    assert client.post("/api/convert", json={"rule": WITH_TECHNIQUE, "attack": ["T1"] * 11}).status_code == 400
