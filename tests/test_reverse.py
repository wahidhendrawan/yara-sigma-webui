"""Tests for Sigma-to-YARA reverse conversion."""

import pytest

from yar2sig.sig2yar import (
    SigmaConversionError,
    convert_sigma_text,
    convert_sigma_to_yara,
)


def test_basic_sigma_rule_converts():
    sigma = {
        "title": "Suspicious Process",
        "description": "Test rule",
        "detection": {
            "selection": {"CommandLine": "powershell.exe"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "rule Suspicious_Process" in yara_text
    assert 'description = "Test rule"' in yara_text
    assert "$s_selection_1" in yara_text
    assert '"powershell.exe"' in yara_text
    # Modifiers may be in any order
    assert ("nocase" in yara_text and "ascii" in yara_text and "wide" in yara_text)
    assert "condition:" in yara_text
    assert len(report) > 0


def test_multiple_values_in_selection():
    sigma = {
        "title": "MultiPattern",
        "detection": {
            "selection": {"Image": ["cmd.exe", "powershell.exe"]},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "$s_selection_1" in yara_text
    assert "$s_selection_2" in yara_text
    assert '"cmd.exe"' in yara_text
    assert '"powershell.exe"' in yara_text


def test_wildcard_converted_to_regex():
    sigma = {
        "title": "WildcardTest",
        "detection": {
            "selection": {"CommandLine": "*.exe *suspicious*"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "= /" in yara_text  # regex pattern
    assert any("wildcard" in msg.lower() for msg in report)


def test_regex_modifier_preserved():
    sigma = {
        "title": "RegexTest",
        "detection": {
            "selection": {"CommandLine|re": r"powershell\.exe\s+-enc"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "= /" in yara_text
    assert r"powershell\.exe\s+-enc" in yara_text or r"powershell\\.exe\\s+-enc" in yara_text


def test_condition_all_of():
    sigma = {
        "title": "AllCondition",
        "detection": {
            "sel1": {"Image": "cmd.exe"},
            "sel2": {"CommandLine": "-enc"},
            "condition": "all of them",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "$s_sel1_1" in yara_text
    assert "$s_sel2_2" in yara_text
    assert "($s_sel1_1 and $s_sel2_2)" in yara_text or "($s_sel2_2 and $s_sel1_1)" in yara_text


def test_condition_any_of():
    sigma = {
        "title": "AnyCondition",
        "detection": {
            "sel1": {"Image": "cmd.exe"},
            "sel2": {"Image": "powershell.exe"},
            "condition": "sel1 or sel2",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "$s_sel1_1" in yara_text
    assert "$s_sel2_2" in yara_text
    assert " or " in yara_text


def test_reserved_keyword_identifier_sanitized():
    sigma = {
        "title": "rule",  # reserved keyword
        "detection": {
            "condition": {"CommandLine": "test"},
            "condition": "condition",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "rule rule_rule" in yara_text or "rule _rule" in yara_text


def test_special_characters_escaped():
    sigma = {
        "title": "EscapeTest",
        "detection": {
            "selection": {"CommandLine": 'test"quote\\backslash\n\r\t'},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert r'\"' in yara_text
    assert r'\\' in yara_text
    assert r'\n' in yara_text
    assert r'\r' in yara_text
    assert r'\t' in yara_text


def test_non_string_value_converted_with_warning():
    sigma = {
        "title": "NonString",
        "detection": {
            "selection": {"EventID": 4688},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert '"4688"' in yara_text
    assert any("non-string" in msg.lower() for msg in report)


def test_nested_dict_skipped_with_warning():
    sigma = {
        "title": "NestedDict",
        "detection": {
            "selection": {"field": {"nested": "value"}},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert any("nested" in msg.lower() or "skipped" in msg.lower() for msg in report)


def test_null_value_skipped():
    sigma = {
        "title": "NullTest",
        "detection": {
            "selection": {"field": None},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert any("null" in msg.lower() for msg in report)


def test_pattern_limit_enforced():
    sigma = {
        "title": "LimitTest",
        "detection": {
            "selection": {"field": [f"value{i}" for i in range(15)]},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma, max_patterns=10)
    # Count only strings: section declarations (10 patterns in strings section)
    strings_section = yara_text.split("strings:")[1].split("condition:")[0]
    assert strings_section.count("$s_selection_") == 10
    assert any("limit" in msg.lower() for msg in report)


def test_pattern_length_limit_enforced():
    long_value = "A" * 10001
    sigma = {
        "title": "LengthTest",
        "detection": {
            "selection": {"field": long_value},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma, max_pattern_length=100)
    assert any("exceeds" in msg.lower() or "skipped" in msg.lower() for msg in report)


def test_metadata_fields_populated():
    sigma = {
        "title": "MetadataTest",
        "id": "12345678-1234-1234-1234-123456789012",
        "status": "experimental",
        "description": "Test description",
        "author": "Test Author",
        "date": "2024/01/01",
        "level": "high",
        "references": ["https://example.com/ref1", "https://example.com/ref2"],
        "detection": {
            "selection": {"field": "value"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert 'description = "Test description"' in yara_text
    assert 'author = "Test Author"' in yara_text
    assert 'sigma_id = "12345678-1234-1234-1234-123456789012"' in yara_text
    assert 'sigma_status = "experimental"' in yara_text
    assert 'sigma_level = "high"' in yara_text
    assert "reference_1" in yara_text
    assert "reference_2" in yara_text


def test_comments_can_be_disabled():
    sigma = {
        "title": "CommentTest",
        "detection": {
            "selection": {"field": "value"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma, include_comments=False)
    assert "/*" not in yara_text
    assert "*/" not in yara_text
    assert len(report) > 0  # report still generated


def test_multiple_documents_in_yaml():
    yaml_text = """---
title: Rule1
detection:
  selection:
    field: value1
  condition: selection
---
title: Rule2
detection:
  selection:
    field: value2
  condition: selection
"""
    results = convert_sigma_text(yaml_text)
    assert len(results) == 2
    assert "rule Rule1" in results[0][0]
    assert "rule Rule2" in results[1][0]
    assert '"value1"' in results[0][0]
    assert '"value2"' in results[1][0]


def test_invalid_yaml_raises_error():
    with pytest.raises(SigmaConversionError, match="Invalid.*YAML"):
        convert_sigma_text("{ invalid yaml: [")


def test_non_dict_rule_raises_error():
    with pytest.raises(SigmaConversionError, match="must be a mapping"):
        convert_sigma_to_yara([1, 2, 3])


def test_missing_detection_raises_error():
    with pytest.raises(SigmaConversionError, match="detection"):
        convert_sigma_to_yara({"title": "NoDetection"})


def test_no_usable_patterns_warns():
    sigma = {
        "title": "EmptyRule",
        "detection": {
            "selection": {"field": None},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "condition:" in yara_text
    assert "false" in yara_text
    assert any("no" in msg.lower() and "pattern" in msg.lower() for msg in report)


def test_cased_modifier_removes_nocase():
    sigma = {
        "title": "CaseSensitive",
        "detection": {
            "selection": {"field|cased": "Value"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "nocase" not in yara_text or yara_text.count("nocase") == 0


def test_utf16_modifier_adds_wide():
    sigma = {
        "title": "UTF16Test",
        "detection": {
            "selection": {"field|utf16": "value"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "wide" in yara_text


def test_unsupported_modifier_skips_value():
    sigma = {
        "title": "UnsupportedModifier",
        "detection": {
            "selection": {"field|cidr": "10.0.0.0/8"},
            "condition": "selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert any("cidr" in msg.lower() and "skipped" in msg.lower() for msg in report)


def test_complex_boolean_condition():
    sigma = {
        "title": "ComplexCondition",
        "detection": {
            "sel1": {"Image": "cmd.exe"},
            "sel2": {"CommandLine": "-enc"},
            "sel3": {"User": "admin"},
            "condition": "(sel1 and sel2) or sel3",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert "$s_sel1_1" in yara_text
    assert "$s_sel2_2" in yara_text
    assert "$s_sel3_3" in yara_text
    # Should preserve boolean structure
    assert "and" in yara_text and "or" in yara_text


def test_negation_not_supported():
    sigma = {
        "title": "NegationTest",
        "detection": {
            "selection": {"Image": "cmd.exe"},
            "condition": "not selection",
        },
    }
    yara_text, report = convert_sigma_to_yara(sigma)
    assert any("negation" in msg.lower() or "not" in msg.lower() for msg in report)


def test_empty_yaml_raises_error():
    with pytest.raises(SigmaConversionError, match="no rule"):
        convert_sigma_text("")


def test_non_string_yaml_input_raises_error():
    with pytest.raises(SigmaConversionError, match="must be text"):
        convert_sigma_text(123)


def test_max_patterns_validation():
    sigma = {"title": "T", "detection": {"s": {"f": "v"}, "condition": "s"}}
    with pytest.raises(SigmaConversionError, match="positive integer"):
        convert_sigma_to_yara(sigma, max_patterns=0)


def test_max_pattern_length_validation():
    sigma = {"title": "T", "detection": {"s": {"f": "v"}, "condition": "s"}}
    with pytest.raises(SigmaConversionError, match="positive integer"):
        convert_sigma_to_yara(sigma, max_pattern_length=-1)


def test_convert_sigma_file_reads_disk(tmp_path):
    from yar2sig.sig2yar import convert_sigma_file

    source = tmp_path / "rule.yml"
    source.write_text(
        "title: FileTest\n"
        "detection:\n"
        "  selection:\n"
        "    Image: cmd.exe\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    results = convert_sigma_file(source)
    assert len(results) == 1
    yara_text, _report = results[0]
    assert "rule FileTest" in yara_text
    assert '"cmd.exe"' in yara_text


def test_convert_sigma_file_missing_path_raises(tmp_path):
    from yar2sig.sig2yar import convert_sigma_file

    with pytest.raises(SigmaConversionError, match="Unable to read"):
        convert_sigma_file(tmp_path / "does-not-exist.yml")


def test_public_api_reexports():
    """The reverse converter must be reachable from the yar2sig package root."""
    import yar2sig

    assert hasattr(yar2sig, "convert_sigma_to_yara")
    assert hasattr(yar2sig, "convert_sigma_text")
    assert hasattr(yar2sig, "convert_sigma_file")
    assert hasattr(yar2sig, "SigmaConversionError")


def test_cli_reverse_writes_yar(tmp_path, capsys):
    from yar2sig.cli import main

    source = tmp_path / "input.yml"
    source.write_text(
        "title: CliTest\n"
        "detection:\n"
        "  selection:\n"
        "    Image: cmd.exe\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    outdir = tmp_path / "out"
    rc = main(["reverse", str(source), "-o", str(outdir)])
    assert rc == 0
    outputs = list(outdir.glob("*.yar"))
    assert len(outputs) == 1
    body = outputs[0].read_text(encoding="utf-8")
    assert "rule CliTest" in body
    assert '"cmd.exe"' in body


def test_cli_reverse_stdout_default(tmp_path, capsys):
    from yar2sig.cli import main

    source = tmp_path / "input.yml"
    source.write_text(
        "title: StdoutTest\n"
        "detection:\n"
        "  s:\n"
        "    Image: notepad.exe\n"
        "  condition: s\n",
        encoding="utf-8",
    )
    rc = main(["reverse", str(source)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "rule StdoutTest" in out
    assert '"notepad.exe"' in out


def test_cli_reverse_json_format(tmp_path, capsys):
    import json as _json
    from yar2sig.cli import main

    source = tmp_path / "input.yml"
    source.write_text(
        "title: JsonTest\n"
        "detection:\n"
        "  s:\n"
        "    Image: chrome.exe\n"
        "  condition: s\n",
        encoding="utf-8",
    )
    rc = main(["reverse", str(source), "--format", "json"])
    assert rc == 0
    envelope = _json.loads(capsys.readouterr().out)
    assert envelope["schema_version"] == "1.0"
    assert envelope["direction"] == "sigma-to-yara"
    assert len(envelope["results"]) == 1
    assert "rule JsonTest" in envelope["results"][0]["yara"]
    assert isinstance(envelope["results"][0]["report"], list)


def test_cli_reverse_invalid_input_returns_error(tmp_path, capsys):
    from yar2sig.cli import main

    source = tmp_path / "bad.yml"
    source.write_text("{ this: is: not: valid: yaml", encoding="utf-8")
    rc = main(["reverse", str(source)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "bad.yml" in err


def test_cli_reverse_directory_processes_all_files(tmp_path):
    from yar2sig.cli import main

    (tmp_path / "one.yml").write_text(
        "title: One\ndetection:\n  s:\n    F: a\n  condition: s\n",
        encoding="utf-8",
    )
    (tmp_path / "two.yaml").write_text(
        "title: Two\ndetection:\n  s:\n    F: b\n  condition: s\n",
        encoding="utf-8",
    )
    outdir = tmp_path / "out"
    rc = main(["reverse", str(tmp_path), "-o", str(outdir), "--no-progress"])
    assert rc == 0
    yars = sorted(outdir.glob("*.yar"))
    assert [p.name for p in yars] == ["one.yar", "two.yar"]
