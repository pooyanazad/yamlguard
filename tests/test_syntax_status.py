"""Tests for syntax status accuracy and unvalidated-input handling (I02: T04, T05)."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from yamlguard.models import Severity, ToolAvailability  # noqa: E402
from yamlguard.output import result_to_json  # noqa: E402
from yamlguard.validators import (  # noqa: E402
    BINARY_FILE_RULE,
    ENCODING_ERROR_RULE,
    FILE_NOT_FOUND_RULE,
    PERMISSION_DENIED_RULE,
    READ_ERROR_RULE,
    UNVALIDATED_INPUT_RULES,
    validate_yaml_file,
    validate_yaml_syntax,
)


class TestInformationalSyntaxFindings:
    """T04: empty, comment-only, and null-only documents stay valid and INFO."""

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("empty", ""),
            ("whitespace", "   \n\n"),
            ("comment-only", "# nothing here yet\n"),
        ],
    )
    def test_empty_and_comment_inputs_report_empty_message(self, tmp_path, name, content):
        path = tmp_path / f"{name}.yaml"
        path.write_text(content, encoding="utf-8")

        issues = validate_yaml_syntax(str(path))

        assert len(issues) == 1
        assert issues[0].severity == Severity.INFO
        assert issues[0].rule == "empty-file"
        assert "empty" in issues[0].message.lower()

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("explicit-null", "---\nnull\n"),
            ("bare-null", "null\n"),
            ("tilde-null", "~\n"),
            ("empty-doc-marker", "---\n"),
            ("multi-null-docs", "---\nnull\n---\n~\n"),
        ],
    )
    def test_null_only_inputs_use_accurate_null_message(self, tmp_path, name, content):
        path = tmp_path / f"{name}.yaml"
        path.write_text(content, encoding="utf-8")

        issues = validate_yaml_syntax(str(path))

        assert len(issues) == 1
        assert issues[0].severity == Severity.INFO
        assert issues[0].rule == "empty-file"
        assert "null" in issues[0].message.lower()
        assert "whitespace/comments" not in issues[0].message.lower()

    @pytest.mark.parametrize(
        "content",
        ["", "# comment only\n", "---\nnull\n", "~\n"],
    )
    def test_informational_inputs_stay_syntactically_valid_in_text_and_json(
        self, tmp_path, capsys, content
    ):
        path = tmp_path / "doc.yaml"
        path.write_text(content, encoding="utf-8")

        with patch("yamlguard.validators.run_yamllint", return_value=[]):
            result = validate_yaml_file(str(path), ToolAvailability(checkov=False), quiet=False)

        out = capsys.readouterr().out
        assert result.syntax_valid is True
        assert result.summary["critical"] == 0
        assert result.summary["info"] == 1
        assert "Syntax validation passed" in out
        assert "Syntax validation failed" not in out

        payload = result_to_json(result)
        assert payload["syntax_valid"] is True
        assert payload["issues"][0]["severity"] == "INFO"

    def test_malformed_yaml_differs_in_text_and_json(self, tmp_path, capsys):
        bad = tmp_path / "broken.yaml"
        bad.write_text("key: [unclosed\n", encoding="utf-8")

        with patch("yamlguard.validators.run_yamllint", return_value=[]):
            result = validate_yaml_file(str(bad), ToolAvailability(checkov=False), quiet=False)

        out = capsys.readouterr().out
        assert result.syntax_valid is False
        assert result.summary["critical"] == 1
        assert "Syntax validation failed" in out
        assert "Syntax validation passed" not in out

        payload = json.loads(json.dumps(result_to_json(result)))
        assert payload["syntax_valid"] is False
        assert payload["issues"][0]["severity"] == "CRITICAL"


class TestUnvalidatedInputSyntax:
    """T05: unreadable, undecodable, and binary inputs produce critical unvalidated-input issues."""

    def test_missing_file_uses_unvalidated_rule(self, tmp_path):
        issues = validate_yaml_syntax(str(tmp_path / "missing.yaml"))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == FILE_NOT_FOUND_RULE
        assert issues[0].rule in UNVALIDATED_INPUT_RULES

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses permission checks")
    def test_permission_denied_uses_unvalidated_rule(self, tmp_path):
        locked = tmp_path / "locked.yaml"
        locked.write_text("key: value\n", encoding="utf-8")
        locked.chmod(0o000)
        try:
            issues = validate_yaml_syntax(str(locked))
            assert len(issues) == 1
            assert issues[0].severity == Severity.CRITICAL
            assert issues[0].rule == PERMISSION_DENIED_RULE
            assert issues[0].rule in UNVALIDATED_INPUT_RULES
        finally:
            locked.chmod(0o644)

    def test_directory_read_error_uses_unvalidated_rule(self, tmp_path):
        issues = validate_yaml_syntax(str(tmp_path))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == READ_ERROR_RULE
        assert issues[0].rule in UNVALIDATED_INPUT_RULES

    def test_invalid_utf8_is_critical_encoding_error(self, tmp_path):
        bad = tmp_path / "latin1.yaml"
        bad.write_bytes(b"key: \xff\xfe\n")
        issues = validate_yaml_syntax(str(bad))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == ENCODING_ERROR_RULE
        assert "utf-8" in issues[0].message.lower()

    def test_binary_null_byte_is_critical(self, tmp_path):
        bin_file = tmp_path / "blob.yaml"
        bin_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00IHDR")
        issues = validate_yaml_syntax(str(bin_file))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == BINARY_FILE_RULE

    def test_binary_null_byte_past_initial_chunk_is_critical(self, tmp_path):
        bin_file = tmp_path / "late_null.yaml"
        bin_file.write_bytes(b"a: 1\n" * 2000 + b"\x00trailing")
        issues = validate_yaml_syntax(str(bin_file))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == BINARY_FILE_RULE

    def test_control_character_reader_error_is_unvalidated_input(self, tmp_path):
        ctrl_file = tmp_path / "ctrl.yaml"
        ctrl_file.write_bytes(b"\x01key: value\n")
        issues = validate_yaml_syntax(str(ctrl_file))
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule == ENCODING_ERROR_RULE
        assert issues[0].rule in UNVALIDATED_INPUT_RULES
