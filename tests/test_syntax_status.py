"""Tests for syntax status accuracy and unvalidated-input handling (I02: T04, T05)."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from yamlguard.models import Severity, ToolAvailability  # noqa: E402
from yamlguard.output import result_to_json  # noqa: E402
from yamlguard.validators import validate_yaml_file, validate_yaml_syntax  # noqa: E402


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
