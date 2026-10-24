"""Tests for per-tool execution status (T03)."""

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from yamlguard.models import (  # noqa: E402
    Severity,
    ToolAvailability,
    ToolExecution,
    ToolStatus,
    ValidationIssue,
    ValidationResult,
)
from yamlguard.output import results_to_junit  # noqa: E402
from yamlguard.validators import validate_yaml_file  # noqa: E402

ROOT = Path(__file__).parent.parent


def _result(issues, tool_status=None, path="config.yaml"):
    summary = {s.name.lower(): 0 for s in Severity}
    summary["total"] = len(issues)
    return ValidationResult(
        file_path=path,
        syntax_valid=True,
        issues=issues,
        summary=summary,
        tool_status=tool_status or [],
    )


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "app.py", *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


class TestToolStatusModel:
    def test_defaults_keep_existing_callers_working(self):
        result = ValidationResult("a.yaml", True, [], {"total": 0})
        assert result.tool_status == []
        assert result.has_operational_failure is False

    def test_failed_status_is_detected(self):
        result = _result([], [ToolExecution("yamllint", ToolStatus.FAILED, "boom")])
        assert result.has_operational_failure is True

    def test_skipped_status_is_not_a_failure(self):
        result = _result([], [ToolExecution("checkov", ToolStatus.SKIPPED, "disabled")])
        assert result.has_operational_failure is False


class TestValidateYamlFileStatus:
    def test_clean_run_reports_completed_tools(self, clean_file, monkeypatch):
        monkeypatch.setattr("yamlguard.validators.run_checkov", lambda *a, **k: [])
        result = validate_yaml_file(clean_file, ToolAvailability(), quiet=True)
        statuses = {e.tool: e.status for e in result.tool_status}
        assert statuses["yamllint"] is ToolStatus.COMPLETED
        assert statuses["checkov"] is ToolStatus.COMPLETED

    def test_no_security_reports_skip_with_reason(self, clean_file):
        result = validate_yaml_file(clean_file, ToolAvailability(), no_security=True, quiet=True)
        checkov = next(e for e in result.tool_status if e.tool == "checkov")
        assert checkov.status is ToolStatus.SKIPPED
        assert "disabled" in checkov.reason

    def test_unavailable_checkov_reports_skip_with_reason(self, clean_file):
        result = validate_yaml_file(clean_file, ToolAvailability(checkov=False), quiet=True)
        checkov = next(e for e in result.tool_status if e.tool == "checkov")
        assert checkov.status is ToolStatus.SKIPPED
        assert "not available" in checkov.reason

    @patch("yamlguard.validators.run_yamllint")
    def test_crash_reports_failed_with_reason(self, mock_lint, clean_file):
        mock_lint.return_value = [
            ValidationIssue(
                "yamllint",
                Severity.HIGH,
                "yamllint execution failed with exit code 2",
                rule="operational-error",
            )
        ]
        result = validate_yaml_file(clean_file, ToolAvailability(), no_security=True, quiet=True)
        lint = next(e for e in result.tool_status if e.tool == "yamllint")
        assert lint.status is ToolStatus.FAILED
        assert "exit code 2" in lint.reason
        assert result.has_operational_failure is True

    @patch("yamlguard.validators.run_yamllint")
    def test_timeout_reports_failed(self, mock_lint, clean_file):
        mock_lint.return_value = [
            ValidationIssue(
                "yamllint",
                Severity.HIGH,
                "yamllint execution timed out after 300 seconds.",
                rule="operational-error",
            )
        ]
        result = validate_yaml_file(clean_file, ToolAvailability(), no_security=True, quiet=True)
        lint = next(e for e in result.tool_status if e.tool == "yamllint")
        assert lint.status is ToolStatus.FAILED
        assert "timed out" in lint.reason


class TestJunitOperationalErrors:
    def test_failed_tool_becomes_error_element(self):
        result = _result([], [ToolExecution("yamllint", ToolStatus.FAILED, "exit code 2")])
        root = ET.fromstring(results_to_junit([result]))
        suite = root.find("testsuite")
        assert suite.get("errors") == "1"
        assert suite.get("failures") == "0"
        error = suite.find("testcase/error")
        assert error is not None
        assert error.get("message") == "exit code 2"

    def test_skipped_tool_does_not_create_error(self):
        result = _result([], [ToolExecution("checkov", ToolStatus.SKIPPED, "disabled")])
        root = ET.fromstring(results_to_junit([result]))
        assert root.get("errors") == "0"
        assert root.find("testsuite/testcase/error") is None

    def test_clean_completion_has_no_error(self):
        result = _result([], [ToolExecution("yamllint", ToolStatus.COMPLETED)])
        root = ET.fromstring(results_to_junit([result]))
        assert root.get("errors") == "0"


class TestCliOperationalFailure:
    """The CLI must fail when a tool did not complete, even with zero findings."""

    def _run_main(self, monkeypatch, argv, result):
        from yamlguard import cli

        monkeypatch.setattr(sys, "argv", ["yamlguard", *argv])
        monkeypatch.setattr(cli, "validate_yaml_file", lambda *a, **k: result)
        monkeypatch.setattr(cli, "check_dependencies", ToolAvailability)
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        return excinfo.value.code

    def test_operational_failure_exits_nonzero(self, monkeypatch, clean_file, capsys):
        code = self._run_main(
            monkeypatch,
            ["--no-security", clean_file],
            _result([], [ToolExecution("yamllint", ToolStatus.FAILED, "exit code 2")]),
        )
        assert code == 1
        assert "incomplete" in capsys.readouterr().out.lower()

    def test_operational_failure_exits_nonzero_in_json_mode(self, monkeypatch, clean_file, capsys):
        code = self._run_main(
            monkeypatch,
            ["--no-security", "-f", "json", clean_file],
            _result([], [ToolExecution("yamllint", ToolStatus.FAILED, "exit code 2")]),
        )
        assert code == 1
        assert capsys.readouterr().out.lstrip().startswith(("{", "["))

    def test_skipped_tool_still_exits_zero(self, monkeypatch, clean_file):
        code = self._run_main(
            monkeypatch,
            ["--no-security", clean_file],
            _result([], [ToolExecution("checkov", ToolStatus.SKIPPED, "disabled")]),
        )
        assert code == 0

    def test_text_output_shows_tool_status(self, clean_file):
        proc = _run_cli("--no-security", clean_file)
        assert "Tool status" in proc.stdout
        assert "skipped" in proc.stdout
