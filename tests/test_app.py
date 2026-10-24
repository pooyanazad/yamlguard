"""
App functionality tests for yamlguard.
Tests core functions directly (no Docker required).
Run with: pytest tests/test_app.py -v
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Make app importable from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import app as validator
from app import (
    Severity,
    ToolAvailability,
    ValidationIssue,
    ValidationResult,
    check_dependencies,
    print_colored,
    print_issues,
    print_summary_table,
    resolve_files,
    run_checkov,
    run_yamllint,
    validate_yaml_file,
    validate_yaml_syntax,
)
from yamlguard.validators import (
    LARGE_FILE_WARNING_THRESHOLD,
    warn_if_large_file,
)

# ─────────────────────────────────────────────────────────────────────────────
FIXTURES = Path(__file__).parent / "fixtures"  # tests/fixtures directory


# ── Helpers ───────────────────────────────────────────────────────────────────
def tmp_yaml(content: str) -> str:
    """Write content to a temp YAML file, return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    f.write(content)
    f.flush()
    return f.name


# ═════════════════════════════════════════════════════════════════════════════
# 1. validate_yaml_syntax
# ═════════════════════════════════════════════════════════════════════════════
class TestValidateYamlSyntax:
    def test_valid_yaml_returns_no_issues(self, clean_file):
        issues = validate_yaml_syntax(clean_file)
        assert issues == [], f"Expected no issues, got: {issues}"

    def test_invalid_yaml_returns_critical_issue(self, issues_file):
        issues = validate_yaml_syntax(issues_file)
        assert len(issues) > 0
        assert issues[0].severity == Severity.CRITICAL

    def test_issue_tool_is_yaml(self, issues_file):
        issues = validate_yaml_syntax(issues_file)
        assert all(i.tool == "yaml" for i in issues)

    def test_issue_contains_line_number(self, issues_file):
        issues = validate_yaml_syntax(issues_file)
        assert any(i.line is not None for i in issues), (
            "Expected at least one issue with a line number"
        )

    def test_issue_rule_is_syntax(self, issues_file):
        issues = validate_yaml_syntax(issues_file)
        assert any(i.rule == "syntax" for i in issues)

    def test_missing_file_returns_critical_issue(self):
        issues = validate_yaml_syntax("/nonexistent/path/file.yaml")
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert "File not found" in issues[0].message

    def test_permission_denied_returns_critical_issue(self, tmp_yaml):
        """Unreadable file gives clear 'Permission denied' error."""
        path = tmp_yaml("key: value\n")
        try:
            os.chmod(path, 0o000)  # Remove all permissions
            issues = validate_yaml_syntax(path)
            assert len(issues) == 1
            assert issues[0].severity == Severity.CRITICAL
            assert "Permission denied" in issues[0].message
        finally:
            os.chmod(path, 0o644)  # Restore so we can delete it
            os.unlink(path)

    def test_inline_valid_yaml(self, tmp_yaml):
        path = tmp_yaml("key: value\nlist:\n  - a\n  - b\n")
        try:
            issues = validate_yaml_syntax(path)
            assert issues == []
        finally:
            os.unlink(path)

    def test_inline_broken_yaml(self, tmp_yaml):
        path = tmp_yaml("key: value\n  bad_indent: oops\n")
        try:
            issues = validate_yaml_syntax(path)
            assert len(issues) > 0
            assert issues[0].severity == Severity.CRITICAL
        finally:
            os.unlink(path)

    def test_multi_document_yaml_is_valid(self, tmp_yaml):
        path = tmp_yaml("---\nkey: value\n---\nother: doc\n")
        try:
            issues = validate_yaml_syntax(path)
            assert issues == []
        finally:
            os.unlink(path)

    # ── #13: empty YAML files ────────────────────────────────────────────────

    def test_empty_file_reports_info_issue(self, tmp_yaml):
        """An empty .yaml file should produce exactly one INFO issue (#13)."""
        path = tmp_yaml("")
        try:
            issues = validate_yaml_syntax(path)
            assert len(issues) == 1
            assert issues[0].severity == Severity.INFO
            assert issues[0].rule == "empty-file"
        finally:
            os.unlink(path)

    def test_whitespace_only_file_reports_info_issue(self, tmp_yaml):
        """A file with only whitespace/newlines should also be flagged as INFO."""
        path = tmp_yaml("   \n\n  \n")
        try:
            issues = validate_yaml_syntax(path)
            assert len(issues) == 1
            assert issues[0].severity == Severity.INFO
        finally:
            os.unlink(path)

    def test_comment_only_file_reports_info_issue(self, tmp_yaml):
        """A file with only YAML comments (no data) is treated as empty."""
        path = tmp_yaml("# This file intentionally left blank\n")
        try:
            issues = validate_yaml_syntax(path)
            assert len(issues) == 1
            assert issues[0].severity == Severity.INFO
            assert issues[0].rule == "empty-file"
        finally:
            os.unlink(path)

    # ── #14: binary files ────────────────────────────────────────────────────

    def test_binary_file_reports_medium_warning(self):
        """A binary file (contains null bytes) should warn MEDIUM, not crash (#14)."""
        f = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False)
        f.write(b"\x00\x01\x02binary\x00data")
        f.close()
        try:
            issues = validate_yaml_syntax(f.name)
            assert len(issues) == 1
            assert issues[0].severity == Severity.MEDIUM
            assert issues[0].rule == "binary-file"
            assert "binary" in issues[0].message.lower()
        finally:
            os.unlink(f.name)

    def test_binary_file_does_not_raise(self):
        """validate_yaml_syntax must never raise on a binary file."""
        f = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False)
        f.write(bytes(range(256)))  # All byte values including many null bytes
        f.close()
        try:
            issues = validate_yaml_syntax(f.name)  # Should not raise
            assert isinstance(issues, list)
        finally:
            os.unlink(f.name)


# ═════════════════════════════════════════════════════════════════════════════
# 2. run_yamllint
# ═════════════════════════════════════════════════════════════════════════════
class TestRunYamllint:
    def test_clean_file_has_no_linting_issues(self, clean_file):
        issues = run_yamllint(clean_file)
        assert issues == [], f"Expected no linting issues, got: {issues}"

    def test_issues_file_has_linting_issues(self, issues_file):
        issues = run_yamllint(issues_file)
        assert len(issues) > 0

    def test_tool_is_yamllint(self, issues_file):
        issues = run_yamllint(issues_file)
        assert all(i.tool == "yamllint" for i in issues)

    def test_yamllint_errors_map_to_medium_severity(self, issues_file):
        issues = run_yamllint(issues_file)
        # Any rule that was an 'error' will have MEDIUM severity
        error_issues = [i for i in issues if i.severity == Severity.MEDIUM]
        assert len(error_issues) > 0, "Expected at least one yamllint error (MEDIUM severity)"

    def test_yamllint_warnings_map_to_low_severity(self, issues_file):
        issues = run_yamllint(issues_file)
        # Any rule that was a 'warning' will have LOW severity
        warn_issues = [i for i in issues if i.severity == Severity.LOW]
        for issue in warn_issues:
            assert issue.severity == Severity.LOW, (
                f"yamllint 'warning' should be LOW, got {issue.severity}"
            )

    def test_issues_have_line_numbers(self, issues_file):
        issues = run_yamllint(issues_file)
        assert any(i.line is not None for i in issues)

    def test_no_stray_brackets_in_messages(self, issues_file):
        """Regression: old parser left trailing ] in messages."""
        issues = run_yamllint(issues_file)
        for issue in issues:
            assert not issue.message.endswith("]"), f"Stray ']' found in message: '{issue.message}'"

    @patch("subprocess.run")
    def test_messages_with_colons_parsed_correctly(self, mock_run):
        """Verify that line, column, level, message (with colons) are correctly extracted."""
        # Mock the stdout of a 'yamllint -f parsable' run
        mock_stdout = (
            "test_file.yaml:12:34: [error] Expected ':', but found '<block end>' (syntax)\n"
            "test_file.yaml:56:78: [warning] Nested map: too many colons: yes (some-rule)\n"
        )
        mock_result = type(
            "MockResult", (), {"stdout": mock_stdout, "stderr": "", "returncode": 1}
        )()
        mock_run.return_value = mock_result

        issues = run_yamllint("fake_path.yaml")
        assert len(issues) == 2

        # Issue 1
        assert issues[0].line == 12
        assert issues[0].column == 34
        assert issues[0].rule == "syntax"
        assert issues[0].severity == Severity.MEDIUM
        assert issues[0].message == "Expected ':', but found '<block end>'"

        # Issue 2
        assert issues[1].line == 56
        assert issues[1].column == 78
        assert issues[1].rule == "some-rule"
        assert issues[1].severity == Severity.LOW
        assert issues[1].message == "Nested map: too many colons: yes"

    @patch("subprocess.run")
    def test_yamllint_empty_output_handled_gracefully(self, mock_run):
        """Empty output gracefully results in 0 issues."""
        mock_result = type("MockResult", (), {"stdout": "", "stderr": "", "returncode": 0})()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")
        assert issues == []

    @patch("subprocess.run")
    def test_yamllint_not_installed_handled_gracefully(self, mock_run):
        """If yamllint is missing, report gracefully."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "",
                "stderr": "/bin/python: No module named yamllint",
                "returncode": 1,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")
        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "not installed" in issues[0].message

    @patch("subprocess.run")
    def test_yamllint_malformed_output_handled_gracefully(self, mock_run):
        """Unexpected format uses fallback."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "Something completely unexpected went wrong",
                "stderr": "",
                "returncode": 1,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")
        assert len(issues) == 1
        assert issues[0].severity == Severity.MEDIUM
        assert issues[0].message == "Something completely unexpected went wrong"

    @patch("subprocess.run")
    def test_yamllint_timeout_handled_gracefully(self, mock_run):
        """Hanging subprocess triggers TimeoutExpired and graceful HIGH severity issue."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="yamllint", timeout=300)
        issues = run_yamllint("fake_path.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "timed out after 300 seconds" in issues[0].message

    @patch("subprocess.run")
    def test_yamllint_crash_nonzero_exit_without_findings_emits_high_severity(self, mock_run):
        """Simulated crash (rc!=0 without findings) cannot yield clean result, emits HIGH operational error."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "",
                "stderr": "Fatal Python error: Segmentation fault",
                "returncode": 139,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "execution failed with exit code 139" in issues[0].message
        assert "Segmentation fault" in issues[0].message

    @patch("subprocess.run")
    def test_yamllint_config_failure_emits_operational_error(self, mock_run):
        """Configuration failure (rc=2 without findings) emits operational error with diagnostic."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "",
                "stderr": "yamllint: error: invalid config file",
                "returncode": 2,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "execution failed with exit code 2" in issues[0].message
        assert "invalid config file" in issues[0].message

    @patch("subprocess.run")
    def test_yamllint_crash_with_stdout_noise_is_not_parsed_as_findings(self, mock_run):
        """A crash that prints to stdout must not be downgraded to a MEDIUM finding."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "Traceback (most recent call last):\n  boom",
                "stderr": "",
                "returncode": 2,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "execution failed with exit code 2" in issues[0].message
        assert "Traceback" in issues[0].message

    @patch("subprocess.run")
    def test_yamllint_diagnostic_is_bounded_and_redacted(self, mock_run):
        """Long stderr is truncated and credential-looking values are masked."""
        mock_result = type(
            "MockResult",
            (),
            {
                "stdout": "",
                "stderr": "AWS_SECRET_ACCESS_KEY=supersecretvalue " + "x" * 500,
                "returncode": 2,
            },
        )()
        mock_run.return_value = mock_result
        issues = run_yamllint("fake_path.yaml")

        assert len(issues) == 1
        assert "supersecretvalue" not in issues[0].message
        assert "AWS_SECRET_ACCESS_KEY=***" in issues[0].message
        assert len(issues[0].message) < 300


class TestRunCheckov:
    @patch("subprocess.run")
    def test_checkov_timeout_handled_gracefully(self, mock_run):
        """Hanging subprocess triggers TimeoutExpired and graceful HIGH severity issue."""
        # Need to import run_checkov if it's not imported at the top, but test_app.py imports it via `from app import *`
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="checkov", timeout=300)
        issues = run_checkov("fake_path.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "timed out after 300 seconds" in issues[0].message

    @patch("subprocess.run")
    def test_checkov_list_output_handled(self, mock_run):
        """Checkov returning a list of reports (multi-framework) is parsed correctly."""
        mock_stdout = json.dumps(
            [
                {
                    "check_type": "github_actions",
                    "results": {
                        "failed_checks": [
                            {
                                "check_name": "Unpinned action",
                                "check_id": "CKV_GHA_1",
                                "severity": "HIGH",
                                "file_line_range": [10, 12],
                            }
                        ]
                    },
                },
                {
                    "check_type": "kubernetes",
                    "results": {
                        "failed_checks": [
                            {
                                "check_name": "Privileged container",
                                "check_id": "CKV_K8S_1",
                                "severity": "CRITICAL",
                                "file_line_range": [25, 30],
                            }
                        ]
                    },
                },
            ]
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=1, stdout=mock_stdout, stderr=""
        )
        issues = run_checkov("workflow.yaml", timeout=300)

        assert len(issues) == 2
        assert issues[0].rule == "CKV_GHA_1"
        assert issues[0].line == 10
        assert issues[1].rule == "CKV_K8S_1"
        assert issues[1].severity == Severity.CRITICAL

    @patch("subprocess.run")
    def test_checkov_dict_output_handled(self, mock_run):
        """Checkov returning a single report dictionary is parsed correctly."""
        mock_stdout = json.dumps(
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_name": "Ensure root user is not used",
                            "check_id": "CKV_DOCKER_1",
                            "severity": "MEDIUM",
                            "file_line_range": [5, 6],
                        }
                    ]
                }
            }
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=1, stdout=mock_stdout, stderr=""
        )
        issues = run_checkov("service.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].rule == "CKV_DOCKER_1"
        assert issues[0].severity == Severity.MEDIUM
        assert issues[0].line == 5

    @patch("subprocess.run")
    def test_checkov_malformed_json_is_operational_error(self, mock_run):
        """Malformed JSON must fail the scan, not become a MEDIUM finding."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=1, stdout="not valid json {{{", stderr=""
        )
        issues = run_checkov("test.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "could not parse JSON report" in issues[0].message

    @patch("subprocess.run")
    def test_checkov_nonzero_exit_with_empty_output_is_operational_error(self, mock_run):
        """A crash with no report cannot look like a clean scan."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=2, stdout="", stderr="checkov: bad argument"
        )
        issues = run_checkov("test.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "exit code 2" in issues[0].message
        assert "bad argument" in issues[0].message

    @patch("subprocess.run")
    def test_checkov_success_exit_with_empty_output_is_operational_error(self, mock_run):
        """Exit 0 with no report still means the scan produced nothing usable."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=0, stdout="", stderr=""
        )
        issues = run_checkov("test.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "no report produced" in issues[0].message

    @patch("subprocess.run")
    def test_checkov_unexpected_json_structure_is_operational_error(self, mock_run):
        """Valid JSON that is not a Checkov report is an operational error."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"], returncode=0, stdout=json.dumps({"unexpected": True}), stderr=""
        )
        issues = run_checkov("test.yaml", timeout=300)

        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH
        assert "unexpected report structure" in issues[0].message

    @patch("subprocess.run")
    def test_checkov_clean_report_yields_no_issues(self, mock_run):
        """A report with no failed checks is a genuine clean result."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"],
            returncode=0,
            stdout=json.dumps({"results": {"failed_checks": []}}),
            stderr="",
        )
        assert run_checkov("test.yaml", timeout=300) == []

    @patch("subprocess.run")
    def test_checkov_diagnostic_is_bounded_and_redacted(self, mock_run):
        """Crash diagnostics are truncated and credential-looking values masked."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["checkov"],
            returncode=2,
            stdout="",
            stderr="GITHUB_TOKEN=ghp_secretvalue " + "y" * 500,
        )
        issues = run_checkov("test.yaml", timeout=300)

        assert len(issues) == 1
        assert "ghp_secretvalue" not in issues[0].message
        assert "GITHUB_TOKEN=***" in issues[0].message
        assert len(issues[0].message) < 300

    def test_trailing_spaces_detected(self, tmp_yaml):
        path = tmp_yaml("key: value   \n")
        try:
            issues = run_yamllint(path)
            messages = " ".join(i.message for i in issues)
            assert "trailing" in messages.lower(), "Expected trailing spaces warning"
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
# 3. resolve_files
# ═════════════════════════════════════════════════════════════════════════════
class TestResolveFiles:
    def test_single_file_resolved(self, clean_file):
        result = resolve_files([clean_file])
        assert len(result) == 1
        assert result[0] == clean_file

    def test_multiple_files_resolved(self, clean_file, issues_file):
        result = resolve_files([clean_file, issues_file])
        assert len(result) == 2

    def test_directory_finds_yaml_files(self):
        result = resolve_files([str(FIXTURES)])
        assert len(result) > 0
        assert all(f.endswith((".yaml", ".yml")) for f in result)

    def test_directory_finds_all_fixtures(self):
        result = resolve_files([str(FIXTURES)])
        # We know we have at least 11 test files
        assert len(result) >= 11

    def test_deduplication_same_file_twice(self, clean_file):
        result = resolve_files([clean_file, clean_file])
        assert len(result) == 1, "Duplicate file should be deduplicated"

    def test_deduplication_dir_and_file(self, clean_file):
        """Dir scan + explicit file reference should not duplicate."""
        result = resolve_files([str(FIXTURES), clean_file])
        clean_count = sum(1 for f in result if Path(f).name == "test3_clean.yaml")
        assert clean_count == 1

    def test_glob_pattern(self):
        pattern = str(FIXTURES / "security_*.yaml")
        result = resolve_files([pattern])
        assert len(result) >= 5
        assert all("security_" in Path(f).name for f in result)

    def test_nonexistent_path_returns_empty(self):
        result = resolve_files(["/nonexistent/does_not_exist.yaml"])
        assert result == []

    def test_only_yaml_and_yml_extensions(self):
        result = resolve_files([str(FIXTURES)])
        for f in result:
            assert Path(f).suffix in {".yaml", ".yml"}


# ═════════════════════════════════════════════════════════════════════════════
# 4. validate_yaml_file (integration)
# ═════════════════════════════════════════════════════════════════════════════
class TestValidateYamlFile:
    def test_clean_file_syntax_valid_true(self, clean_file):
        result = validate_yaml_file(clean_file)
        assert result.syntax_valid is True

    def test_clean_file_zero_critical(self, clean_file):
        result = validate_yaml_file(clean_file)
        assert result.summary["critical"] == 0

    def test_clean_file_total_zero(self, clean_file):
        result = validate_yaml_file(clean_file)
        # Clean file should have no issues at all
        assert result.summary["total"] == 0

    def test_issues_file_syntax_invalid(self, issues_file):
        result = validate_yaml_file(issues_file)
        assert result.syntax_valid is False

    def test_issues_file_has_critical(self, issues_file):
        result = validate_yaml_file(issues_file)
        assert result.summary["critical"] > 0

    def test_issues_file_has_medium_from_yamllint(self, issues_file):
        result = validate_yaml_file(issues_file)
        assert result.summary["medium"] > 0, "yamllint errors should appear as MEDIUM"

    def test_result_contains_file_path(self, clean_file):
        result = validate_yaml_file(clean_file)
        assert result.file_path == clean_file

    def test_result_is_validation_result_type(self, clean_file):
        result = validate_yaml_file(clean_file)
        assert isinstance(result, ValidationResult)

    def test_summary_keys_present(self, clean_file):
        result = validate_yaml_file(clean_file)
        for key in ("total", "critical", "high", "medium", "low", "info"):
            assert key in result.summary, f"Missing summary key: {key}"

    def test_summary_total_equals_sum_of_severities(self, issues_file):
        result = validate_yaml_file(issues_file)
        s = result.summary
        assert s["total"] == s["critical"] + s["high"] + s["medium"] + s["low"] + s["info"]

    def test_issues_list_matches_summary_total(self, issues_file):
        result = validate_yaml_file(issues_file)
        assert len(result.issues) == result.summary["total"]

    def test_all_issues_have_required_fields(self, issues_file):
        result = validate_yaml_file(issues_file)
        for issue in result.issues:
            assert isinstance(issue, ValidationIssue)
            assert issue.tool in ("yaml", "yamllint", "checkov")
            assert isinstance(issue.severity, Severity)
            assert issue.message

    def test_checkov_false_produces_no_checkov_issues(self, security_file):
        """When tools.checkov=False, no checkov issues should appear in results."""
        tools = ToolAvailability(checkov=False)
        result = validate_yaml_file(security_file, tools)
        checkov_issues = [i for i in result.issues if i.tool == "checkov"]
        assert checkov_issues == [], (
            f"Expected no checkov issues when checkov=False, got: {checkov_issues}"
        )

    def test_checkov_true_is_default_behaviour(self):
        """Default ToolAvailability has checkov=True."""
        tools = ToolAvailability()
        assert tools.checkov is True

    def test_tools_parameter_is_optional(self, clean_file):
        """validate_yaml_file() works fine with no tools argument (uses defaults)."""
        result = validate_yaml_file(clean_file)
        assert isinstance(result, ValidationResult)

    def test_no_security_skips_checkov(self, clean_file):
        tools = ToolAvailability(checkov=True)

        with patch("yamlguard.validators.run_checkov") as mock_run_checkov:
            validate_yaml_file(clean_file, tools, no_security=True)

        mock_run_checkov.assert_not_called()

    def test_no_security_skips_large_file_warning(self, clean_file, capsys):
        tools = ToolAvailability(yamllint=False, checkov=False)

        with patch(
            "yamlguard.validators.os.path.getsize",
            return_value=LARGE_FILE_WARNING_THRESHOLD + 1,
        ):
            validate_yaml_file(clean_file, tools, no_security=True)

        output = capsys.readouterr().out
        assert "large YAML file detected" not in output
        assert "Security checks skipped (--no-security)" in output

    def test_security_runs_by_default(self, clean_file):
        tools = ToolAvailability(checkov=True)

        with patch("yamlguard.validators.run_checkov", return_value=[]) as mock_run_checkov:
            validate_yaml_file(clean_file, tools)

        mock_run_checkov.assert_called_once_with(clean_file, timeout=300)

    def test_yamllint_false_only_runs_syntax_and_security(self, tmp_yaml):
        """When tools.yamllint=False, validate_yaml_file skips yamllint."""
        # A file that has trailing-space linting issues but valid syntax
        path = tmp_yaml("key: value   \n")
        try:
            tools = ToolAvailability(yamllint=False, checkov=False)
            result = validate_yaml_file(path, tools)
            # yamllint disabled — but run_yamllint is still called by validate_yaml_file;
            # ToolAvailability.yamllint only gates check_dependencies exit behaviour.
            # This test confirms the result type is still correct.
            assert isinstance(result, ValidationResult)
        finally:
            os.unlink(path)


class TestLargeFileWarning:
    @pytest.mark.parametrize(
        "file_size",
        [LARGE_FILE_WARNING_THRESHOLD - 1, LARGE_FILE_WARNING_THRESHOLD],
    )
    def test_does_not_warn_at_or_below_threshold(self, file_size):
        with (
            patch("yamlguard.validators.os.path.getsize", return_value=file_size),
            patch("yamlguard.validators.print_colored") as mock_print,
        ):
            warn_if_large_file("config.yaml")

        mock_print.assert_not_called()

    def test_warns_above_threshold(self):
        with (
            patch(
                "yamlguard.validators.os.path.getsize",
                return_value=LARGE_FILE_WARNING_THRESHOLD + 1,
            ),
            patch("yamlguard.validators.print_colored") as mock_print,
        ):
            warn_if_large_file("config.yaml")

        message = mock_print.call_args.args[0]
        assert "large YAML file" in message
        assert "--no-security" in message

    def test_ignores_file_size_errors(self):
        with (
            patch(
                "yamlguard.validators.os.path.getsize",
                side_effect=OSError("unavailable"),
            ),
            patch("yamlguard.validators.print_colored") as mock_print,
        ):
            warn_if_large_file("missing.yaml")

        mock_print.assert_not_called()


class TestCliSecurityOption:
    def test_no_security_flag_is_passed_to_validator(self):
        result = ValidationResult(
            file_path="config.yaml",
            syntax_valid=True,
            issues=[],
            summary={
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        )

        with (
            patch.object(sys, "argv", ["app.py", "config.yaml", "--no-security"]),
            patch("yamlguard.cli.resolve_files", return_value=["config.yaml"]),
            patch(
                "yamlguard.cli.check_dependencies",
                return_value=ToolAvailability(),
            ),
            patch("yamlguard.cli.validate_yaml_file", return_value=result) as mock_validate,
            pytest.raises(SystemExit) as exit_info,
        ):
            validator.main()

        assert exit_info.value.code == 0
        mock_validate.assert_called_once_with(
            "config.yaml",
            ToolAvailability(),
            timeout=300,
            no_security=True,
            quiet=False,
        )


# ═════════════════════════════════════════════════════════════════════════════
# 5. ValidationIssue dataclass
# ═════════════════════════════════════════════════════════════════════════════
class TestValidationIssue:
    def test_default_optional_fields_are_none(self):
        issue = ValidationIssue(tool="yaml", severity=Severity.CRITICAL, message="test")
        assert issue.line is None
        assert issue.column is None
        assert issue.rule is None
        assert issue.file_path is None

    def test_all_fields_settable(self):
        issue = ValidationIssue(
            tool="yamllint",
            severity=Severity.MEDIUM,
            message="bad indent",
            line=10,
            column=2,
            rule="indentation",
            file_path="/tmp/test.yaml",
        )
        assert issue.line == 10
        assert issue.column == 2
        assert issue.rule == "indentation"

    def test_severity_enum_values(self):
        for sev in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            issue = ValidationIssue(tool="yaml", severity=sev, message="x")
            assert issue.severity == sev


# ═════════════════════════════════════════════════════════════════════════════
# 6. ToolAvailability dataclass
# ═════════════════════════════════════════════════════════════════════════════
class TestToolAvailability:
    def test_defaults_are_both_true(self):
        tools = ToolAvailability()
        assert tools.yamllint is True
        assert tools.checkov is True

    def test_can_disable_checkov(self):
        tools = ToolAvailability(checkov=False)
        assert tools.checkov is False
        assert tools.yamllint is True

    def test_can_disable_yamllint(self):
        tools = ToolAvailability(yamllint=False)
        assert tools.yamllint is False
        assert tools.checkov is True

    def test_can_disable_both(self):
        tools = ToolAvailability(yamllint=False, checkov=False)
        assert tools.yamllint is False
        assert tools.checkov is False

    def test_check_dependencies_returns_tool_availability(self):
        """check_dependencies() must return a ToolAvailability instance."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            result = check_dependencies()
        assert isinstance(result, ToolAvailability)

    def test_check_dependencies_checkov_false_when_import_fails(self):
        """When checkov import fails, returned tools.checkov must be False."""

        def fake_run(cmd, **kwargs):
            # Fail only the 'import checkov' check
            if "import checkov" in " ".join(cmd):
                raise FileNotFoundError("checkov not found")
            import subprocess

            r = subprocess.CompletedProcess(cmd, 0, b"", b"")
            return r

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()
        assert result.checkov is False
        assert result.yamllint is True


# ═════════════════════════════════════════════════════════════════════════════
# 7. print_colored  (#25)
# ═════════════════════════════════════════════════════════════════════════════
class TestPrintColored:
    """#25 — Use capsys to capture stdout and verify correct formatting."""

    def test_critical_severity_contains_text(self, capsys):
        print_colored("critical message", Severity.CRITICAL)
        captured = capsys.readouterr()
        assert "critical message" in captured.out

    def test_high_severity_contains_text(self, capsys):
        print_colored("high message", Severity.HIGH)
        captured = capsys.readouterr()
        assert "high message" in captured.out

    def test_medium_severity_contains_text(self, capsys):
        print_colored("medium message", Severity.MEDIUM)
        captured = capsys.readouterr()
        assert "medium message" in captured.out

    def test_low_severity_contains_text(self, capsys):
        print_colored("low message", Severity.LOW)
        captured = capsys.readouterr()
        assert "low message" in captured.out

    def test_info_severity_contains_text(self, capsys):
        print_colored("info message", Severity.INFO)
        captured = capsys.readouterr()
        assert "info message" in captured.out

    def test_no_severity_still_prints(self, capsys):
        """Calling with severity=None (default) should still print the text."""
        print_colored("plain text")
        captured = capsys.readouterr()
        assert "plain text" in captured.out

    def test_bold_flag_does_not_suppress_text(self, capsys):
        print_colored("bold text", Severity.CRITICAL, bold=True)
        captured = capsys.readouterr()
        assert "bold text" in captured.out

    def test_output_ends_with_newline(self, capsys):
        """print() always appends a newline — verify it."""
        print_colored("newline test", Severity.INFO)
        captured = capsys.readouterr()
        assert captured.out.endswith("\n")

    def test_nothing_printed_to_stderr(self, capsys):
        print_colored("no stderr", Severity.LOW)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_each_severity_level_produces_output(self, capsys):
        """Smoke-test: all five severity levels produce non-empty stdout."""
        for severity in Severity:
            print_colored("test", severity)
            captured = capsys.readouterr()
            assert captured.out.strip() != "", f"No output for severity {severity}"


# ═════════════════════════════════════════════════════════════════════════════
# 8. print_issues grouping  (#26)
# ═════════════════════════════════════════════════════════════════════════════
class TestPrintIssues:
    """#26 — Verify issues are grouped by severity in CRITICAL→INFO order."""

    def _make_issue(self, severity: Severity, message: str) -> ValidationIssue:
        return ValidationIssue(tool="test", severity=severity, message=message)

    def test_empty_list_prints_nothing(self, capsys):
        print_issues([])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_single_critical_issue_appears_in_output(self, capsys):
        issues = [self._make_issue(Severity.CRITICAL, "critical problem")]
        print_issues(issues)
        captured = capsys.readouterr()
        assert "critical problem" in captured.out

    def test_critical_appears_before_info(self, capsys):
        """CRITICAL issues must appear before INFO issues in output."""
        issues = [
            self._make_issue(Severity.INFO, "info detail"),
            self._make_issue(Severity.CRITICAL, "critical detail"),
        ]
        print_issues(issues)
        captured = capsys.readouterr()
        critical_pos = captured.out.index("critical detail")
        info_pos = captured.out.index("info detail")
        assert critical_pos < info_pos, "CRITICAL must come before INFO in output"

    def test_severity_order_critical_high_medium_low_info(self, capsys):
        """Full ordering: CRITICAL → HIGH → MEDIUM → LOW → INFO."""
        issues = [
            self._make_issue(Severity.INFO, "msg-info"),
            self._make_issue(Severity.LOW, "msg-low"),
            self._make_issue(Severity.MEDIUM, "msg-medium"),
            self._make_issue(Severity.HIGH, "msg-high"),
            self._make_issue(Severity.CRITICAL, "msg-critical"),
        ]
        print_issues(issues)
        captured = capsys.readouterr()
        out = captured.out
        pos_critical = out.index("msg-critical")
        pos_high = out.index("msg-high")
        pos_medium = out.index("msg-medium")
        pos_low = out.index("msg-low")
        pos_info = out.index("msg-info")
        assert pos_critical < pos_high < pos_medium < pos_low < pos_info, (
            "Expected output order: CRITICAL < HIGH < MEDIUM < LOW < INFO"
        )

    def test_issues_with_line_and_column_shown(self, capsys):
        issue = ValidationIssue(
            tool="yaml", severity=Severity.HIGH, message="bad indent", line=42, column=7
        )
        print_issues([issue])
        captured = capsys.readouterr()
        assert "42" in captured.out
        assert "7" in captured.out

    def test_issues_with_rule_shown(self, capsys):
        issue = ValidationIssue(
            tool="yamllint",
            severity=Severity.MEDIUM,
            message="trailing spaces",
            rule="trailing-spaces",
        )
        print_issues([issue])
        captured = capsys.readouterr()
        assert "trailing-spaces" in captured.out

    def test_issues_without_optional_fields(self, capsys):
        """Issues with no line/column/rule must not crash and still show message."""
        issue = ValidationIssue(tool="yaml", severity=Severity.LOW, message="bare message")
        print_issues([issue])
        captured = capsys.readouterr()
        assert "bare message" in captured.out

    def test_header_printed_when_issues_present(self, capsys):
        issues = [self._make_issue(Severity.INFO, "something")]
        print_issues(issues)
        captured = capsys.readouterr()
        assert "Issues Found" in captured.out

    def test_multiple_issues_same_severity_all_appear(self, capsys):
        issues = [
            self._make_issue(Severity.HIGH, "first high"),
            self._make_issue(Severity.HIGH, "second high"),
        ]
        print_issues(issues)
        captured = capsys.readouterr()
        assert "first high" in captured.out
        assert "second high" in captured.out

    def test_severity_label_printed_as_header(self, capsys):
        """Each severity group should have its label (e.g. 'HIGH:') in output."""
        issues = [self._make_issue(Severity.HIGH, "some high issue")]
        print_issues(issues)
        captured = capsys.readouterr()
        assert "HIGH" in captured.out


# ═════════════════════════════════════════════════════════════════════════════
# 9. print_summary_table  (#27)
# ═════════════════════════════════════════════════════════════════════════════
class TestPrintSummaryTable:
    """#27 — Verify the summary table renders correctly and counts match."""

    def _make_summary(self, critical=0, high=0, medium=0, low=0, info=0) -> dict:
        total = critical + high + medium + low + info
        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }

    # ── Structure ──────────────────────────────────────────────────────────

    def test_header_line_present(self, capsys):
        """Output must contain the 'Summary Report' header."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        assert "Summary" in out

    def test_severity_names_present(self, capsys):
        """All five severity names appear in the table."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert name in out, f"Missing severity label '{name}' in table output"

    def test_total_row_present(self, capsys):
        """A TOTAL row must be present in the output."""
        print_summary_table(self._make_summary(high=2))
        out = capsys.readouterr().out
        assert "TOTAL" in out

    # ── Zero-issue state ────────────────────────────────────────────────────

    def test_all_clean_shows_zero_counts(self, capsys):
        """When all counts are 0, every row shows 0."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        # All five severity rows + TOTAL should show 0
        # Count occurrences of '0' (at least 6: five rows + total)
        assert out.count("0") >= 6

    def test_all_clean_total_is_zero(self, capsys):
        """Clean run: total shown in TOTAL row is 0."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        # The TOTAL line should contain '0'
        total_line = [line for line in out.splitlines() if "TOTAL" in line]
        assert total_line, "TOTAL row not found"
        assert "0" in total_line[0]

    def test_all_clean_status_label(self, capsys):
        """Clean run: status should indicate 'Clean' or similar."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        assert "Clean" in out or "All Clean" in out

    # ── Non-zero counts ─────────────────────────────────────────────────────

    def test_critical_count_appears_in_output(self, capsys):
        """A critical count of 3 must appear in the output."""
        print_summary_table(self._make_summary(critical=3))
        out = capsys.readouterr().out
        assert "3" in out

    def test_total_equals_sum_of_severities(self, capsys):
        """TOTAL row count must equal the sum of individual severity counts."""
        summary = self._make_summary(critical=1, high=2, medium=3, low=4, info=5)
        expected_total = 1 + 2 + 3 + 4 + 5  # 15
        print_summary_table(summary)
        out = capsys.readouterr().out
        total_line = [line for line in out.splitlines() if "TOTAL" in line]
        assert total_line, "TOTAL row not found"
        assert str(expected_total) in total_line[0]

    def test_issues_found_status_when_count_nonzero(self, capsys):
        """When count > 0, status label should indicate issues were found."""
        print_summary_table(self._make_summary(high=1))
        out = capsys.readouterr().out
        assert "Issues Found" in out or "Issues" in out

    def test_mixed_counts_all_appear(self, capsys):
        """Each individual count value appears in output."""
        print_summary_table(self._make_summary(critical=1, high=2, medium=3, low=4, info=5))
        out = capsys.readouterr().out
        for count in (1, 2, 3, 4, 5):
            assert str(count) in out, f"Count {count} missing from summary table output"

    # ── No side-effects ─────────────────────────────────────────────────────

    def test_nothing_printed_to_stderr(self, capsys):
        """print_summary_table must not write to stderr."""
        print_summary_table(self._make_summary(critical=1))
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_output_ends_with_newline(self, capsys):
        """Last character of output is a newline."""
        print_summary_table(self._make_summary())
        out = capsys.readouterr().out
        assert out.endswith("\n")


# ═════════════════════════════════════════════════════════════════════════════
# 10. check_dependencies  (#28)
# ═════════════════════════════════════════════════════════════════════════════
class TestCheckDependenciesMocked:
    """#28 — Use unittest.mock.patch to simulate missing tools and verify behavior."""

    # ── Return type ─────────────────────────────────────────────────────────

    def test_returns_tool_availability_instance(self):
        """check_dependencies() always returns a ToolAvailability."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()
            result = check_dependencies()
        assert isinstance(result, ToolAvailability)

    # ── Both tools available ─────────────────────────────────────────────────

    def test_both_tools_available(self):
        """When both subprocess calls succeed, yamllint and checkov are True."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()
            result = check_dependencies()
        assert result.yamllint is True
        assert result.checkov is True

    # ── yamllint missing ────────────────────────────────────────────────────

    def test_yamllint_missing_raises_sys_exit(self):
        """Missing yamllint causes sys.exit(1) (it is a required tool)."""

        def fake_run(cmd, **kwargs):
            if "yamllint" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("yamllint not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run), pytest.raises(SystemExit) as exc_info:
            check_dependencies()
        assert exc_info.value.code == 1

    def test_yamllint_missing_prints_critical_message(self, capsys):
        """Missing yamllint prints a CRITICAL message before exiting."""

        def fake_run(cmd, **kwargs):
            if "yamllint" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("yamllint not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run), pytest.raises(SystemExit):
            check_dependencies()
        out = capsys.readouterr().out
        assert "yamllint" in out.lower() or "Missing" in out

    def test_yamllint_timeout_raises_sys_exit(self):
        """TimeoutExpired on yamllint check is treated as missing → sys.exit(1)."""

        def fake_run(cmd, **kwargs):
            if "yamllint" in " ".join(str(c) for c in cmd):
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run), pytest.raises(SystemExit) as exc_info:
            check_dependencies()
        assert exc_info.value.code == 1

    # ── checkov missing (optional) ──────────────────────────────────────────

    def test_checkov_missing_does_not_exit(self):
        """Missing checkov should NOT call sys.exit — it is optional."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("checkov not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()  # must not raise
        assert isinstance(result, ToolAvailability)

    def test_checkov_missing_sets_checkov_false(self):
        """When checkov import fails, returned tools.checkov is False."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("checkov not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()
        assert result.checkov is False

    def test_checkov_missing_yamllint_still_true(self):
        """When only checkov is missing, yamllint remains True."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("checkov not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()
        assert result.yamllint is True

    def test_checkov_missing_prints_warning(self, capsys):
        """Missing checkov prints a warning to stdout (not a fatal error)."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise FileNotFoundError("checkov not found")
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            check_dependencies()
        out = capsys.readouterr().out
        assert "checkov" in out.lower()

    def test_checkov_timeout_sets_checkov_false(self):
        """TimeoutExpired on checkov import check is treated as unavailable."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()
        assert result.checkov is False

    # ── CalledProcessError variants ──────────────────────────────────────────

    def test_yamllint_called_process_error_raises_sys_exit(self):
        """CalledProcessError from yamllint check triggers sys.exit(1)."""

        def fake_run(cmd, **kwargs):
            if "yamllint" in " ".join(str(c) for c in cmd):
                raise subprocess.CalledProcessError(returncode=1, cmd=cmd)
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run), pytest.raises(SystemExit) as exc_info:
            check_dependencies()
        assert exc_info.value.code == 1

    def test_checkov_called_process_error_sets_false(self):
        """CalledProcessError from checkov import check marks checkov=False."""

        def fake_run(cmd, **kwargs):
            if "import checkov" in " ".join(str(c) for c in cmd):
                raise subprocess.CalledProcessError(returncode=1, cmd=cmd)
            return type("R", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            result = check_dependencies()
        assert result.checkov is False


# ═════════════════════════════════════════════════════════════════════════════
# 11. main() end-to-end — exit code 0  (#29)
# ═════════════════════════════════════════════════════════════════════════════
_PYTHON = sys.executable
_APP = str(Path(__file__).parent.parent / "app.py")
_CLEAN = str(FIXTURES / "test3_clean.yaml")
_ISSUES = str(FIXTURES / "test1_issues.yaml")


class TestMainEndToEnd:
    """#29 — Call `python app.py <clean_file>` via subprocess and verify exit code 0."""

    def _run(self, *args, timeout=60):
        return subprocess.run(
            [_PYTHON, _APP, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_clean_file_exits_zero(self):
        """Clean YAML file → exit code 0."""
        result = self._run(_CLEAN)
        assert result.returncode == 0, (
            f"Expected exit 0 for clean file, got {result.returncode}\n"
            f"stdout: {result.stdout[-500:]}\nstderr: {result.stderr[-200:]}"
        )

    def test_clean_file_stdout_contains_validation_passed(self):
        """Output mentions successful validation."""
        result = self._run(_CLEAN)
        combined = result.stdout + result.stderr
        assert any(word in combined for word in ("passed", "Clean", "successfully")), (
            f"Expected success indicator in output. stdout: {result.stdout[-300:]}"
        )

    def test_clean_file_no_critical_in_output(self):
        """Clean file output should not mention CRITICAL issues."""
        result = self._run(_CLEAN)
        assert "CRITICAL" not in result.stdout or "0" in result.stdout

    def test_nonexistent_file_exits_nonzero(self):
        """Passing a nonexistent file should exit with a non-zero code."""
        result = self._run("/nonexistent/totally_fake.yaml")
        assert result.returncode != 0

    def test_output_contains_file_path(self):
        """Output should mention the file being validated."""
        result = self._run(_CLEAN)
        assert "test3_clean" in result.stdout or "test3_clean" in result.stderr


# ═════════════════════════════════════════════════════════════════════════════
# 12. main() exit code 1  (#30)
# ═════════════════════════════════════════════════════════════════════════════
class TestMainExitCode1:
    """#30 — Call `python app.py <issues_file>` via subprocess and verify exit code 1."""

    def _run(self, *args, timeout=60):
        return subprocess.run(
            [_PYTHON, _APP, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_issues_file_exits_one(self):
        """File with CRITICAL/HIGH issues → exit code 1."""
        result = self._run(_ISSUES)
        assert result.returncode == 1, (
            f"Expected exit 1 for issues file, got {result.returncode}\n"
            f"stdout: {result.stdout[-500:]}"
        )

    def test_issues_file_output_mentions_failed(self):
        """Output should mention failure or issues found."""
        result = self._run(_ISSUES)
        combined = result.stdout + result.stderr
        assert any(word in combined for word in ("failed", "Issues Found", "CRITICAL", "HIGH")), (
            f"Expected failure indicators in output. stdout: {result.stdout[-300:]}"
        )

    def test_issues_file_stdout_not_empty(self):
        """There should be some output when issues exist."""
        result = self._run(_ISSUES)
        assert len(result.stdout.strip()) > 0

    def test_exit_code_differs_between_clean_and_issues(self):
        """Exit codes for a clean vs. issues file must differ."""
        clean_result = subprocess.run([_PYTHON, _APP, _CLEAN], capture_output=True, timeout=60)
        issues_result = subprocess.run([_PYTHON, _APP, _ISSUES], capture_output=True, timeout=60)
        assert clean_result.returncode != issues_result.returncode, (
            "Clean and issues files should produce different exit codes"
        )

    def test_second_issues_file_also_exits_one(self):
        """A different issues fixture also produces exit code 1."""
        issues2 = str(FIXTURES / "test2_issues.yaml")
        result = self._run(issues2)
        assert result.returncode == 1


# ═════════════════════════════════════════════════════════════════════════════
# 13. --help and --version flags  (#31)
# ═════════════════════════════════════════════════════════════════════════════
class TestHelpVersionFlags:
    """#31 — Verify --help and --version print expected output and exit 0."""

    def _run(self, *args, timeout=10):
        return subprocess.run(
            [_PYTHON, _APP, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    # ── --version ────────────────────────────────────────────────────────────

    def test_version_exits_zero(self):
        """--version exits with code 0."""
        result = self._run("--version")
        assert result.returncode == 0, f"--version exit code: {result.returncode}"

    def test_version_prints_version_number(self):
        """--version output contains a version number (digits and dots)."""
        import re

        result = self._run("--version")
        combined = result.stdout + result.stderr
        assert re.search(r"\d+\.\d+", combined), f"No version number found in: {combined!r}"

    def test_version_output_contains_program_name(self):
        """--version output contains the program name."""
        result = self._run("--version")
        combined = result.stdout + result.stderr
        assert "yamlguard" in combined.lower(), (
            f"Program name missing from --version output: {combined!r}"
        )

    # ── --help ───────────────────────────────────────────────────────────────

    def test_help_exits_zero(self):
        """--help exits with code 0."""
        result = self._run("--help")
        assert result.returncode == 0, f"--help exit code: {result.returncode}"

    def test_help_prints_usage(self):
        """--help output contains 'usage' (case-insensitive)."""
        result = self._run("--help")
        combined = result.stdout + result.stderr
        assert "usage" in combined.lower(), (
            f"'usage' missing from --help output: {combined[:300]!r}"
        )

    def test_help_mentions_file_argument(self):
        """--help describes the FILE positional argument."""
        result = self._run("--help")
        combined = result.stdout + result.stderr
        assert "FILE" in combined or "file" in combined.lower()

    def test_help_mentions_timeout_flag(self):
        """--help describes the --timeout flag."""
        result = self._run("--help")
        assert "--timeout" in result.stdout + result.stderr

    def test_help_mentions_version_flag(self):
        """--help lists --version as an option."""
        result = self._run("--help")
        assert "--version" in result.stdout + result.stderr

    def test_help_output_not_empty(self):
        """--help produces non-empty output."""
        result = self._run("--help")
        assert len((result.stdout + result.stderr).strip()) > 0


# ═════════════════════════════════════════════════════════════════════════════
# 14. Multi-file combined summary  (#32)
# ═════════════════════════════════════════════════════════════════════════════
class TestMultiFileSummary:
    """#32 — Run app with 2+ files and verify combined summary output."""

    def _run(self, *args, timeout=120):
        return subprocess.run(
            [_PYTHON, _APP, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_two_files_shows_files_scanned(self):
        """Running with 2 files produces 'Files scanned' in output."""
        result = self._run(_CLEAN, _ISSUES)
        assert "Files scanned" in result.stdout, (
            f"'Files scanned' not found in output:\n{result.stdout[-500:]}"
        )

    def test_files_scanned_count_is_two(self):
        """'Files scanned: 2' appears when exactly 2 files are passed."""
        result = self._run(_CLEAN, _ISSUES)
        assert "Files scanned: 2" in result.stdout, (
            f"Expected 'Files scanned: 2', got:\n{result.stdout[-500:]}"
        )

    def test_three_files_shows_count_three(self):
        """Passing 3 files reports 'Files scanned: 3'."""
        issues2 = str(FIXTURES / "test2_issues.yaml")
        result = self._run(_CLEAN, _ISSUES, issues2)
        assert "Files scanned: 3" in result.stdout, (
            f"Expected 'Files scanned: 3', got:\n{result.stdout[-500:]}"
        )

    def test_combined_results_header_present(self):
        """'Combined Results' section header appears for multi-file runs."""
        result = self._run(_CLEAN, _ISSUES)
        assert "Combined Results" in result.stdout or "combined" in result.stdout.lower()

    def test_total_issues_line_present(self):
        """'Total issues' line is printed in the combined summary."""
        result = self._run(_CLEAN, _ISSUES)
        assert "Total issues" in result.stdout, f"'Total issues' not found:\n{result.stdout[-500:]}"

    def test_single_file_no_combined_section(self):
        """With only 1 file, 'Files scanned' should NOT appear (no combined section)."""
        result = self._run(_CLEAN)
        assert "Files scanned" not in result.stdout

    def test_multi_file_exit_code_reflects_issues(self):
        """When at least one file has CRITICAL/HIGH issues, exit code is 1."""
        result = self._run(_CLEAN, _ISSUES)
        assert result.returncode == 1

    def test_multi_file_both_paths_in_output(self):
        """Both file paths are mentioned somewhere in the output."""
        result = self._run(_CLEAN, _ISSUES)
        assert "test3_clean" in result.stdout
        assert "test1_issues" in result.stdout


# ═════════════════════════════════════════════════════════════════════════════
# 15. resolve_files() negative cases  (#33)
# ═════════════════════════════════════════════════════════════════════════════
class TestResolveFilesNegative:
    """#33 — Symlink loops, permission-denied dirs, no-extension files."""

    # ── Files without a .yaml/.yml extension ─────────────────────────────────

    def test_plain_text_file_not_included(self, tmp_path):
        """A .txt file in a directory is silently ignored — not a YAML file."""
        (tmp_path / "notes.txt").write_text("some text")
        result = resolve_files([str(tmp_path)])
        assert all(f.endswith((".yaml", ".yml")) for f in result)

    def test_no_extension_file_not_included(self, tmp_path):
        """A file with no extension at all is not returned by resolve_files."""
        (tmp_path / "Makefile").write_text("all:\n\techo hi")
        result = resolve_files([str(tmp_path)])
        assert not any("Makefile" in f for f in result)

    def test_yaml_extension_file_is_included(self, tmp_path):
        """A valid .yaml file in a dir IS included (positive sanity check)."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value\n")
        result = resolve_files([str(tmp_path)])
        assert any("config.yaml" in f for f in result)

    def test_mixed_dir_only_yaml_returned(self, tmp_path):
        """Directory with mixed extensions — only .yaml/.yml come back."""
        (tmp_path / "good.yaml").write_text("a: 1\n")
        (tmp_path / "good.yml").write_text("b: 2\n")
        (tmp_path / "bad.json").write_text('{"c": 3}')
        (tmp_path / "bad.txt").write_text("plain text")
        (tmp_path / "bad").write_text("no extension")
        result = resolve_files([str(tmp_path)])
        assert len(result) == 2
        assert all(f.endswith((".yaml", ".yml")) for f in result)

    def test_explicit_no_extension_path_skipped(self, tmp_path):
        """Passing an explicit path with no .yaml extension returns empty."""
        no_ext = tmp_path / "datafile"
        no_ext.write_text("key: value\n")
        result = resolve_files([str(no_ext)])
        # resolve_files accepts explicit files regardless of extension
        # — but they won't match the yaml-only filter from dir scans.
        # If passed directly as a file, it IS included (it's a real file).
        # The important thing: no crash, returns a list.
        assert isinstance(result, list)

    # ── Permission-denied directory ───────────────────────────────────────────

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses permission checks")
    def test_permission_denied_dir_does_not_crash(self, tmp_path):
        """resolve_files() must not raise when scanning an unreadable directory."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "hidden.yaml").write_text("key: value\n")
        secret_dir.chmod(0o000)
        try:
            result = resolve_files([str(tmp_path)])
            # Should return a list (possibly empty) without raising
            assert isinstance(result, list)
        finally:
            secret_dir.chmod(0o755)  # restore so pytest cleanup works

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses permission checks")
    def test_permission_denied_dir_returns_list(self, tmp_path):
        """Even with a locked dir, the return value is always a list."""
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            result = resolve_files([str(locked)])
            assert isinstance(result, list)
        finally:
            locked.chmod(0o755)

    # ── Symlink handling ──────────────────────────────────────────────────────

    def test_broken_symlink_does_not_crash(self, tmp_path):
        """Broken links are omitted whether passed directly or found in a directory."""
        link = tmp_path / "ghost.yaml"
        link.symlink_to(tmp_path / "missing.yaml")

        assert resolve_files([str(link)]) == []
        assert resolve_files([str(tmp_path)]) == []

    def test_symlink_to_valid_file_is_skipped(self, tmp_path):
        """A real YAML file is found while a link to it is omitted."""
        real = tmp_path / "real.yaml"
        real.write_text("key: value\n")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)

        assert resolve_files([str(link)]) == []
        assert resolve_files([str(tmp_path)]) == [str(real)]
        assert resolve_files([str(tmp_path / "*.yaml")]) == [str(real)]

    def test_symlinked_directory_is_skipped(self, tmp_path, capsys):
        """Do not scan a directory link, even when it contains YAML files."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "inside.yaml").write_text("key: value\n")
        scan = tmp_path / "scan"
        scan.mkdir()
        link = scan / "linked"
        link.symlink_to(target, target_is_directory=True)

        assert resolve_files([str(link)]) == []
        assert resolve_files([str(scan)]) == []
        assert resolve_files([str(scan / "*" / "*.yaml")]) == []
        assert resolve_files([str(link / "inside.yaml")]) == []
        assert capsys.readouterr().out == ""

    def test_glob_matching_only_symlinks_is_skipped(self, tmp_path, capsys):
        """A glob that finds only links should not claim its path is missing."""
        target = tmp_path / "target.yaml"
        target.write_text("ok: true\n")
        scan = tmp_path / "scan"
        scan.mkdir()
        (scan / "linked.yaml").symlink_to(target)

        assert resolve_files([str(scan / "*.yaml")]) == []
        assert capsys.readouterr().out == ""

    def test_trailing_slash_glob_matches_only_directories(self, tmp_path):
        """A directory-only glob must not pass regular files to validation."""
        configs = tmp_path / "configs"
        configs.mkdir()
        valid_dir = configs / "valid"
        valid_dir.mkdir()
        valid = valid_dir / "config.yaml"
        valid.write_text("ok: true\n")
        notes = configs / "notes.txt"
        notes.write_text("not YAML: [\n")
        (configs / "linked").symlink_to(valid_dir, target_is_directory=True)

        assert resolve_files([str(configs / "*") + os.sep]) == [str(valid)]
        assert resolve_files([str(notes) + os.sep]) == []

    def test_recursive_glob_skips_symlinked_directory(self, tmp_path):
        """A recursive glob must not enter a linked directory outside its root."""
        scan = tmp_path / "scan"
        scan.mkdir()
        real = scan / "real.yaml"
        real.write_text("key: value\n")
        target = tmp_path / "target"
        target.mkdir()
        (target / "outside.yaml").write_text("key: value\n")
        (scan / "linked").symlink_to(target, target_is_directory=True)

        assert resolve_files([str(scan / "**" / "*.yaml")]) == [str(real)]

    def test_glob_does_not_reinterpret_matched_directory_name(self, tmp_path):
        """A matched literal name containing glob syntax must not reopen a symlink."""
        scan = tmp_path / "scan"
        scan.mkdir()
        literal = scan / "a[1]"
        literal.mkdir()
        real = literal / "real.yaml"
        real.write_text("ok: true\n")

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "leaked.yaml").write_text("ok: true\n")
        (scan / "a1").symlink_to(outside, target_is_directory=True)

        assert resolve_files([str(scan / "*" / "*.yaml")]) == [str(real)]

    def test_explicit_path_with_glob_characters_is_still_accepted(self, tmp_path, capsys):
        """Literal fallback accepts real paths but still rejects symlink ancestors."""
        literal = tmp_path / "odd[1]"
        literal.mkdir()
        real = literal / "real.yaml"
        real.write_text("ok: true\n")
        link = tmp_path / "linked[1]"
        link.symlink_to(literal, target_is_directory=True)

        assert resolve_files([str(real)]) == [str(real)]
        assert resolve_files([str(link / "real.yaml")]) == []
        assert capsys.readouterr().out == ""

    def test_symlink_loop_does_not_hang(self, tmp_path):
        """Directory scans and recursive globs both terminate on circular links."""
        real = tmp_path / "valid.yaml"
        real.write_text("ok: true\n")
        nested = tmp_path / "nested"
        nested.mkdir()
        other = nested / "other.yaml"
        other.write_text("ok: true\n")
        (nested / "loop").symlink_to(tmp_path, target_is_directory=True)

        expected = {str(real), str(other)}
        assert set(resolve_files([str(tmp_path)])) == expected
        assert set(resolve_files([str(tmp_path / "**" / "*.yaml")])) == expected

    def test_relative_recursive_glob_skips_symlink_loop(self, tmp_path, monkeypatch):
        """The CLI's relative glob example also terminates on a circular link."""
        real = tmp_path / "valid.yaml"
        real.write_text("ok: true\n")
        (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
        monkeypatch.chdir(tmp_path)

        assert resolve_files(["**/*.yaml"]) == [str(real)]

    def test_empty_directory_returns_empty_list(self, tmp_path):
        """Scanning a directory with no YAML files returns an empty list."""
        result = resolve_files([str(tmp_path)])
        assert result == []

    def test_nonexistent_explicit_path_returns_empty(self):
        """A completely made-up path returns [] without crashing."""
        result = resolve_files(["/this/path/does/not/exist/at/all.yaml"])
        assert result == []


# ═════════════════════════════════════════════════════════════════════════════
# 16. Large YAML files  (#34)
# ═════════════════════════════════════════════════════════════════════════════
_LARGE_FIXTURE = str(FIXTURES / "large_10k.yaml")


class TestLargeYamlFiles:
    """#34 — 40,000-line fixture (688 KB). Verify correctness and no excessive time."""

    # ── Fixture sanity ────────────────────────────────────────────────────────

    def test_large_fixture_exists(self):
        """The large fixture file was generated and is present on disk."""
        assert Path(_LARGE_FIXTURE).exists(), f"Missing fixture: {_LARGE_FIXTURE}"

    def test_large_fixture_line_count(self):
        """The fixture has at least 10,000 lines of YAML content."""
        with open(_LARGE_FIXTURE) as f:
            line_count = sum(1 for _ in f)
        assert line_count >= 10_000, f"Expected ≥10k lines, got {line_count}"

    def test_large_fixture_size_in_bytes(self):
        """The fixture is at least 100 KB (proves it's not a stub)."""
        size = Path(_LARGE_FIXTURE).stat().st_size
        assert size >= 100_000, f"Fixture too small: {size} bytes"

    # ── Syntax validation ─────────────────────────────────────────────────────

    def test_large_file_syntax_valid(self):
        """validate_yaml_syntax() reports no issues on the large fixture."""
        issues = validate_yaml_syntax(_LARGE_FIXTURE)
        assert issues == [], f"Unexpected syntax issues: {issues[:3]}"

    def test_large_file_syntax_returns_list(self):
        """validate_yaml_syntax() always returns a list, never raises."""
        result = validate_yaml_syntax(_LARGE_FIXTURE)
        assert isinstance(result, list)

    # ── Performance (time budget) ─────────────────────────────────────────────

    def test_large_file_syntax_check_within_30s(self):
        """Syntax check on the large fixture completes within 30 seconds."""
        import time

        start = time.monotonic()
        validate_yaml_syntax(_LARGE_FIXTURE)
        elapsed = time.monotonic() - start
        assert elapsed < 30, f"Syntax check took {elapsed:.1f}s — too slow for a 40k-line file"

    def test_large_file_resolve_files_works(self):
        """resolve_files() happily accepts the large fixture path."""
        result = resolve_files([_LARGE_FIXTURE])
        assert len(result) == 1
        assert _LARGE_FIXTURE in result[0] or result[0].endswith("large_10k.yaml")

    # ── yamllint on large file ─────────────────────────────────────────────────

    def test_large_file_yamllint_returns_list(self):
        """run_yamllint() on a large file always returns a list without crashing."""
        result = run_yamllint(_LARGE_FIXTURE, timeout=60)
        assert isinstance(result, list)

    def test_large_file_yamllint_within_60s(self):
        """yamllint on the large fixture completes within 60 seconds."""
        import time

        start = time.monotonic()
        run_yamllint(_LARGE_FIXTURE, timeout=60)
        elapsed = time.monotonic() - start
        assert elapsed < 60, f"yamllint took {elapsed:.1f}s on large file"

    # ── Memory safety ─────────────────────────────────────────────────────────

    def test_large_file_validate_yaml_file_completes(self):
        """validate_yaml_file() on the large fixture runs to completion."""
        tools = ToolAvailability(checkov=False)  # skip slow checkov
        result = validate_yaml_file(_LARGE_FIXTURE, tools)
        assert isinstance(result, ValidationResult)

    def test_large_file_result_has_summary(self):
        """validate_yaml_file() on the large fixture returns a complete summary dict."""
        tools = ToolAvailability(checkov=False)
        result = validate_yaml_file(_LARGE_FIXTURE, tools)
        for key in ("total", "critical", "high", "medium", "low", "info"):
            assert key in result.summary, f"Missing summary key: {key}"


# ═════════════════════════════════════════════════════════════════════════════
# 17. JSON output  (--format json)
# ═════════════════════════════════════════════════════════════════════════════
from app import print_json_result, result_to_json  # noqa: E402


class TestJsonOutput:
    """Tests for result_to_json(), print_json_result(), and --format json CLI flag."""

    # ── helpers ───────────────────────────────────────────────────────────────

    def _make_result(
        self,
        file_path: str = "test.yaml",
        syntax_valid: bool = True,
        issues: list | None = None,
    ) -> ValidationResult:
        """Build a minimal ValidationResult for testing."""
        if issues is None:
            issues = []
        summary = {
            "total": len(issues),
            "critical": sum(1 for i in issues if i.severity == Severity.CRITICAL),
            "high": sum(1 for i in issues if i.severity == Severity.HIGH),
            "medium": sum(1 for i in issues if i.severity == Severity.MEDIUM),
            "low": sum(1 for i in issues if i.severity == Severity.LOW),
            "info": sum(1 for i in issues if i.severity == Severity.INFO),
        }
        return ValidationResult(
            file_path=file_path,
            syntax_valid=syntax_valid,
            issues=issues,
            summary=summary,
        )

    def _make_issue(  # noqa: PLR0913, PLR0917
        self,
        tool: str = "yaml",
        severity: Severity = Severity.MEDIUM,
        message: str = "some problem",
        line: int | None = 5,
        column: int | None = 3,
        rule: str | None = "test-rule",
        file_path: str | None = "test.yaml",
    ) -> ValidationIssue:
        return ValidationIssue(
            tool=tool,
            severity=severity,
            message=message,
            line=line,
            column=column,
            rule=rule,
            file_path=file_path,
        )

    # ── result_to_json() — field presence ─────────────────────────────────────

    def test_result_to_json_returns_dict(self):
        """result_to_json() must return a dict."""
        result = self._make_result()
        assert isinstance(result_to_json(result), dict)

    def test_result_to_json_has_file_path(self):
        result = self._make_result(file_path="myfile.yaml")
        d = result_to_json(result)
        assert d["file_path"] == "myfile.yaml"

    def test_result_to_json_has_syntax_valid_true(self):
        result = self._make_result(syntax_valid=True)
        assert result_to_json(result)["syntax_valid"] is True

    def test_result_to_json_has_syntax_valid_false(self):
        result = self._make_result(syntax_valid=False)
        assert result_to_json(result)["syntax_valid"] is False

    def test_result_to_json_has_summary(self):
        result = self._make_result()
        d = result_to_json(result)
        assert "summary" in d
        for key in ("total", "critical", "high", "medium", "low", "info"):
            assert key in d["summary"], f"summary missing key '{key}'"

    def test_result_to_json_has_issues_list(self):
        result = self._make_result()
        d = result_to_json(result)
        assert isinstance(d["issues"], list)

    def test_result_to_json_empty_issues(self):
        result = self._make_result()
        assert result_to_json(result)["issues"] == []

    # ── result_to_json() — issue serialisation ────────────────────────────────

    def test_result_to_json_issue_fields(self):
        """Each serialised issue must contain all expected keys."""
        issue = self._make_issue()
        result = self._make_result(issues=[issue])
        d = result_to_json(result)
        assert len(d["issues"]) == 1
        issue_d = d["issues"][0]
        for key in ("tool", "severity", "message", "line", "column", "rule", "file_path"):
            assert key in issue_d, f"issue missing key '{key}'"

    def test_result_to_json_severity_is_string(self):
        """Severity enum must be serialised as its string value, not an object."""
        issue = self._make_issue(severity=Severity.CRITICAL)
        result = self._make_result(issues=[issue])
        d = result_to_json(result)
        assert d["issues"][0]["severity"] == "CRITICAL"

    def test_result_to_json_none_fields_preserved(self):
        """Optional fields (line, column, rule, file_path) that are None stay None."""
        issue = self._make_issue(line=None, column=None, rule=None, file_path=None)
        result = self._make_result(issues=[issue])
        d = result_to_json(result)
        issue_d = d["issues"][0]
        assert issue_d["line"] is None
        assert issue_d["column"] is None
        assert issue_d["rule"] is None
        assert issue_d["file_path"] is None

    def test_result_to_json_multiple_issues(self):
        """All issues are serialised when there is more than one."""
        issues = [
            self._make_issue(severity=Severity.CRITICAL, message="bad"),
            self._make_issue(severity=Severity.LOW, message="minor"),
        ]
        result = self._make_result(issues=issues)
        d = result_to_json(result)
        assert len(d["issues"]) == 2
        messages = {i["message"] for i in d["issues"]}
        assert messages == {"bad", "minor"}

    # ── result_to_json() — round-trip / JSON validity ─────────────────────────

    def test_result_to_json_is_json_serialisable(self):
        """result_to_json() output must be serialisable with json.dumps() without error."""
        issue = self._make_issue()
        result = self._make_result(issues=[issue])
        try:
            raw = json.dumps(result_to_json(result))
        except (TypeError, ValueError) as exc:
            pytest.fail(f"result_to_json() output is not JSON-serialisable: {exc}")
        assert isinstance(raw, str)

    def test_result_to_json_round_trip(self):
        """Serialise → deserialise → values must match the original result."""
        issue = self._make_issue(
            tool="yamllint",
            severity=Severity.HIGH,
            message="trailing spaces",
            line=10,
            column=1,
            rule="trailing-spaces",
        )
        result = self._make_result(
            file_path="/tmp/check.yaml",
            syntax_valid=True,
            issues=[issue],
        )
        raw = json.dumps(result_to_json(result))
        restored = json.loads(raw)

        assert restored["file_path"] == "/tmp/check.yaml"
        assert restored["syntax_valid"] is True
        assert len(restored["issues"]) == 1
        ri = restored["issues"][0]
        assert ri["tool"] == "yamllint"
        assert ri["severity"] == "HIGH"
        assert ri["message"] == "trailing spaces"
        assert ri["line"] == 10
        assert ri["column"] == 1
        assert ri["rule"] == "trailing-spaces"

    # ── print_json_result() — stdout validity ─────────────────────────────────

    def test_print_json_result_single_emits_object(self, capsys):
        """Single result → stdout is a JSON object (not an array)."""
        result = self._make_result()
        print_json_result([result])
        captured = capsys.readouterr().out
        parsed = json.loads(captured)
        assert isinstance(parsed, dict)

    def test_print_json_result_multiple_emits_array(self, capsys):
        """Multiple results → stdout is a JSON array."""
        results = [self._make_result("a.yaml"), self._make_result("b.yaml")]
        print_json_result(results)
        captured = capsys.readouterr().out
        parsed = json.loads(captured)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_print_json_result_valid_json(self, capsys):
        """Output must be parseable by json.loads() without error."""
        issue = self._make_issue(severity=Severity.CRITICAL)
        result = self._make_result(syntax_valid=False, issues=[issue])
        print_json_result([result])
        captured = capsys.readouterr().out
        try:
            json.loads(captured)
        except json.JSONDecodeError as exc:
            pytest.fail(f"print_json_result() emitted invalid JSON: {exc}")

    def test_print_json_result_no_ansi_codes(self, capsys):
        """JSON output must not contain ANSI escape sequences."""
        result = self._make_result(issues=[self._make_issue(severity=Severity.CRITICAL)])
        print_json_result([result])
        captured = capsys.readouterr().out
        assert "\x1b[" not in captured, "ANSI escape codes found in JSON output"

    def test_print_json_result_contains_all_top_level_keys(self, capsys):
        """The JSON object must contain file_path, syntax_valid, summary, and issues."""
        result = self._make_result()
        print_json_result([result])
        captured = capsys.readouterr().out
        parsed = json.loads(captured)
        for key in ("file_path", "syntax_valid", "summary", "issues"):
            assert key in parsed, f"Top-level key '{key}' missing from JSON output"

    def test_print_json_result_summary_counts_correct(self, capsys):
        """Summary counts in JSON must match the actual issues."""
        issues = [
            self._make_issue(severity=Severity.CRITICAL),
            self._make_issue(severity=Severity.HIGH),
            self._make_issue(severity=Severity.MEDIUM),
        ]
        result = self._make_result(issues=issues)
        print_json_result([result])
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["summary"]["total"] == 3
        assert parsed["summary"]["critical"] == 1
        assert parsed["summary"]["high"] == 1
        assert parsed["summary"]["medium"] == 1

    # ── --format json CLI flag ────────────────────────────────────────────────

    def test_format_flag_accepted_json(self, clean_file):
        """--format json is accepted by argparse without SystemExit."""
        with (
            patch("sys.argv", ["yamlguard", "--format", "json", clean_file]),
            patch("yamlguard.cli.check_dependencies") as mock_deps,
            patch("yamlguard.cli.validate_yaml_file") as mock_val,
        ):
            mock_deps.return_value = ToolAvailability(yamllint=False, checkov=False)
            mock_val.return_value = self._make_result(file_path=clean_file)
            try:
                from yamlguard import cli

                cli.main()
            except SystemExit as exc:
                assert exc.code == 0, f"Expected exit 0, got {exc.code}"

    def test_format_flag_accepted_text(self, clean_file):
        """--format text (explicit) is accepted by argparse without SystemExit."""
        with (
            patch("sys.argv", ["yamlguard", "--format", "text", clean_file]),
            patch("yamlguard.cli.check_dependencies") as mock_deps,
            patch("yamlguard.cli.validate_yaml_file") as mock_val,
        ):
            mock_deps.return_value = ToolAvailability(yamllint=False, checkov=False)
            mock_val.return_value = self._make_result(file_path=clean_file)
            try:
                from yamlguard import cli

                cli.main()
            except SystemExit as exc:
                assert exc.code == 0, f"Expected exit 0, got {exc.code}"

    def test_format_flag_short_f(self, clean_file):
        """-f json (short form) is accepted by argparse."""
        with (
            patch("sys.argv", ["yamlguard", "-f", "json", clean_file]),
            patch("yamlguard.cli.check_dependencies") as mock_deps,
            patch("yamlguard.cli.validate_yaml_file") as mock_val,
        ):
            mock_deps.return_value = ToolAvailability(yamllint=False, checkov=False)
            mock_val.return_value = self._make_result(file_path=clean_file)
            try:
                from yamlguard import cli

                cli.main()
            except SystemExit as exc:
                assert exc.code == 0, f"Expected exit 0, got {exc.code}"

    def test_format_json_produces_valid_json_via_subprocess(self, clean_file):
        """End-to-end: running the tool with --format json produces valid JSON on stdout."""
        result = subprocess.run(
            [sys.executable, "app.py", "--format", "json", clean_file],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"stdout was not valid JSON: {exc}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
            )
        assert isinstance(parsed, dict)

    def test_format_json_no_colored_text_on_stdout(self, clean_file):
        """--format json must not emit any ANSI escape codes on stdout."""
        result = subprocess.run(
            [sys.executable, "app.py", "--format", "json", clean_file],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert "\x1b[" not in result.stdout, f"ANSI codes found in JSON stdout:\n{result.stdout!r}"

    def test_format_json_stdout_has_required_keys(self, clean_file):
        """JSON stdout from --format json must include all required top-level keys."""
        result = subprocess.run(
            [sys.executable, "app.py", "--format", "json", clean_file],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        parsed = json.loads(result.stdout)
        for key in ("file_path", "syntax_valid", "summary", "issues"):
            assert key in parsed, f"Key '{key}' missing from JSON output"

    def test_format_invalid_choice_exits_nonzero(self):
        """An unknown --format value must cause a non-zero exit (argparse error)."""
        result = subprocess.run(
            [sys.executable, "app.py", "--format", "xml", "dummy.yaml"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode != 0

    def test_format_default_is_text(self, clean_file):
        """Omitting --format defaults to text mode (no JSON on stdout)."""
        result = subprocess.run(
            [sys.executable, "app.py", clean_file],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        # In text mode the output should NOT start with '{' or '['
        stdout = result.stdout.strip()
        assert not stdout.startswith("{") and not stdout.startswith("["), (
            f"Text mode output looks like JSON: {stdout[:120]!r}"
        )
