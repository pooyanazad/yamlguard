"""
yamlguard.validators
=========================
Core validation functions.

  validate_yaml_syntax() — PyYAML syntax check
  run_yamllint()         — yamllint linting check
  run_checkov()          — checkov security check
  validate_yaml_file()   — orchestrates all three checks for one file
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import yaml

from yamlguard.models import (
    Severity,
    ToolAvailability,
    ToolExecution,
    ToolStatus,
    ValidationIssue,
    ValidationResult,
)
from yamlguard.output import print_colored

# ─────────────────────────────────────────────────────────────────────────────
PYTHON_EXECUTABLE = sys.executable
LARGE_FILE_WARNING_THRESHOLD = 1024 * 1024

# Issues carrying this rule mean "the tool did not finish", not "the file has a
# problem". Severity alone cannot express that distinction.
OPERATIONAL_ERROR_RULE = "operational-error"

# Operational errors quote a short excerpt of tool output. Keep it bounded and
# strip anything that looks like a credential so reports stay safe to publish.
_MAX_DIAGNOSTIC_CHARS = 200
_SECRET_PATTERN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*)"
    r"\s*[=:]\s*\S+"
)


def _bounded_diagnostic(text: str, limit: int = _MAX_DIAGNOSTIC_CHARS) -> str:
    """Return a single-line, length-bounded, secret-redacted excerpt of tool output."""
    collapsed = " ".join((text or "").split())
    collapsed = _SECRET_PATTERN.sub(r"\1=***", collapsed)
    if len(collapsed) > limit:
        collapsed = collapsed[: limit - 3] + "..."
    return collapsed


def _diagnostic_suffix(result: subprocess.CompletedProcess) -> str:
    """Build a ``": <excerpt>"`` suffix from a finished subprocess, or ``""``."""
    excerpt = _bounded_diagnostic(result.stderr) or _bounded_diagnostic(result.stdout)
    return f": {excerpt}" if excerpt else ""


# ─────────────────────────────────────────────────────────────────────────────
def warn_if_large_file(file_path: str) -> None:
    """Warn when security checks may be slow for a large YAML file."""
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        return

    if file_size > LARGE_FILE_WARNING_THRESHOLD:
        print_colored(
            "Warning: large YAML file detected. Security checks may be slow; "
            "use --no-security to skip them.",
            Severity.MEDIUM,
        )


# ─────────────────────────────────────────────────────────────────────────────
def validate_yaml_syntax(file_path: str) -> list[ValidationIssue]:
    """Validate YAML syntax using PyYAML."""
    issues: list[ValidationIssue] = []

    # Check file existence and read permission before opening
    if not os.path.exists(file_path):
        return [
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"File not found: {file_path}",
                file_path=file_path,
            )
        ]
    if not os.access(file_path, os.R_OK):
        return [
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"Permission denied: {file_path}",
                file_path=file_path,
            )
        ]

    # #14 — Detect binary files early by sniffing for null bytes.
    # Avoids a confusing UnicodeDecodeError later; report as MEDIUM warning.
    try:
        with open(file_path, "rb") as raw:
            chunk = raw.read(8192)
        if b"\x00" in chunk:
            return [
                ValidationIssue(
                    tool="yaml",
                    severity=Severity.MEDIUM,
                    message=(
                        f"File appears to be binary (contains null bytes): {file_path}. "
                        "Rename or remove the file — it cannot be validated as YAML."
                    ),
                    rule="binary-file",
                    file_path=file_path,
                )
            ]
    except OSError as e:
        return [
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"File reading error: {e!s}",
                file_path=file_path,
            )
        ]

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            # Use safe_load_all to handle multiple documents
            documents = list(yaml.safe_load_all(file))

        # #13 — Detect empty YAML files.
        # safe_load_all returns [] for truly empty / whitespace / comment-only
        # files, and [None] for files that contain an explicit null document.
        # Neither case contains meaningful data — report as INFO.
        if not documents or all(doc is None for doc in documents):
            issues.append(
                ValidationIssue(
                    tool="yaml",
                    severity=Severity.INFO,
                    message="File is empty or contains only whitespace/comments.",
                    rule="empty-file",
                    file_path=file_path,
                )
            )
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        line_num = mark.line + 1 if mark else None
        column_num = mark.column + 1 if mark else None
        issues.append(
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=str(e),
                line=line_num,
                column=column_num,
                rule="syntax",
                file_path=file_path,
            )
        )
    except FileNotFoundError:
        issues.append(
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"File not found: {file_path}",
                file_path=file_path,
            )
        )
    except PermissionError:
        issues.append(
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"Permission denied: {file_path}",
                file_path=file_path,
            )
        )
    except UnicodeDecodeError as e:
        issues.append(
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"File encoding error (not valid UTF-8): {e!s}",
                file_path=file_path,
            )
        )
    except OSError as e:
        issues.append(
            ValidationIssue(
                tool="yaml",
                severity=Severity.CRITICAL,
                message=f"File reading error: {e!s}",
                file_path=file_path,
            )
        )

    return issues


# ─────────────────────────────────────────────────────────────────────────────
def run_yamllint(file_path: str, timeout: int = 300) -> list[ValidationIssue]:
    """Run yamllint and parse results.

    Return codes from yamllint:
      0 — no problems found
      1 — one or more lint issues found (normal operation)
      anything else — configuration error or crash

    Only 0 and 1 are normal lint-result exits, so only those are parsed for
    findings. Any other exit is an operational error: it is reported with HIGH
    severity and its stdout is never interpreted as lint output, so a crash
    that happens to print something cannot masquerade as a clean scan.
    """
    issues: list[ValidationIssue] = []
    pattern = re.compile(r"^(.+?):(\d+):(\d+): \[([^\]]+)\] (.+?)(?: \(([^)]+)\))?$")

    try:
        result = subprocess.run(
            [PYTHON_EXECUTABLE, "-m", "yamllint", "-f", "parsable", file_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0 and "No module named yamllint" in result.stderr:
            issues.append(
                ValidationIssue(
                    tool="yamllint",
                    severity=Severity.HIGH,
                    message="yamllint is not installed or not available in the Python environment.",
                    rule=OPERATIONAL_ERROR_RULE,
                    file_path=file_path,
                )
            )
            return issues

        # Only 0 (clean) and 1 (findings) are normal lint-result exits.
        if result.returncode not in (0, 1):
            issues.append(
                ValidationIssue(
                    tool="yamllint",
                    severity=Severity.HIGH,
                    message=(
                        f"yamllint execution failed with exit code {result.returncode}"
                        f"{_diagnostic_suffix(result)}"
                    ),
                    rule=OPERATIONAL_ERROR_RULE,
                    file_path=file_path,
                )
            )
            return issues

        for line in result.stdout.strip().split("\n"):
            if line.strip():
                match = pattern.match(line)
                if match:
                    _parsed_file, line_num, col_num, level, message, rule = match.groups()
                    severity = Severity.MEDIUM if level == "error" else Severity.LOW
                    issues.append(
                        ValidationIssue(
                            tool="yamllint",
                            severity=severity,
                            message=message.strip(),
                            line=int(line_num),
                            column=int(col_num),
                            rule=rule or level,
                            file_path=file_path,
                        )
                    )
                else:
                    # Fallback for unexpected format
                    issues.append(
                        ValidationIssue(
                            tool="yamllint",
                            severity=Severity.MEDIUM,
                            message=line.strip(),
                            file_path=file_path,
                        )
                    )

    except subprocess.TimeoutExpired:
        issues.append(
            ValidationIssue(
                tool="yamllint",
                severity=Severity.HIGH,
                message=f"yamllint execution timed out after {timeout} seconds.",
                rule=OPERATIONAL_ERROR_RULE,
                file_path=file_path,
            )
        )
    except OSError as e:
        issues.append(
            ValidationIssue(
                tool="yamllint",
                severity=Severity.HIGH,
                message=f"yamllint execution failed: {e!s}",
                rule=OPERATIONAL_ERROR_RULE,
                file_path=file_path,
            )
        )

    return issues


# ─────────────────────────────────────────────────────────────────────────────
def _checkov_operational_error(file_path: str, reason: str) -> ValidationIssue:
    """Build a HIGH-severity issue describing a Checkov run that did not complete."""
    return ValidationIssue(
        tool="checkov",
        severity=Severity.HIGH,
        message=f"checkov execution failed: {reason}",
        rule=OPERATIONAL_ERROR_RULE,
        file_path=file_path,
    )


def _parse_checkov_report(data: object) -> list[dict] | None:
    """Return the report dicts in a Checkov payload, or None if the shape is unexpected."""
    if isinstance(data, dict):
        reports = [data]
    elif isinstance(data, list):
        reports = data
    else:
        return None

    # An empty list is Checkov's "no applicable framework" answer, not a failure.
    if not reports:
        return []
    if not all(isinstance(report, dict) for report in reports):
        return None
    # A usable report carries a "results" object, or is checkov's summary-only
    # form (counts, no "results") returned when no framework applies to the file.
    if not any(
        isinstance(report.get("results"), dict) or isinstance(report.get("failed"), int)
        for report in reports
    ):
        return None
    return reports


def run_checkov(file_path: str, timeout: int = 300) -> list[ValidationIssue]:
    """Run checkov and parse results.

    Checkov exits 0 when nothing failed and 1 when checks failed; both are
    normal. Any other exit, empty output on exit 1, unparseable JSON, or an unexpected
    payload shape is an operational error reported at HIGH severity, so an
    incomplete scan can never be mistaken for a clean one.
    """
    issues: list[ValidationIssue] = []

    try:
        result = subprocess.run(
            [
                PYTHON_EXECUTABLE,
                "-m",
                "checkov.main",
                "-f",
                file_path,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode not in (0, 1):
            issues.append(
                _checkov_operational_error(
                    file_path,
                    f"exit code {result.returncode}{_diagnostic_suffix(result)}",
                )
            )
            return issues

        if not result.stdout.strip():
            if result.returncode == 0:
                return issues  # exit 0 and no report: nothing applicable to scan
            issues.append(
                _checkov_operational_error(
                    file_path,
                    f"no report produced (exit code {result.returncode})"
                    f"{_diagnostic_suffix(result)}",
                )
            )
            return issues

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            issues.append(
                _checkov_operational_error(
                    file_path,
                    f"could not parse JSON report ({e.msg} at line {e.lineno})",
                )
            )
            return issues

        reports = _parse_checkov_report(data)
        if reports is None:
            issues.append(
                _checkov_operational_error(
                    file_path,
                    f"unexpected report structure ({type(data).__name__})",
                )
            )
            return issues

        for report in reports:
            results = report.get("results")
            if not isinstance(results, dict):
                continue
            for check in results.get("failed_checks", []) or []:
                if not isinstance(check, dict):
                    continue
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                severity = severity_map.get(
                    str(check.get("severity") or "HIGH").upper(),
                    Severity.HIGH,
                )

                line_num = None
                if check.get("file_line_range") and len(check["file_line_range"]) > 0:
                    line_num = check["file_line_range"][0]

                issues.append(
                    ValidationIssue(
                        tool="checkov",
                        severity=severity,
                        message=check.get("check_name", "Security check failed"),
                        line=line_num,
                        rule=check.get("check_id", ""),
                        file_path=file_path,
                    )
                )

    except subprocess.TimeoutExpired:
        issues.append(
            ValidationIssue(
                tool="checkov",
                severity=Severity.HIGH,
                message=f"checkov execution timed out after {timeout} seconds.",
                rule=OPERATIONAL_ERROR_RULE,
                file_path=file_path,
            )
        )
    except OSError as e:
        issues.append(
            ValidationIssue(
                tool="checkov",
                severity=Severity.HIGH,
                message=f"checkov execution failed: {e!s}",
                rule=OPERATIONAL_ERROR_RULE,
                file_path=file_path,
            )
        )

    return issues


# ─────────────────────────────────────────────────────────────────────────────
def _tool_execution(tool: str, issues: list[ValidationIssue]) -> ToolExecution:
    """Derive how a tool ran from the issues it returned."""
    failure = next((i for i in issues if i.rule == OPERATIONAL_ERROR_RULE), None)
    if failure is None:
        return ToolExecution(tool, ToolStatus.COMPLETED)
    return ToolExecution(tool, ToolStatus.FAILED, failure.message)


def validate_yaml_file(  # noqa: PLR0915
    file_path: str,
    tools: ToolAvailability | None = None,
    timeout: int = 300,
    no_security: bool = False,
    quiet: bool = False,
) -> ValidationResult:
    """Validate a YAML file using all available tools.

    Args:
        file_path:   Path to the YAML file to validate.
        tools:       Which external tools are available (probed automatically if None).
        timeout:     Subprocess timeout in seconds.
        no_security: Skip Checkov security checks.
        quiet:       Suppress all progress output (used in JSON mode so stdout stays clean).
    """
    if tools is None:
        tools = ToolAvailability()

    def _say(text: str, severity: Severity = Severity.INFO, bold: bool = False) -> None:
        if not quiet:
            print_colored(text, severity, bold=bold)

    _say(f"\n🔍 Validating: {file_path}", Severity.INFO, bold=True)
    _say("=" * 60, Severity.INFO)
    if not no_security and not quiet:
        warn_if_large_file(file_path)

    all_issues: list[ValidationIssue] = []
    tool_status: list[ToolExecution] = []
    syntax_valid = True

    # 1. Check YAML syntax
    _say("\n📋 Checking YAML syntax...", Severity.INFO)
    syntax_issues = validate_yaml_syntax(file_path)
    all_issues.extend(syntax_issues)

    if syntax_issues:
        syntax_valid = False
        _say("❌ Syntax validation failed", Severity.CRITICAL)
    else:
        _say("✅ Syntax validation passed", Severity.INFO)

    # 2. Run yamllint
    _say("\n🔧 Running yamllint...", Severity.INFO)
    yamllint_issues = run_yamllint(file_path, timeout=timeout)
    all_issues.extend(yamllint_issues)
    tool_status.append(_tool_execution("yamllint", yamllint_issues))

    if tool_status[-1].failed:
        _say("❌ yamllint did not complete", Severity.HIGH)
    elif yamllint_issues:
        _say(f"⚠️  Found {len(yamllint_issues)} linting issues", Severity.MEDIUM)
    else:
        _say("✅ No linting issues found", Severity.INFO)

    # 3. Run checkov (if available)
    if no_security or not tools.checkov:
        skipped_by = "--no-security" if no_security else "checkov not available"
        reason = "security checks disabled" if no_security else skipped_by
        tool_status.append(ToolExecution("checkov", ToolStatus.SKIPPED, reason))
        _say(f"\n⚠️  Security checks skipped ({skipped_by})", Severity.MEDIUM)
    else:
        _say("\n🔒 Running security checks (checkov)...", Severity.INFO)
        checkov_issues = run_checkov(file_path, timeout=timeout)
        all_issues.extend(checkov_issues)
        tool_status.append(_tool_execution("checkov", checkov_issues))

        if tool_status[-1].failed:
            _say("❌ checkov did not complete", Severity.HIGH)
        elif checkov_issues:
            _say(f"🚨 Found {len(checkov_issues)} security issues", Severity.HIGH)
        else:
            _say("✅ No security issues found", Severity.INFO)

    # Generate summary
    summary = {
        "total": len(all_issues),
        "critical": len([i for i in all_issues if i.severity == Severity.CRITICAL]),
        "high": len([i for i in all_issues if i.severity == Severity.HIGH]),
        "medium": len([i for i in all_issues if i.severity == Severity.MEDIUM]),
        "low": len([i for i in all_issues if i.severity == Severity.LOW]),
        "info": len([i for i in all_issues if i.severity == Severity.INFO]),
    }

    return ValidationResult(
        file_path=file_path,
        syntax_valid=syntax_valid,
        issues=all_issues,
        summary=summary,
        tool_status=tool_status,
    )


__all__ = [
    "LARGE_FILE_WARNING_THRESHOLD",
    "OPERATIONAL_ERROR_RULE",
    "run_checkov",
    "run_yamllint",
    "validate_yaml_file",
    "validate_yaml_syntax",
    "warn_if_large_file",
]
