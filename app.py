#!/usr/bin/env python3
"""Compatibility entry point for yamlguard.

Use ``yamlguard`` or ``python -m yamlguard`` for new commands. This wrapper keeps
``python app.py`` and existing ``import app`` callers working.
"""

# ── version ───────────────────────────────────────────────────────────────────
from yamlguard import __version__  # noqa: F401

# ── CLI ───────────────────────────────────────────────────────────────────────
from yamlguard.cli import (  # noqa: F401
    check_dependencies,
    main,
    resolve_files,
)

# ── models ────────────────────────────────────────────────────────────────────
from yamlguard.models import (  # noqa: F401
    SEVERITY_COLORS,
    Severity,
    ToolAvailability,
    ToolExecution,
    ToolStatus,
    ValidationIssue,
    ValidationResult,
)

# ── output helpers ────────────────────────────────────────────────────────────
from yamlguard.output import (  # noqa: F401
    print_colored,
    print_issues,
    print_json_result,
    print_junit_result,
    print_sarif_result,
    print_summary_table,
    print_tool_status,
    result_to_json,
    results_to_junit,
    results_to_sarif,
)

# ── validators ────────────────────────────────────────────────────────────────
from yamlguard.validators import (  # noqa: F401
    run_checkov,
    run_yamllint,
    validate_yaml_file,
    validate_yaml_syntax,
)

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
