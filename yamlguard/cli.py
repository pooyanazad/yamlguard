"""
yamlguard.cli
==================
Argparse entry-point, file resolution, and dependency checking.

  check_dependencies() — probe yamllint & checkov, return ToolAvailability
  resolve_files()      — expand paths / globs to a flat list of YAML files
  main()               — parse args, drive validation, set exit code
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import os
import subprocess
import sys
from pathlib import Path

# Re-export __version__ so callers can do `from yamlguard.cli import __version__`
from yamlguard import __version__
from yamlguard.models import Severity, ToolAvailability
from yamlguard.output import (
    print_colored,
    print_issues,
    print_json_result,
    print_junit_result,
    print_sarif_result,
    print_summary_table,
    print_tool_status,
)
from yamlguard.validators import validate_yaml_file

# ─────────────────────────────────────────────────────────────────────────────
_PYTHON = sys.executable


# ─────────────────────────────────────────────────────────────────────────────
def check_dependencies() -> ToolAvailability:
    """Check if required tools are installed and return their availability."""
    missing_tools: list[str] = []
    tools = ToolAvailability()

    # Check yamllint
    try:
        subprocess.run(
            [_PYTHON, "-m", "yamllint", "--version"],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        tools.yamllint = False
        missing_tools.append("yamllint")

    # Check checkov (optional)
    try:
        subprocess.run(
            [_PYTHON, "-c", "import checkov"],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        tools.checkov = False
        print_colored(
            "Warning: checkov not available, security checks will be skipped",
            Severity.MEDIUM,
        )

    if missing_tools:
        print_colored(
            f"Missing required tools: {', '.join(missing_tools)}",
            Severity.CRITICAL,
            bold=True,
        )
        print_colored("Install with: python3 -m pip install yamllint checkov", Severity.INFO)
        sys.exit(1)

    return tools


# ─────────────────────────────────────────────────────────────────────────────
def _contains_symlink(path: Path) -> bool:
    """Check every path component, including links to missing targets."""
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current /= part
        if current.is_symlink():
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
def _expand_paths(path_arg: str) -> tuple[list[Path], bool]:
    """Expand a path or glob without descending through symbolic links."""
    directory_only = path_arg.endswith(os.sep) or bool(os.altsep and path_arg.endswith(os.altsep))
    path = Path(path_arg)
    skipped_symlink = False
    if path.is_absolute():
        matches = [Path(path.anchor)]
        parts = path.parts[1:]
    else:
        matches = [Path(".")]
        parts = path.parts

    for part in parts:
        expanded: list[Path] = []
        for parent in matches:
            if part == "**":
                # Recursive glob expansion must prune links before entering them.
                for root, dirs, _ in os.walk(parent, followlinks=False):
                    dirs[:] = [
                        name
                        for name in dirs
                        if not name.startswith(".") and not (Path(root) / name).is_symlink()
                    ]
                    expanded.append(Path(root))
            else:
                # A matched parent is a literal path, even if its name contains
                # glob metacharacters (e.g. "a[1]"). Reinterpreting it here can
                # reopen a symlink that was filtered out in an earlier segment.
                for match in glob.iglob(str(Path(glob.escape(str(parent))) / part)):
                    candidate = Path(match)
                    if candidate.is_symlink():
                        skipped_symlink = True
                    else:
                        expanded.append(candidate)
        matches = expanded

    # Path strips trailing separators, but glob patterns ending in one match
    # directories only (e.g. "configs/*/").
    matches = [match for match in matches if not directory_only or match.is_dir()]

    # Keep the old literal-path fallback for names such as "odd[1]" while
    # rejecting links in every component, not just at the final file.
    if not matches and _contains_symlink(path):
        skipped_symlink = True
    elif not matches and path.exists() and (not directory_only or path.is_dir()):
        matches = [path]

    return matches, skipped_symlink


# ─────────────────────────────────────────────────────────────────────────────
def resolve_files(paths: list[str]) -> list[str]:
    """Resolve paths and globs to YAML files, skipping file and directory links."""
    yaml_extensions = {".yaml", ".yml"}
    resolved: list[str] = []
    seen: set[str] = set()

    for path_arg in paths:
        expanded, skipped_symlink = _expand_paths(path_arg)
        if not expanded and not skipped_symlink:
            print_colored(f"Warning: '{path_arg}' not found, skipping", Severity.MEDIUM)

        for item in expanded:
            p = item.resolve()

            if p.is_dir():
                for root, dirs, files in os.walk(p, followlinks=False):
                    dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
                    for name in sorted(files):
                        yaml_file = Path(root) / name
                        if yaml_file.suffix not in yaml_extensions or yaml_file.is_symlink():
                            continue
                        real = str(yaml_file.resolve())
                        if real not in seen:
                            seen.add(real)
                            resolved.append(str(yaml_file))
            elif p.is_file():
                real = str(p)
                if real not in seen:
                    seen.add(real)
                    resolved.append(str(p))
            else:
                print_colored(f"Warning: '{path_arg}' not found, skipping", Severity.MEDIUM)

    return resolved


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:  # noqa: PLR0912, PLR0915
    """Parse arguments, validate files, and set the process exit code."""
    parser = argparse.ArgumentParser(
        prog="yamlguard",
        description="Validate YAML files for syntax, linting, and security issues.",
        epilog=(
            "Examples:\n"
            "  yamlguard config.yaml\n"
            "  yamlguard config.yaml deployment.yaml\n"
            "  yamlguard ./configs/\n"
            '  yamlguard "./configs/**/*.yaml"\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="YAML files, directories, or glob patterns to validate",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for subprocess calls (default: 300)",
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip Checkov security checks",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "sarif", "junit"],
        default="text",
        metavar="FORMAT",
        help=(
            "Output format: 'text' (default, coloured), 'json' (machine-readable), "
            "'sarif' (SARIF v2.1.0, for GitHub code scanning) or "
            "'junit' (JUnit XML, for CI systems)"
        ),
    )

    args = parser.parse_args()

    # Diagnostics must not corrupt JSON, XML, or SARIF redirected from stdout.
    diagnostic_output = sys.stdout if args.format == "text" else sys.stderr
    with contextlib.redirect_stdout(diagnostic_output):
        yaml_files = resolve_files(args.files)

    if not yaml_files:
        with contextlib.redirect_stdout(diagnostic_output):
            print_colored(
                "Error: No YAML files found for the given paths",
                Severity.CRITICAL,
                bold=True,
            )
        sys.exit(1)

    with contextlib.redirect_stdout(diagnostic_output):
        tools = check_dependencies()

    # Any non-text format is machine-readable: keep stdout free of decoration.
    json_mode = args.format != "text"

    results = []
    has_critical_high = False
    has_operational_failure = False
    total_issues = 0

    for yaml_file in yaml_files:
        result = validate_yaml_file(
            yaml_file,
            tools,
            timeout=args.timeout,
            no_security=args.no_security,
            quiet=json_mode,
        )
        results.append(result)

        if not json_mode:
            print_issues(result.issues)
            print_tool_status(result.tool_status)
            print_summary_table(result.summary)

        critical_high = result.summary["critical"] + result.summary["high"]
        if critical_high > 0:
            has_critical_high = True
        if result.has_operational_failure:
            has_operational_failure = True
        total_issues += result.summary["total"]

    # ── Machine-readable output (single emit at the end) ──────────────────────
    if args.format == "json":
        print_json_result(results)
    elif args.format == "sarif":
        print_sarif_result(results)
    elif args.format == "junit":
        print_junit_result(results)
    # Combined summary for multi-file runs (text mode only)
    if not json_mode and len(yaml_files) > 1:
        print_colored("\n" + "=" * 60, Severity.INFO)
        print_colored("📊 Combined Results:", Severity.INFO, bold=True)
        print_colored(f"   Files scanned: {len(yaml_files)}", Severity.INFO)
        print_colored(f"   Total issues:  {total_issues}", Severity.INFO)

        combined = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
        }
        for r in results:
            for key in combined:
                combined[key] += r.summary[key]
        print_summary_table(combined)

        files_with_issues = [r for r in results if r.summary["total"] > 0]
        if files_with_issues:
            print_colored("\n📁 Files with issues:", Severity.MEDIUM, bold=True)
            for r in files_with_issues:
                ch = r.summary["critical"] + r.summary["high"]
                icon = "💥" if ch > 0 else "⚠️"
                print_colored(
                    f"   {icon} {r.file_path} ({r.summary['total']} issues)",
                    Severity.MEDIUM,
                )

    # Final status
    if not json_mode:
        print_colored("\n" + "=" * 60, Severity.INFO)
    if has_operational_failure:
        # A tool that did not finish means the scan is incomplete, so it can
        # never be reported as a success regardless of the findings it produced.
        if not json_mode:
            print_colored(
                "💥 Validation incomplete! A validator failed to run.",
                Severity.CRITICAL,
                bold=True,
            )
        sys.exit(1)
    if total_issues == 0:
        if not json_mode:
            print_colored(
                "🎉 Validation completed successfully! No issues found.",
                Severity.INFO,
                bold=True,
            )
        sys.exit(0)
    elif has_critical_high:
        if not json_mode:
            print_colored(
                "💥 Validation failed! Found critical/high severity issues.",
                Severity.CRITICAL,
                bold=True,
            )
        sys.exit(1)
    else:
        if not json_mode:
            print_colored(
                f"⚠️  Validation completed with {total_issues} minor issues.",
                Severity.MEDIUM,
                bold=True,
            )
        sys.exit(0)


__all__ = ["check_dependencies", "main", "resolve_files"]
