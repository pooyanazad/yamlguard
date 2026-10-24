"""
yamlguard.models
=====================
Dataclasses and enums shared across the package.

  Severity         — CRITICAL / HIGH / MEDIUM / LOW / INFO
  ToolStatus       — COMPLETED / SKIPPED / FAILED
  ToolExecution    — how one tool ran for one file
  ValidationIssue  — one problem found in a YAML file
  ValidationResult — full result for one file
  ToolAvailability — which external tools are present
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ===== IMPORTS & DEPENDENCIES =====
try:
    from colorama import Fore, Style, init

    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class Fore:  # type: ignore[no-redef]
        RED = ""
        YELLOW = ""
        GREEN = ""
        CYAN = ""
        WHITE = ""

    class Style:  # type: ignore[no-redef]
        BRIGHT = ""
        RESET_ALL = ""


# ===== ENUMS =====
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ToolStatus(Enum):
    """Whether a tool actually produced a usable result for a file."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH: Fore.RED,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.GREEN,
}


# ===== DATACLASSES =====
@dataclass
class ValidationIssue:
    tool: str
    severity: Severity
    message: str
    line: int | None = None
    column: int | None = None
    rule: str | None = None
    file_path: str | None = None


@dataclass
class ToolExecution:
    """How one tool ran for one file, independent of any finding severity."""

    tool: str
    status: ToolStatus
    reason: str | None = None

    @property
    def failed(self) -> bool:
        return self.status is ToolStatus.FAILED


@dataclass
class ValidationResult:
    file_path: str
    syntax_valid: bool
    issues: list[ValidationIssue]
    summary: dict[str, int]
    # Defaults keep existing callers that build ValidationResult positionally working.
    tool_status: list[ToolExecution] = field(default_factory=list)

    @property
    def has_operational_failure(self) -> bool:
        """True when any tool failed to complete, regardless of finding severity."""
        return any(execution.failed for execution in self.tool_status)


@dataclass
class ToolAvailability:
    """Tracks which external tools are available on the system."""

    yamllint: bool = True
    checkov: bool = True


__all__ = [
    "SEVERITY_COLORS",
    "Severity",
    "ToolAvailability",
    "ToolExecution",
    "ToolStatus",
    "ValidationIssue",
    "ValidationResult",
]
