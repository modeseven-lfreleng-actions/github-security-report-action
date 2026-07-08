# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Severity scale and normalisation.

Phase 0 (see ``docs/phase0-findings.md``) established two severity vocabularies
in the code-scanning feed:

- ``rule.security_severity_level`` -- critical / high / medium / low -- used by
  CodeQL and Scorecard, and the primary ranking key.
- ``rule.severity`` -- error / warning / note -- the SARIF level, the only axis
  zizmor populates.

To present a single, uniform set of severity columns across every table (as the
design requires), the SARIF level is normalised onto the security scale when no
security severity is present: error -> high, warning -> medium, note -> low,
and none -> informational. Dependabot's ``security_advisory.severity`` maps
directly.

The ``note`` mapping mirrors zizmor's own SARIF encoder, which emits both its
Low and Informational findings at SARIF level ``note`` (Medium -> ``warning``,
High -> ``error``). The organisation scan pipeline runs zizmor with
``--min-severity low``, so informational findings never reach the uploaded
SARIF: every ``note`` alert in code scanning is a genuine Low finding, and the
ruleset-enforced PR gate blocks on it. Mapping ``note`` below LOW would
(and previously did) under-state the estate's posture relative to that gate.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity. Higher value == more severe (worst-first sorting).

    ``INFORMATIONAL`` is the lowest rung (below ``LOW``): SARIF ``none``
    findings and unclassifiable alerts normalise here, so a category can
    choose to treat them as non-actionable via its ``fail_severity`` cutoff.
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


# Direct names on the security-severity scale (CodeQL, Scorecard, Dependabot).
_SECURITY_NAMES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,  # Dependabot uses "moderate"
    "low": Severity.LOW,
}

# SARIF level -> security scale, used only as a fallback (zizmor). zizmor's
# SARIF encoder emits Low AND Informational findings as ``note``, but the scan
# pipeline's --min-severity low floor keeps informational findings out of the
# SARIF entirely, so a ``note`` alert is a genuine Low finding (matching the
# ruleset-enforced PR gate, which blocks on note-and-above). The rare ``none``
# level stays at INFORMATIONAL.
_SARIF_LEVEL_NAMES: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}


def from_name(value: str | None) -> Severity | None:
    """Parse a security-severity name (critical/high/medium/low/moderate)."""
    if not value:
        return None
    return _SECURITY_NAMES.get(value.strip().lower())


def from_sarif_level(value: str | None) -> Severity | None:
    """Parse a SARIF level (error/warning/note) onto the security scale."""
    if not value:
        return None
    return _SARIF_LEVEL_NAMES.get(value.strip().lower())


def from_code_scanning(
    security_severity_level: str | None,
    sarif_severity: str | None,
) -> Severity:
    """Resolve a code-scanning alert's severity.

    Prefers ``security_severity_level``; falls back to the SARIF ``severity``
    (the zizmor case). Defaults to ``INFORMATIONAL`` when neither is recognised
    so an unclassifiable finding is never silently dropped from ranking, yet is
    not over-stated as a low-or-higher concern.
    """
    sarif = from_sarif_level(sarif_severity)
    resolved = from_name(security_severity_level)
    if resolved is None:
        resolved = sarif
    return resolved if resolved is not None else Severity.INFORMATIONAL
