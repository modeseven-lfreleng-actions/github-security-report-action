# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Security and quality reporting across GitHub organisations."""

from __future__ import annotations

try:  # pragma: no cover - resolved at build time by hatch-vcs
    from github_security_report._version import __version__
except ImportError:  # pragma: no cover - editable/source checkout without build
    __version__ = "0.0.0+unknown"


__all__ = ["__version__"]
