# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Git context detection for local repo-mode.

When run inside a Git checkout with no org config, the tool defaults to repo
mode for the repository the checkout points at. The remote is resolved in
preference order ``upstream`` then ``origin``, and only ``github.com`` remotes
qualify. See ``docs/BRIEF.md`` section 10.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable

log = logging.getLogger(__name__)

REMOTE_PREFERENCE = ("upstream", "origin")

# git@github.com:owner/repo(.git) or https://github.com/owner/repo(.git)
_SSH = re.compile(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$")
_HTTPS = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def parse_remote_url(url: str) -> tuple[str, str] | None:
    """Parse a github.com remote URL into ``(owner, repo)``; None otherwise."""
    url = url.strip()
    match = _SSH.match(url) or _HTTPS.match(url)
    if not match:
        return None
    return match.group("owner"), match.group("repo")


def _git_remote_url(name: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", name],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, FileNotFoundError):  # git not installed / not a repo
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def detect_repo(
    remote_reader: Callable[[str], str | None] = _git_remote_url,
) -> tuple[str, str] | None:
    """Resolve ``(owner, repo)`` from git remotes (upstream, then origin)."""
    for name in REMOTE_PREFERENCE:
        url = remote_reader(name)
        if not url:
            continue
        parsed = parse_remote_url(url)
        if parsed:
            log.info("detected %s/%s from the %s remote", parsed[0], parsed[1], name)
            return parsed
        log.debug("remote %s (%s) is not a github.com remote", name, url)
    return None
