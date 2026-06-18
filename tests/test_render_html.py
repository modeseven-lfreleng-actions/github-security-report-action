# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for HTML rendering (Jinja2 + Simple-DataTables)."""

from __future__ import annotations

import datetime as dt

from github_security_report import report
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.render import html

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _org(name: str, signals: list[RepoSignal], count: int = 1) -> report.OrgReport:
    return report.build_org_report(name, signals, repo_count=count, generated_at=WHEN)


class TestOrgHtml:
    def test_contains_sections_and_data(self) -> None:
        signals = [
            RepoSignal(
                _repo("bad"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(critical=1),
            ),
            RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG),
        ]
        out = html.render_org_html(_org("lfreleng-actions", signals, count=2))
        assert "Security report: lfreleng-actions" in out
        # The decorative heading emoji is hidden from assistive tech.
        assert 'aria-hidden="true"' in out
        assert "CodeQL" in out
        assert '<a href="https://github.com/o/bad">bad</a>' in out
        assert "Not enabled" in out
        assert "nagme" in out

    def test_datatables_pinned_not_latest(self) -> None:
        out = html.render_org_html(_org("o", []))
        assert f"simple-datatables@{html.DATATABLES_VERSION}" in out
        assert "simple-datatables@latest" not in out
        assert "simpleDatatables.DataTable" in out
        # CDN assets carry Subresource Integrity hashes + crossorigin.
        assert f'integrity="{html.DATATABLES_CSS_SRI}"' in out
        assert f'integrity="{html.DATATABLES_JS_SRI}"' in out
        assert 'crossorigin="anonymous"' in out

    def test_html_escaping(self) -> None:
        # A pathological repo name must be escaped, not injected.
        signals = [
            RepoSignal(
                Repo("<x>", "o/<x>", "https://github.com/o/x"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(low=1),
            )
        ]
        out = html.render_org_html(_org("o", signals))
        assert "<x>" not in out.replace(
            "&lt;x&gt;", ""
        )  # only the escaped form appears

    def test_renders_dependabot_subtables_and_releases(self) -> None:
        org = _org("o", [], count=2)
        org.dependabot_tables = [
            report.TableSection(
                title="Enablement",
                columns=("Repository", "Dependabot alerts"),
                rows=[report.TableRow(repo=_repo("off"), cells=("❌ not enabled",))],
            )
        ]
        org.releases = report.TableSection(
            title="Releases / Tagging",
            columns=("Repository", "Last release", "Last tag"),
            rows=[report.TableRow(repo=_repo("stale"), cells=("never", "never"))],
            note="Ranked by combined staleness.",
        )
        out = html.render_org_html(org)
        assert "<h3>Enablement</h3>" in out
        assert '<a href="https://github.com/o/off">off</a>' in out
        assert "<h2>Releases / Tagging</h2>" in out
        assert '<a href="https://github.com/o/stale">stale</a>' in out
        assert "Ranked by combined staleness." in out


class TestIndexHtml:
    def test_card_per_org(self) -> None:
        orgs = [_org("alpha", [], count=3), _org("beta", [], count=7)]
        out = html.render_index_html(orgs)
        assert "alpha" in out and "beta" in out
        assert 'href="alpha/report.html"' in out
        assert "3 repositories" in out
        assert "7 repositories" in out

    def test_slugify(self) -> None:
        assert html.slugify("Linux Foundation") == "linux-foundation"

    def test_slugify_strips_path_traversal(self) -> None:
        # A hostile org name must never produce a path separator or ".." that
        # could escape the output directory.
        for hostile in ("../etc", "a/b", "..", "../../x"):
            slug = html.slugify(hostile)
            assert "/" not in slug
            assert ".." not in slug

    def test_slugify_empty_falls_back(self) -> None:
        assert html.slugify("///") == "org"
        assert html.slugify("   ") == "org"
