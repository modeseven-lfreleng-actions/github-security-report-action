# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Transport tests for the async GitHub client (no live network: respx)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from github_security_report.client import GitHubClient

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"


@pytest.fixture
async def client() -> AsyncIterator[GitHubClient]:
    c = GitHubClient("test-token", concurrency=4)
    yield c
    await c.aclose()


@respx.mock
async def test_list_org_repos_skips_disabled_and_empty(client: GitHubClient) -> None:
    respx.get(f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name": "live", "full_name": "o/live", "html_url": "u", "size": 10},
                {"name": "empty", "full_name": "o/empty", "html_url": "u", "size": 0},
                {
                    "name": "dead",
                    "full_name": "o/dead",
                    "html_url": "u",
                    "size": 5,
                    "disabled": True,
                },
            ],
        )
    )
    status, repos = await client.list_org_repos("o")
    assert status == 200
    assert [r.name for r in repos] == ["live"]


@respx.mock
async def test_list_org_repos_reports_incomplete_status(client: GitHubClient) -> None:
    # A first page that succeeds followed by a failing page must surface the
    # failing status so the caller can flag the report as partial.
    page1 = httpx.Response(
        200,
        json=[{"name": "r1", "full_name": "o/r1", "html_url": "u", "size": 10}],
        headers={"Link": f'<{API}/orgs/o/repos?page=2>; rel="next"'},
    )
    page2 = httpx.Response(403)
    route = respx.get(url__startswith=f"{API}/orgs/o/repos")
    route.side_effect = [page1, page2]
    status, repos = await client.list_org_repos("o")
    assert status == 403
    assert [r.name for r in repos] == ["r1"]


@respx.mock
async def test_org_bulk_alerts_paginates(client: GitHubClient) -> None:
    page1 = httpx.Response(
        200,
        json=[{"number": 1}],
        headers={"Link": f'<{API}/orgs/o/code-scanning/alerts?page=2>; rel="next"'},
    )
    page2 = httpx.Response(200, json=[{"number": 2}])
    route = respx.get(url__startswith=f"{API}/orgs/o/code-scanning/alerts")
    route.side_effect = [page1, page2]
    status, alerts = await client.org_bulk_alerts("o", "code-scanning")
    assert status == 200
    assert [a["number"] for a in alerts] == [1, 2]


@respx.mock
async def test_org_bulk_alerts_reports_error_status(client: GitHubClient) -> None:
    # A forbidden sweep must surface its status so callers can degrade affected
    # signals to unknown rather than treating the empty result as clean.
    respx.get(url__startswith=f"{API}/orgs/o/dependabot/alerts").mock(
        return_value=httpx.Response(403)
    )
    status, alerts = await client.org_bulk_alerts("o", "dependabot")
    assert status == 403
    assert alerts == []


@respx.mock
async def test_get_list_later_page_failure_returns_partial_and_status(
    client: GitHubClient,
) -> None:
    # A first page that succeeds followed by a failing page must return the
    # partial items WITH the failing status, so callers know the data is
    # incomplete and do not report a falsely-clean undercount.
    page1 = httpx.Response(
        200,
        json=[{"number": 1}],
        headers={"Link": f'<{API}/orgs/o/dependabot/alerts?page=2>; rel="next"'},
    )
    page2 = httpx.Response(403)
    route = respx.get(url__startswith=f"{API}/orgs/o/dependabot/alerts")
    route.side_effect = [page1, page2]
    status, alerts = await client.org_bulk_alerts("o", "dependabot")
    assert status == 403
    assert [a["number"] for a in alerts] == [1]


@respx.mock
async def test_code_scanning_tools(client: GitHubClient) -> None:
    # Each signal tool is probed via the analyses tool_name filter; CodeQL and
    # Scorecard have analyses, zizmor does not.
    def _side(request: httpx.Request) -> httpx.Response:
        tool = request.url.params.get("tool_name")
        if tool in ("CodeQL", "Scorecard"):
            return httpx.Response(200, json=[{"tool": {"name": tool}}])
        return httpx.Response(200, json=[])

    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        side_effect=_side
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 200
    assert tools == {"CodeQL", "Scorecard"}


@respx.mock
async def test_code_scanning_tools_detects_low_frequency_tool(
    client: GitHubClient,
) -> None:
    # A tool the page-by-page scan could have missed (only zizmor present) is
    # detected definitively via its tool_name filter.
    def _side(request: httpx.Request) -> httpx.Response:
        tool = request.url.params.get("tool_name")
        if tool == "zizmor":
            return httpx.Response(200, json=[{"tool": {"name": "zizmor"}}])
        return httpx.Response(200, json=[])

    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        side_effect=_side
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 200
    assert tools == {"zizmor"}


@respx.mock
async def test_code_scanning_disabled_returns_404(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(404, json={"message": "no analysis found"})
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 404
    assert tools == set()


@respx.mock
async def test_secret_scanning_status(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(404)
    )
    assert await client.secret_scanning_status("o", "r") == 404


@respx.mock
async def test_dependabot_enabled_true_false_and_indeterminate(
    client: GitHubClient,
) -> None:
    route = respx.post(f"{API}/graphql")
    route.side_effect = [
        httpx.Response(
            200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": True}}}
        ),
        httpx.Response(
            200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": False}}}
        ),
        httpx.Response(200, json={"data": {"repository": None}}),
    ]
    assert await client.dependabot_enabled("o", "r") is True
    assert await client.dependabot_enabled("o", "r") is False
    assert await client.dependabot_enabled("o", "r") is None


@respx.mock
async def test_scorecard_score(client: GitHubClient) -> None:
    respx.get(f"{SCORECARD}/projects/github.com/o/good").mock(
        return_value=httpx.Response(200, json={"score": 8.2})
    )
    respx.get(f"{SCORECARD}/projects/github.com/o/none").mock(
        return_value=httpx.Response(404)
    )
    assert await client.scorecard_score("o", "good") == (200, 8.2)
    assert await client.scorecard_score("o", "none") == (404, None)


@respx.mock
async def test_backoff_retries_then_succeeds(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr("github_security_report.client.asyncio.sleep", _fake_sleep)
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = [
        httpx.Response(429, headers={"retry-after": "1"}),
        httpx.Response(200, json=[]),
    ]
    status = await client.secret_scanning_status("o", "r")
    assert status == 200
    assert slept == [1.0]


@respx.mock
async def test_genuine_403_not_retried(client: GitHubClient) -> None:
    # A 403 with rate-limit budget remaining is a real permission error.
    respx.get(f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 403


@respx.mock
async def test_transport_error_becomes_indeterminate(client: GitHubClient) -> None:
    # A transport failure (DNS/TLS/connect/read) must not abort the run; it is
    # converted into an indeterminate non-200 status so signals degrade.
    respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        side_effect=httpx.ConnectError("boom")
    )
    status = await client.secret_scanning_status("o", "r")
    assert status == 503


@respx.mock
async def test_org_workflow_rulesets(client: GitHubClient) -> None:
    respx.get(url__regex=r"orgs/o/rulesets($|\?)").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "name": "Zizmor scans",
                    "target": "branch",
                    "enforcement": "active",
                },
                {
                    "id": 2,
                    "name": "Evaluate only",
                    "target": "branch",
                    "enforcement": "evaluate",
                },
            ],
        )
    )
    respx.get(f"{API}/orgs/o/rulesets/1").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Zizmor scans",
                "enforcement": "active",
                "rules": [{"type": "workflows", "parameters": {"workflows": []}}],
            },
        )
    )
    status, details = await client.org_workflow_rulesets("o")
    assert status == 200
    # Only the active ruleset's detail is fetched; the evaluate-only one is skipped.
    assert [d["name"] for d in details] == ["Zizmor scans"]


@respx.mock
async def test_org_workflow_rulesets_forbidden(client: GitHubClient) -> None:
    respx.get(url__regex=r"orgs/o/rulesets($|\?)").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    status, details = await client.org_workflow_rulesets("o")
    assert status == 403
    assert details == []


@respx.mock
async def test_repo_branch_rules(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/rules/branches/main").mock(
        return_value=httpx.Response(200, json=[{"type": "workflows", "parameters": {}}])
    )
    status, rules = await client.repo_branch_rules("o", "r", "main")
    assert status == 200
    assert rules[0]["type"] == "workflows"


# --------------------------------------------------------------------------- #
# Dependabot posture + release/tag freshness probes
# --------------------------------------------------------------------------- #
@respx.mock
async def test_automated_security_fixes_enabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(200, json={"enabled": True, "paused": False})
    )
    assert await client.automated_security_fixes("o", "r") is True


@respx.mock
async def test_automated_security_fixes_404_is_disabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(404)
    )
    assert await client.automated_security_fixes("o", "r") is False


@respx.mock
async def test_automated_security_fixes_error_is_indeterminate(
    client: GitHubClient,
) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    assert await client.automated_security_fixes("o", "r") is None


@respx.mock
async def test_dependabot_config_returns_raw_body(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/contents/.github/dependabot.yml").mock(
        return_value=httpx.Response(200, text="version: 2\n")
    )
    status, text = await client.dependabot_config("o", "r")
    assert status == 200
    assert text == "version: 2\n"


@respx.mock
async def test_dependabot_config_missing(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/contents/.github/dependabot.yml").mock(
        return_value=httpx.Response(404)
    )
    status, text = await client.dependabot_config("o", "r")
    assert status == 404
    assert text == ""


@respx.mock
async def test_latest_release_at_parses_published(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/releases/latest").mock(
        return_value=httpx.Response(200, json={"published_at": "2026-01-02T03:04:05Z"})
    )
    when = await client.latest_release_at("o", "r")
    assert when is not None
    assert when.year == 2026 and when.month == 1 and when.day == 2


@respx.mock
async def test_latest_release_at_none_when_absent(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/releases/latest").mock(return_value=httpx.Response(404))
    assert await client.latest_release_at("o", "r") is None


@respx.mock
async def test_latest_tag_at_lightweight_commit(client: GitHubClient) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "refs": {
                            "nodes": [
                                {
                                    "target": {
                                        "__typename": "Commit",
                                        "committedDate": "2025-12-31T00:00:00Z",
                                    }
                                }
                            ]
                        }
                    }
                }
            },
        )
    )
    when = await client.latest_tag_at("o", "r")
    assert when is not None and when.year == 2025


@respx.mock
async def test_latest_tag_at_annotated_tag(client: GitHubClient) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "refs": {
                            "nodes": [
                                {
                                    "target": {
                                        "__typename": "Tag",
                                        "target": {
                                            "committedDate": "2025-06-01T00:00:00Z"
                                        },
                                    }
                                }
                            ]
                        }
                    }
                }
            },
        )
    )
    when = await client.latest_tag_at("o", "r")
    assert when is not None and when.month == 6


@respx.mock
async def test_latest_tag_at_none_when_no_tags(client: GitHubClient) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": {"repository": {"refs": {"nodes": []}}}}
        )
    )
    assert await client.latest_tag_at("o", "r") is None
