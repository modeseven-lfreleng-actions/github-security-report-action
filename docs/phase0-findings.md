<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Phase 0 findings

Results from running `scripts/phase0_capability_spike.py` against
`lfreleng-actions`. This records what the real APIs returned so the design in
[`BRIEF.md`](BRIEF.md) and [`adr/0001-architecture-and-scope.md`](adr/0001-architecture-and-scope.md)
can be confirmed or corrected. Raw output lives in the git-ignored
`phase0-output/` (not committed).

First run: `--org lfreleng-actions --sample 5` (97 repos total, 96 in default
scope), classic PAT with `security_events`, `repo`, `read:org`.

## Confirmed

- **Org-bulk endpoints work with the PAT** — all three returned `200`:
  `/orgs/{org}/code-scanning/alerts`, `/orgs/{org}/dependabot/alerts`,
  `/orgs/{org}/secret-scanning/alerts`. The **org-bulk-first** strategy is
  validated: the sampled five repos were individually clean, yet the org sweep
  surfaced real alerts — i.e. per-repo sampling misses offenders that the bulk
  sweep catches. Rate-limit cost is low (a few units per sweep).
- **Severity fields for ranking are present:**
  - code scanning: `rule.security_severity_level` ∈
    {critical, high, medium, low} **and** `rule.severity` ∈
    {error, warning, note}. Rank on `security_severity_level`, fall back to
    `severity`.
  - dependabot: `security_advisory.severity` plus
    `security_advisory.cvss.score` (and `cvss_severities`, `cwes`, `epss`).
- **Org-bulk alerts carry the full `repository` object** (`full_name`, `fork`,
  `private`, …) — so the ranked tables can be built entirely from the bulk
  sweep without per-repo alert calls.
- **Enabled-probes (positive cases) behave as designed:** code scanning
  `default-setup.state == "configured"`; secret scanning `200 []` =
  enabled-clean; Dependabot GraphQL `hasVulnerabilityAlertsEnabled == true`.

## Corrections to the design

### 1. Scorecard source pivots from the external API to code scanning

The external `api.securityscorecards.dev` endpoint returned **`404` for every
sampled repo** — the public Scorecard dataset does not cover our estate, so it
is **not** a viable source for us.

However, OpenSSF Scorecard results **are** present — uploaded as SARIF into
**code scanning**, surfacing as alerts with `tool.name == "Scorecard"`
(rule ids like `FuzzingID`, `security_severity_level` populated). Our repos run
the `openssf-scorecard` workflow, which publishes to code scanning rather than
the public API.

**Decision impact:** the Scorecard table is sourced from the code-scanning
sweep, partitioned by `tool.name`, **not** from `securityscorecards.dev`. Keep
the external API only as an optional enrichment if/when a repo is in the public
dataset.

### 2. The code-scanning endpoint multiplexes tools — partition by `tool.name`

`/code-scanning/alerts` returns findings from **all** uploaded analysis tools,
not just CodeQL. On `lfreleng-actions` the open code-scanning alerts are
predominantly `Scorecard`, with CodeQL (and potentially `zizmor`, `actionlint`,
etc.) mixed in.

**Decision impact:** the v1 signals must **partition the single code-scanning
sweep by `tool.name`**:

- `tool.name == "CodeQL"` → the CodeQL / code-scanning table.
- `tool.name == "Scorecard"` → the Scorecard table.
- other tools → out of v1 scope (candidate for a future "other scanners"
  section); must not leak into the CodeQL table.

Treating "all code-scanning alerts" as "CodeQL" would be wrong and would inflate
the CodeQL table with Scorecard/quality findings.

### 3. Scorecard aggregate score (0–10) is not in code-scanning alerts

Code scanning exposes Scorecard's **per-check findings** (with
`security_severity_level`), but **not** the aggregate 0–10 score. The score
lives in the Scorecard SARIF run properties / the external API (which 404s).

**Open question:** the Scorecard table metric likely shifts from "score
ascending" to **failing-check count / severity** (worst-first), unless we parse
the score from the SARIF run artifact. To be decided after a follow-up probe.

## Gaps — not yet observed (need targeted follow-up probes)

The sampled repos all had tooling enabled and were clean, so the **negative**
sides of the enabled-probe contract are unconfirmed:

- secret scanning `404` (feature disabled) — predicted but not seen.
- Dependabot `hasVulnerabilityAlertsEnabled == false` — not seen.
- code scanning `default-setup` `not-configured` / a repo with no CodeQL — not
  seen.
- a repo where code scanning is entirely absent (to confirm the
  empty-list-vs-disabled disambiguation end to end).

Follow-up: pick repos known to lack each feature (or a throwaway/private repo)
and re-run with explicit `--repo` to capture each negative status code.

## Spike refinements to make next

- Partition and **report code-scanning counts by `tool.name`** in the matrix
  (so CodeQL vs Scorecard volumes are visible directly).
- Probe a **deliberately under-configured repo** to capture the disabled/404
  cases above.
- Investigate the **Scorecard aggregate score** source (SARIF run properties vs
  external API) and decide the Scorecard metric.
- Capture **full first-page** alert samples (the current `scrub()` truncates
  lists to two entries — good for shape, insufficient for volume/fixtures).
- Inspect a **Dependabot org-bulk** page for the canonical `severity`/`cvss`
  location to finalise the ranking key.
