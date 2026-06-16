<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Scripts

## `phase0_capability_spike.py` (throwaway)

A self-contained [PEP 723](https://peps.python.org/pep-0723/) spike that
validates the GitHub security/quality APIs against a real organisation **before**
the tool's schema, columns, and rendering are designed. It is the executable
form of the Phase 0 gate described in
[`../docs/BRIEF.md`](../docs/BRIEF.md) and
[`../docs/adr/0001-architecture-and-scope.md`](../docs/adr/0001-architecture-and-scope.md).

It is **not** part of the package and carries no project dependency; `uv`
resolves its inline dependencies on the fly.

### Run

```bash
# A classic PAT with security_events, repo, read:org is required for the
# org-level security endpoints. The ephemeral Actions GITHUB_TOKEN will
# 403/404 on them — capturing that is itself a useful Phase 0 result.
export GITHUB_TOKEN=ghp_xxx

# Sample five in-scope repos from the default org:
uv run scripts/phase0_capability_spike.py --org lfreleng-actions --sample 5

# Or probe specific repos:
uv run scripts/phase0_capability_spike.py \
  --repo dependamerge --repo project-reporting-tool

# Use a differently named token variable:
uv run scripts/phase0_capability_spike.py --token-env SECURITY_REPORT_PAT
```

### What it answers (the Phase 0 open items)

- Which **org-bulk** endpoints actually return data for our PAT tier
  (`/orgs/{org}/{code-scanning,dependabot,secret-scanning}/alerts`).
- The **status-code semantics** that drive the per-signal enabled-probe
  contract (e.g. secret scanning `404` = disabled vs `200 []` = enabled-clean;
  code scanning `default-setup.state`; Dependabot
  `hasVulnerabilityAlertsEnabled`).
- Whether **OpenSSF Scorecard** data is published for our repos
  (`api.securityscorecards.dev`).
- Real response **shapes**, captured as scrubbed samples.

### Output

- `phase0-output/capability-matrix.json` — machine-readable results.
- `phase0-output/fixtures/<signal>/*.json` — scrubbed sample responses.
- A Rich table printed to the terminal.

**`phase0-output/` is git-ignored.** Captured data is live API output; a human
must review and scrub it before any sample is promoted to `tests/fixtures/` as a
golden fixture. The script applies aggressive automatic redaction (e.g. the
secret-scanning `secret` field) but that is a safety net, not a substitute for
review.

### Fixture sources

- **Enabled / populated states** — `lfreleng-actions` (production org, security
  features on org-wide).
- **Disabled states** — `modeseven-lfreleng-actions` (the **canonical**
  disabled-state source: forks default to security features off). The
  `dependamerge` fork there is a **mixed-state** repo (CodeQL + Scorecard on,
  secret scanning + Dependabot off) — ideal for exercising the four-state model
  in one fixture. Run e.g.
  `uv run scripts/phase0_capability_spike.py --org modeseven-lfreleng-actions
  --repo dependamerge --repo gha-workflow-linter`.
