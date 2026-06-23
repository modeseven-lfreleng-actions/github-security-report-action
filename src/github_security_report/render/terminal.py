# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Rich terminal rendering.

The default presentation for local/TTY runs: one coloured table per signal,
worst-first, with clean/nag/unknown summaries beneath. The CLI falls back to a
plain console (no colour) in CI / non-TTY contexts. See ``docs/BRIEF.md``
sections 10-11.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.render import markdown
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableSection,
    note_sentences,
    truncate,
)

_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


def _add_columns(table: Table, signal: SignalType) -> None:
    table.add_column("Repository", overflow="fold")
    if signal is SignalType.SECRET_SCANNING:
        table.add_column("Open", justify="right")
        return
    if signal is SignalType.SCORECARD:
        table.add_column("Score", justify="right")
    for name, style in _SEVERITY_STYLE.items():
        table.add_column(name.capitalize(), justify="right", style=style)
    if signal is not SignalType.SCORECARD:
        table.add_column("Total", justify="right")


def _row(sig: RepoSignal) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    base = [str(c.critical), str(c.high), str(c.medium), str(c.low)]
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "—"
        return [sig.repo.name, score, *base]
    return [sig.repo.name, *base, str(c.total)]


def _names(repos: Sequence[Repo], top_n: int | None) -> str:
    """Comma-joined repo names limited to ``top_n`` with a '(+N more)' tail."""
    shown, hidden = truncate(repos, top_n)
    text = ", ".join(r.name for r in shown)
    if hidden:
        text += f" … (+{hidden} more)"
    return text


def _status_lines(
    *,
    clean: int,
    flagged: int,
    flagged_noun: str,
    excluded: int,
    unknown: int,
) -> list[str]:
    """The ✅/❌/⏩/❓ count lines shared by every feature's footer.

    Each numerical total sits on its own line and zero counts are omitted, so a
    section shows only the states that apply. The ❌ line's noun is
    feature-specific ("Disabled", "Stale", "Mutable", "Without cooldown", …)
    while the ✅/⏩/❓ labels are uniform across every feature.
    """
    lines: list[str] = []
    if clean:
        lines.append(f"[green]✅ {clean} Clean[/green]")
    if flagged:
        lines.append(f"[yellow]❌ {flagged} {flagged_noun}[/yellow]")
    if excluded:
        lines.append(f"[blue]⏩ {excluded} Excluded[/blue]")
    if unknown:
        lines.append(f"[dim]❓ {unknown} Unknown[/dim]")
    return lines


def render_section(
    section: SignalSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> None:
    offenders, hidden_offenders = truncate(section.offenders, top_n)
    if offenders:
        table = Table(title=section.signal.heading, title_justify="left", title_style="bold")
        _add_columns(table, section.signal)
        for sig in offenders:
            table.add_row(*_row(sig))
        # A trailing totals row sums the additive severity columns across the
        # rows shown above. Secret scanning has no such columns, so skip it.
        if section.signal.uses_severity_columns:
            table.add_section()
            table.add_row(
                *markdown.total_row_cells(section.signal, offenders),
                style="bold",
            )
        console.print(table)
        if hidden_offenders:
            console.print(f"  [dim]… and {hidden_offenders} more[/dim]")
    else:
        console.print(f"[bold]{section.signal.heading}[/bold]")
    # Numerical totals first (each on its own line, always the true total), then
    # the repository-name breakdowns -- numbers and names are never mixed on one
    # line, and the name lists honour the same offender limit as the tables.
    totals = _status_lines(
        clean=section.clean_count,
        flagged=len(section.nag_repos),
        flagged_noun="Disabled",
        excluded=len(excluded),
        unknown=section.unknown_count,
    )
    if not (offenders or totals):
        totals.append("[dim]No data[/dim]")
    for line in totals:
        console.print("  " + line)
    if section.nag_repos:
        console.print(f"  [yellow]Disabled:[/yellow] {_names(section.nag_repos, top_n)}")
    if excluded:
        console.print(f"  [blue]Excluded:[/blue] {_names(excluded, top_n)}")
    console.print()


def render_table_section(
    section: TableSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
    show_notes: bool = True,
) -> None:
    """Render a generic posture/freshness section to the terminal.

    Every feature shares the same status footer as the signal sections
    (✅ Clean / ❌ <noun> / ⏩ Excluded / ❓ Unknown). A single-column section
    carries no per-repository data beyond the name, so it is a *pure name list*:
    its table is dropped and the flagged repositories are listed inline as a
    "<noun>:" breakdown, exactly like a signal section's "Disabled:" line. A
    multi-column section keeps its data table (the extra columns -- ages,
    ecosystems, release tags -- cannot be expressed as counts) and shows the
    same count footer beneath it.

    ``show_notes`` gates the explanatory footnote lines (scope/ranking
    guidance); set it False (via ``report.cli_notes``) for a terser view that
    keeps the tables and the status footer but drops the guidance.
    """
    rows, hidden = truncate(section.rows, top_n)
    name_list = len(section.columns) == 1
    # The title is always a bare heading line; the counts are relocated beneath
    # so every category presents its results in the same place.
    console.print(f"[bold]{section.title}[/bold]")

    if not name_list and rows:
        table = Table(title_justify="left", title_style="bold")
        for i, col in enumerate(section.columns):
            table.add_column(col, overflow="fold", justify="left" if i == 0 else "right")
        for row in rows:
            table.add_row(row.repo.name, *row.cells)
        console.print(table)
        if hidden:
            console.print(f"  [dim]… and {hidden} more[/dim]")

    # Org-level exclusions apply to every feature, but only the name-list
    # sections mirror the signal-section footer that lists them; the columnar
    # sections describe their own (age/threshold) scope in the note instead.
    totals = _status_lines(
        clean=section.clean_count,
        flagged=len(section.rows),
        flagged_noun=section.flagged_noun,
        excluded=len(excluded) if name_list else 0,
        unknown=section.unknown_count,
    )
    if not totals:
        totals.append("[dim]No data[/dim]")
    for line in totals:
        console.print("  " + line)

    if name_list:
        if section.rows:
            names = _names([r.repo for r in section.rows], top_n)
            console.print(f"  [yellow]{section.flagged_noun}:[/yellow] {names}")
        if excluded:
            console.print(f"  [blue]Excluded:[/blue] {_names(excluded, top_n)}")

    # The guidance note describes a populated result, so it is shown only when
    # there are flagged repositories (mirrors the previous table-only note) and
    # the caller has not suppressed notes via ``report.cli_notes``.
    if show_notes and section.rows and section.note:
        for sentence in note_sentences(section.note):
            console.print(f"  [dim]{sentence}[/dim]")
    console.print()


def render_org(
    org: OrgReport,
    console: Console,
    *,
    top_n: int | None = None,
    show_notes: bool = True,
) -> None:
    console.rule(f"[bold]Security report: {org.org}[/bold]")
    console.print(f"[dim]{org.repo_count} repositories analysed[/dim]\n")
    if org.partial:
        console.print(
            "[yellow]⚠ Incomplete: the repository listing could not be fully "
            "read; some repositories may be missing.[/yellow]\n"
        )
    excluded = org.excluded_repos
    for section in org.sections:
        render_section(section, console, excluded=excluded, top_n=top_n)
        if section.signal is SignalType.DEPENDABOT:
            for table in org.dependabot_tables:
                render_table_section(
                    table,
                    console,
                    excluded=excluded,
                    top_n=top_n,
                    show_notes=show_notes,
                )
    if org.releases is not None:
        render_table_section(
            org.releases,
            console,
            excluded=excluded,
            top_n=top_n,
            show_notes=show_notes,
        )
    if org.mutable_releases is not None:
        render_table_section(
            org.mutable_releases,
            console,
            excluded=excluded,
            top_n=top_n,
            show_notes=show_notes,
        )
    if org.private_vulnerability_reporting is not None:
        render_table_section(
            org.private_vulnerability_reporting,
            console,
            excluded=excluded,
            top_n=top_n,
            show_notes=show_notes,
        )


def render_orgs(
    orgs: list[OrgReport],
    console: Console,
    *,
    top_n: int | None = None,
    show_notes: bool = True,
) -> None:
    for org in orgs:
        render_org(org, console, top_n=top_n, show_notes=show_notes)
