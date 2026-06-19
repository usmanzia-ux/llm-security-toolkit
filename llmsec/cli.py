"""Command-line interface for llm-security-toolkit."""

from __future__ import annotations

import argparse
import sys
from typing import List

from rich.console import Console
from rich.table import Table

from . import __version__, probes, reporters, scanner
from .models import ScanReport, Severity
from .targets import BACKENDS, build_target
from .targets.base import TargetError

console = Console()

_SEV_STYLE = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "blue",
    "Informational": "dim",
}
_FAIL_LEVELS = ["critical", "high", "medium", "low"]


def _list_probes() -> int:
    table = Table(title="Available probes", title_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Name")
    for p in probes.ALL_PROBES:
        table.add_row(
            p.probe_id,
            p.owasp.value.split(" ", 1)[0],
            f"[{_SEV_STYLE[p.severity.value]}]{p.severity.value}[/]",
            p.name,
        )
    console.print(table)
    return 0


def _print_summary(report: ScanReport) -> None:
    table = Table(title="Scan Results", title_style="bold cyan")
    table.add_column("Probe", style="bold")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Result")
    for p in report.probes:
        if p.vulnerable:
            result = "[bold red]VULNERABLE[/]"
            sev = f"[{_SEV_STYLE[p.severity.value]}]{p.severity.value}[/]"
        else:
            result = "[green]passed[/]"
            sev = "[dim]—[/]"
        table.add_row(p.probe_id, p.owasp.value.split(" ", 1)[0], sev, result)
    console.print(table)

    posture = report.posture()
    style = "green" if posture == "Pass" else _SEV_STYLE.get(posture, "bold")
    console.print(
        f"\nOverall posture: [{style}]{posture}[/]  "
        f"({report.vulnerable_count}/{len(report.probes)} probes vulnerable)"
    )


def _gate(report: ScanReport, fail_on: str) -> int:
    """Return a non-zero code if any finding is at/above the fail threshold."""
    if fail_on == "off":
        return 0
    threshold = Severity(fail_on.capitalize()).rank
    for p in report.probes:
        if p.vulnerable and p.severity.rank <= threshold:
            return 1
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="llmsec",
        description="Black-box security scanner for LLM-backed applications "
                    "(OWASP Top 10 for LLM Applications, 2025).",
    )
    parser.add_argument(
        "-t", "--target", default="mock",
        help="Target spec: backend[:model]. Backends: " + ", ".join(BACKENDS)
             + ". Default: mock (offline, no API key).",
    )
    parser.add_argument("--config", help="Config file for the 'http' target (YAML/JSON).")
    parser.add_argument("--system", help="System prompt to set on openai/anthropic targets.")
    parser.add_argument(
        "-p", "--probes", help="Comma-separated probe IDs to run (default: all). "
                               "See --list.",
    )
    parser.add_argument("-f", "--format", default="markdown",
                        choices=list(reporters.FORMATS), help="Report format (default: markdown).")
    parser.add_argument("-o", "--output", help="Report output path.")
    parser.add_argument(
        "--fail-on", default="off", choices=["off"] + _FAIL_LEVELS,
        help="Exit non-zero if a finding at/above this severity is confirmed "
             "(for CI gating). Default: off.",
    )
    parser.add_argument("--list", action="store_true", help="List available probes and exit.")
    parser.add_argument("-V", "--version", action="version",
                        version=f"llm-security-toolkit {__version__}")
    args = parser.parse_args(argv)

    console.print(f"[bold cyan]llm-security-toolkit[/bold cyan] v{__version__}\n")

    if args.list:
        return _list_probes()

    # Build the target.
    try:
        target = build_target(args.target, system=args.system, config_file=args.config)
    except TargetError as exc:
        console.print(f"[red]✗[/red] {exc}")
        return 2

    # Select probes.
    try:
        selected = probes.select(args.probes.split(",") if args.probes else None)
    except KeyError as exc:
        console.print(f"[red]✗[/red] unknown probe id: {exc}. Use --list to see valid IDs.")
        return 2

    console.print(f"Target: [bold]{target.label}[/bold]")
    console.print(f"Running [bold]{len(selected)}[/bold] probe(s)…\n")

    def _progress(p: probes.Probe) -> None:
        console.print(f"  [cyan]▸[/cyan] {p.probe_id}  {p.name}")

    try:
        report = scanner.scan(target, selected, on_probe=_progress)
    except Exception as exc:  # noqa: BLE001 - surface a clean message
        console.print(f"[red]✗[/red] scan failed: {exc}")
        return 2

    console.print()
    _print_summary(report)

    output = args.output or f"llmsec_report{reporters.extension(args.format)}"
    try:
        path = reporters.render(report, args.format, output)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]✗[/red] failed to write report: {exc}")
        return 2
    console.print(f"\n[green]✓ Report written:[/green] {path}")

    return _gate(report, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
