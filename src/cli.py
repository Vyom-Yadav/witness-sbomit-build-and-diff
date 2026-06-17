from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.config import settings
from src.orchestrator.models import HumanOverride, PipelineStep

app = typer.Typer(
    name="sbomit-analyzer",
    help="SBOM Accuracy Analyzer — compare sbomit vs syft SBOMs across witness versions",
    no_args_is_help=True,
)
console = Console()


@app.command()
def run(
    repo_url: str = typer.Option(..., help="Git repository URL"),
    commit_sha: str = typer.Option(None, help="Commit SHA to build (default: latest)"),
) -> None:
    """Start a new analysis pipeline."""
    from src.orchestrator.client import start_pipeline

    commit_display = commit_sha[:8] if commit_sha else "latest"
    console.print(Panel(f"Starting analysis for {repo_url} @ {commit_display}", style="bold blue"))

    run_id = asyncio.run(start_pipeline(repo_url, commit_sha))

    console.print("[green]Pipeline started[/green]")
    console.print(f"  Run ID:     {run_id}")
    console.print(f"  Repository: {repo_url}")
    console.print(f"  Commit:     {commit_display}")
    console.print(f"\n  Monitor with: sbomit-analyzer detail --run-id {run_id}")


@app.command()
def rerun(
    run_id: str = typer.Option(..., help="Run ID to re-execute"),
    from_step: str = typer.Option(
        "classify",
        help="Step to re-run from: discover, execute, analyze_diff, classify",
    ),
) -> None:
    """Re-run a pipeline from a specific step."""
    from src.storage import get_run

    run_data = get_run(run_id)
    if not run_data:
        console.print(f"[red]Run {run_id} not found[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"Re-running {run_id} from step: {from_step}", style="bold yellow"))

    from src.orchestrator.client import start_pipeline

    new_run_id = asyncio.run(start_pipeline(
        run_data["repo_url"],
        run_data["commit_sha"],
    ))

    console.print("[green]Re-run started[/green]")
    console.print(f"  New Run ID: {new_run_id}")


@app.command()
def override(
    run_id: str = typer.Option(..., help="Run ID to override"),
    package: str = typer.Option(..., help="Package name to override"),
    classification: str = typer.Option(
        ...,
        help="New classification: sbomit_correct, syft_correct, inconclusive",
    ),
    reason: str = typer.Option(..., help="Reason for the override"),
    human_id: str = typer.Option("human", help="Identifier of the person overriding"),
) -> None:
    """Override a classification and re-run from that point."""
    from src.storage import get_classifications_for_run

    classifications = get_classifications_for_run(run_id)
    target = None
    for cls in classifications:
        if cls["package_name"] == package:
            target = cls
            break

    if not target:
        console.print(f"[red]No classification found for package '{package}' in run {run_id}[/red]")
        raise typer.Exit(1)

    override_obj = HumanOverride(
        step=PipelineStep.CLASSIFY,
        package_name=package,
        override_field="classification",
        original_value=str(target["classification"]),
        new_value=classification,
        reason=reason,
        human_id=human_id,
    )

    console.print(Panel(
        f"Overriding classification for {package}\n"
        f"  Original:  {target['classification']}\n"
        f"  New:       {classification}\n"
        f"  Reason:    {reason}",
        style="bold yellow",
    ))

    from src.orchestrator.client import send_override

    asyncio.run(send_override(run_id, override_obj))

    console.print("[green]Override applied. Pipeline will re-run from classify step.[/green]")


@app.command()
def history(
    repo_url: str = typer.Option(None, help="Filter by repository URL"),
    limit: int = typer.Option(20, help="Max results"),
) -> None:
    """List past analysis runs."""
    from src.storage import list_runs

    runs = list_runs(repo_url=repo_url, limit=limit)

    if not runs:
        console.print("[dim]No runs found[/dim]")
        return

    table = Table(title="Analysis Runs")
    table.add_column("Run ID", style="cyan")
    table.add_column("Repository", style="green")
    table.add_column("Commit", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Confidence")
    table.add_column("Timestamp")

    for r in runs:
        status_style = {
            "complete": "green",
            "failed": "red",
            "needs_review": "yellow",
        }.get(str(r["status"]), "dim")

        ts = r["timestamp"]
        ts_str = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") and ts else "N/A"
        conf = float(r["confidence_score"]) if r["confidence_score"] is not None else None

        table.add_row(
            str(r["id"])[:8],
            str(r["repo_url"]).split("/")[-1],
            str(r["commit_sha"])[:8],
            f"[{status_style}]{r['status']}[/{status_style}]",
            f"{conf:.2f}" if conf is not None else "N/A",
            ts_str,
        )

    console.print(table)


@app.command()
def detail(
    run_id: str = typer.Option(..., help="Run ID to inspect"),
) -> None:
    """Show detailed results for a specific run."""
    from src.storage import (
        get_classifications_for_run,
        get_metrics_for_run,
        get_overrides_for_run,
        get_run,
    )

    run_data = get_run(run_id)
    if not run_data:
        console.print(f"[red]Run {run_id} not found[/red]")
        raise typer.Exit(1)

    # Run info
    console.print(Panel(
        f"Repository: {run_data['repo_url']}\n"
        f"Commit:     {run_data['commit_sha']}\n"
        f"Status:     {run_data['status']}\n"
        f"Confidence: {run_data['confidence_score']}",
        title=f"Run {str(run_data['id'])[:8]}",
        style="bold blue",
    ))

    # Metrics
    metrics = get_metrics_for_run(run_id)
    if metrics:
        console.print(Panel(
            f"Total diffs:      {metrics['total_diffs']}\n"
            f"Avg confidence:   {metrics['avg_confidence']:.2f}\n"
            f"sbomit accuracy:  {metrics['sbomit_accuracy']:.1%}\n"
            f"syft accuracy:    {metrics['syft_accuracy']:.1%}\n"
            f"Inconclusive:     {metrics['inconclusive_count']}\n"
            f"Human overridden: {metrics['human_overridden']}",
            title="Agent Metrics",
            style="bold green",
        ))

    # Classifications
    classifications = get_classifications_for_run(run_id)
    if classifications:
        table = Table(title="Classifications")
        table.add_column("Package", style="cyan")
        table.add_column("Type")
        table.add_column("sbomit")
        table.add_column("syft")
        table.add_column("Classification", style="bold")
        table.add_column("Confidence")

        for cls in classifications:
            style = {
                "sbomit_correct": "yellow",
                "syft_correct": "blue",
                "inconclusive": "dim",
            }.get(str(cls["classification"]), "")

            table.add_row(
                str(cls["package_name"]),
                "",
                "",
                "",
                f"[{style}]{cls['classification']}[/{style}]",
                f"{float(cls['confidence']):.2f}",
            )

        console.print(table)

    # Overrides
    overrides = get_overrides_for_run(run_id)
    if overrides:
        console.print(Panel(
            "\n".join(
                f"  {o['package_name']}: {o['original_classification']} -> "
                f"{o['new_classification']} "
                f"(by {o['human_id']}: {o['reason']})"
                for o in overrides
            ),
            title="Human Overrides",
            style="bold yellow",
        ))


@app.command()
def audit(
    run_id: str = typer.Option(..., help="Run ID to audit"),
    output: str = typer.Option("audit.json", help="Output file path"),
) -> None:
    """Export all overrides for a run as JSON (audit trail)."""
    from src.storage import get_classifications_for_run, get_overrides_for_run, get_run

    run_data = get_run(run_id)
    if not run_data:
        console.print(f"[red]Run {run_id} not found[/red]")
        raise typer.Exit(1)

    overrides = get_overrides_for_run(run_id)
    classifications = get_classifications_for_run(run_id)

    ts = run_data["timestamp"]
    ts_iso = ts.isoformat() if hasattr(ts, "isoformat") and ts else None

    audit_data = {
        "run_id": run_id,
        "repo_url": run_data["repo_url"],
        "commit_sha": run_data["commit_sha"],
        "timestamp": ts_iso,
        "total_classifications": len(classifications),
        "total_overrides": len(overrides),
        "overrides": [
            {
                "package": o["package_name"],
                "original": o["original_classification"],
                "override": o["new_classification"],
                "reason": o["reason"],
                "human_id": o["human_id"],
                "applied_at": (
                    o["applied_at"].isoformat() if o["applied_at"] else None
                ),
            }
            for o in overrides
        ],
    }

    Path(output).write_text(json.dumps(audit_data, indent=2))
    console.print(f"[green]Audit trail exported to {output}[/green]")


@app.command()
def export(
    run_id: str = typer.Option(..., help="Run ID to export"),
    output: str = typer.Option("result.json", help="Output file path"),
) -> None:
    """Export full analysis results as JSON."""
    from src.storage import (
        get_classifications_for_run,
        get_diffs_for_run,
        get_metrics_for_run,
        get_run,
    )

    run_data = get_run(run_id)
    if not run_data:
        console.print(f"[red]Run {run_id} not found[/red]")
        raise typer.Exit(1)

    diffs = get_diffs_for_run(run_id)
    classifications = get_classifications_for_run(run_id)
    metrics = get_metrics_for_run(run_id)

    result = {
        "run_id": run_id,
        "repo_url": run_data["repo_url"],
        "commit_sha": run_data["commit_sha"],
        "status": run_data["status"],
        "confidence_score": run_data["confidence_score"],
        "build_instruction": run_data["build_instruction"],
        "sbom_strategy": run_data["sbom_strategy"],
        "diffs": [
            {
                "diff_type": d["diff_type"],
                "package_name": d["package_name"],
                "purl": d["purl"],
                "sha256": d["sha256"],
                "sbomit_value": d["sbomit_value"],
                "syft_value": d["syft_value"],
            }
            for d in diffs
        ],
        "classifications": [
            {
                "package_name": c["package_name"],
                "classification": c["classification"],
                "confidence": float(c["confidence"]),
                "reasoning": c["reasoning"],
                "human_overridden": bool(c["human_overridden"]),
            }
            for c in classifications
        ],
        "metrics": {
            "total_diffs": int(metrics["total_diffs"]),
            "classified": metrics["classified"],
            "avg_confidence": float(metrics["avg_confidence"]),
            "sbomit_accuracy": float(metrics["sbomit_accuracy"]),
            "syft_accuracy": float(metrics["syft_accuracy"]),
            "inconclusive_count": int(metrics["inconclusive_count"]),
            "human_overridden": int(metrics["human_overridden"]),
        } if metrics else None,
    }

    Path(output).write_text(json.dumps(result, indent=2))
    console.print(f"[green]Results exported to {output}[/green]")


@app.command()
def worker() -> None:
    """Start the Temporal worker (run in separate terminal)."""
    import asyncio

    from src.orchestrator.client import start_worker

    console.print(Panel("Starting Temporal worker...", style="bold green"))
    asyncio.run(start_worker())


if __name__ == "__main__":
    app()
