from __future__ import annotations

from temporalio.client import Client
from temporalio.worker import Worker

from src.config import settings
from src.orchestrator.activities import (
    analyze_diff_activity,
    classify_diffs_activity,
    discover_build_activity,
    execute_build_activity,
    store_results_activity,
)
from src.orchestrator.models import HumanOverride, PipelineInput
from src.orchestrator.workflows import SBOMAnalysisWorkflow


async def start_worker() -> None:
    """Start the Temporal worker."""
    client = await Client.connect(settings.temporal_address)

    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[SBOMAnalysisWorkflow],
        activities=[
            discover_build_activity,
            execute_build_activity,
            analyze_diff_activity,
            classify_diffs_activity,
            store_results_activity,
        ],
    )
    await worker.run()


async def start_pipeline(
    repo_url: str,
    commit_sha: str | None,
) -> str:
    """Start a new analysis pipeline. Returns the run ID."""
    
    # Create run in DB directly (no need for Temporal)
    from src.storage import create_run
    run_id = create_run(repo_url, commit_sha)

    # Connect to Temporal
    client = await Client.connect(settings.temporal_address)

    # Start the workflow
    workflow_id = f"sbomit-{run_id[:8]}"
    pipeline_input = PipelineInput(
        repo_url=repo_url,
        commit_sha=commit_sha,
        run_id=run_id,
    )

    await client.start_workflow(
        SBOMAnalysisWorkflow.run,
        pipeline_input,
        id=workflow_id,
        task_queue=settings.temporal_task_queue,
    )

    return run_id


async def send_override(
    workflow_id: str,
    override: HumanOverride,
) -> None:
    """Send a human override to a running workflow."""
    client = await Client.connect(settings.temporal_address)
    handle = client.get_workflow_handle(workflow_id)
    await handle.signal(SBOMAnalysisWorkflow.human_override, override)


async def get_workflow_state(workflow_id: str) -> dict | None:
    """Query the current state of a workflow."""
    client = await Client.connect(settings.temporal_address)
    handle = client.get_workflow_handle(workflow_id)
    try:
        result = await handle.result()
        return result
    except Exception:
        return None

