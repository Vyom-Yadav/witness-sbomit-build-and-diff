from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class PipelineStep(StrEnum):
    DISCOVER = "discover"
    EXECUTE = "execute"
    ANALYZE_DIFF = "analyze_diff"
    CLASSIFY = "classify"
    STORE = "store"
    COMPLETE = "complete"


@dataclass
class PipelineState:
    run_id: str = ""
    discovery_result: dict | None = None
    build_result: dict | None = None
    diff_result: dict | None = None
    classifications: list[dict] | None = None
    agent_metrics: dict | None = None
    human_overrides: dict = field(default_factory=dict)
    override_history: list[dict] = field(default_factory=list)


@dataclass
class PipelineInput:
    repo_url: str
    commit_sha: str | None = None
    run_id: str = ""


@dataclass
class HumanOverride:
    step: PipelineStep
    package_name: str
    override_field: str
    original_value: str
    new_value: str
    reason: str
    human_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
