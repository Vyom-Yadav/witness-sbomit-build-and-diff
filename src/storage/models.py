from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class RunStatus(StrEnum):
    PENDING = "pending"
    DISCOVERING = "discovering"
    RECONCILING = "reconciling"
    BUILDING = "building"
    ANALYZING = "analyzing"
    CLASSIFYING = "classifying"
    COMPLETE = "complete"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class PipelineStep(StrEnum):
    DISCOVER = "discover"
    RECONCILE = "reconcile"
    EXECUTE = "execute"
    ANALYZE_DIFF = "analyze_diff"
    CLASSIFY = "classify"
    STORE = "store"
    COMPLETE = "complete"


def _new_id() -> str:
    return str(uuid4())


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    repo_url: Mapped[str] = mapped_column(String, nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    status: Mapped[str] = mapped_column(String, default=RunStatus.PENDING.value)
    build_instruction: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    sbom_strategy: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reconciled_plan: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    state_checkpoint: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    artifacts: Mapped[list[BuildArtifact]] = relationship(
        "BuildArtifact", back_populates="run", cascade="all, delete-orphan"
    )
    diffs: Mapped[list[SBOMDiff]] = relationship(
        "SBOMDiff", back_populates="run", cascade="all, delete-orphan"
    )
    classifications: Mapped[list[Classification]] = relationship(
        "Classification", back_populates="run", cascade="all, delete-orphan"
    )
    metrics: Mapped[AgentMetrics | None] = relationship(
        "AgentMetrics", back_populates="run", uselist=False, cascade="all, delete-orphan"
    )
    overrides: Mapped[list[OverrideRecord]] = relationship(
        "OverrideRecord", back_populates="run", cascade="all, delete-orphan"
    )


class BuildArtifact(Base):
    __tablename__ = "build_artifacts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    witness_version: Mapped[str] = mapped_column(String, nullable=False)
    artifact_type: Mapped[str] = mapped_column(String, nullable=False)
    file_path: Mapped[str] = mapped_column(String, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String, nullable=True)

    run: Mapped[Run] = relationship("Run", back_populates="artifacts")


class SBOMDiff(Base):
    __tablename__ = "sbom_diffs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    diff_type: Mapped[str] = mapped_column(String, nullable=False)
    package_name: Mapped[str] = mapped_column(String, nullable=False)
    purl: Mapped[str | None] = mapped_column(String, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    sbomit_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    syft_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    run: Mapped[Run] = relationship("Run", back_populates="diffs")
    classification: Mapped[Classification | None] = relationship(
        "Classification", back_populates="diff", uselist=False
    )


class Classification(Base):
    __tablename__ = "classifications"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    diff_id: Mapped[str] = mapped_column(String, ForeignKey("sbom_diffs.id"), nullable=False)
    classification: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_files: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    human_overridden: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )

    run: Mapped[Run] = relationship("Run", back_populates="classifications")
    diff: Mapped[SBOMDiff] = relationship("SBOMDiff", back_populates="classification")


class AgentMetrics(Base):
    __tablename__ = "agent_metrics"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    total_diffs: Mapped[float] = mapped_column(Float, nullable=False)
    classified: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False)
    avg_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    sbomit_accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    syft_accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    inconclusive_count: Mapped[float] = mapped_column(Float, nullable=False)
    human_overridden: Mapped[float] = mapped_column(Float, default=0)
    token_usage: Mapped[float] = mapped_column(Float, default=0)

    run: Mapped[Run] = relationship("Run", back_populates="metrics")


class OverrideRecord(Base):
    __tablename__ = "override_history"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    classification_id: Mapped[str | None] = mapped_column(String, nullable=True)
    package_name: Mapped[str] = mapped_column(String, nullable=False)
    original_classification: Mapped[str] = mapped_column(String, nullable=False)
    new_classification: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    human_id: Mapped[str] = mapped_column(String, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )

    run: Mapped[Run] = relationship("Run", back_populates="overrides")
