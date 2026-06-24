from __future__ import annotations

from sqlalchemy import desc, select

from src.storage.db import get_session, init_db
from src.storage.models import (
    AgentMetrics,
    BuildArtifact,
    Classification,
    OverrideRecord,
    Run,
    RunStatus,
    SBOMDiff,
)


def create_run(
    repo_url: str,
    commit_sha: str | None,
) -> str:
    init_db()
    with get_session() as session:
        run = Run(
            repo_url=repo_url,
            commit_sha=commit_sha,
            status=RunStatus.PENDING.value,
        )
        session.add(run)
        session.flush()
        run_id: str = run.id
        session.commit()
        return run_id


def update_run_status(run_id: str, status: RunStatus) -> None:
    with get_session() as session:
        stmt = select(Run).where(Run.id == run_id)
        row = session.execute(stmt).first()
        if row:
            row[0].status = status.value
            session.commit()


def save_build_instruction(
    run_id: str, instruction: dict, sbom_strategy: dict, confidence: float
) -> None:
    with get_session() as session:
        stmt = select(Run).where(Run.id == run_id)
        row = session.execute(stmt).first()
        if row:
            run = row[0]
            run.build_instruction = instruction
            run.sbom_strategy = sbom_strategy
            run.confidence_score = confidence
            session.commit()


def save_reconciled_plan(run_id: str, plan: dict) -> None:
    with get_session() as session:
        stmt = select(Run).where(Run.id == run_id)
        row = session.execute(stmt).first()
        if row:
            row[0].reconciled_plan = plan
            session.commit()


def save_build_artifact(
    run_id: str,
    witness_version: str,
    artifact_type: str,
    file_path: str,
    sha256: str | None = None,
) -> None:
    with get_session() as session:
        artifact = BuildArtifact(
            run_id=run_id,
            witness_version=witness_version,
            artifact_type=artifact_type,
            file_path=file_path,
            sha256=sha256,
        )
        session.add(artifact)
        session.commit()


def save_diffs(run_id: str, diffs: list[dict]) -> None:
    with get_session() as session:
        for diff in diffs:
            sbom_diff = SBOMDiff(
                run_id=run_id,
                diff_type=diff["diff_type"],
                package_name=diff["package_name"],
                purl=diff.get("purl"),
                sha256=diff.get("sha256"),
                sbomit_value=diff.get("sbomit_value"),
                syft_value=diff.get("syft_value"),
                details=diff.get("details"),
            )
            session.add(sbom_diff)
        session.commit()


def save_classification(
    run_id: str,
    diff_id: str,
    classification: str,
    confidence: float,
    reasoning: str,
    evidence_files: list[str] | None = None,
) -> None:
    with get_session() as session:
        cls = Classification(
            run_id=run_id,
            diff_id=diff_id,
            classification=classification,
            confidence=confidence,
            reasoning=reasoning,
            evidence_files=evidence_files or [],
        )
        session.add(cls)
        session.commit()


def save_agent_metrics(run_id: str, metrics: dict) -> None:
    with get_session() as session:
        m = AgentMetrics(
            run_id=run_id,
            total_diffs=metrics["total_diffs"],
            classified=metrics["classified"],
            avg_confidence=metrics["avg_confidence"],
            sbomit_accuracy=metrics["sbomit_accuracy"],
            syft_accuracy=metrics["syft_accuracy"],
            inconclusive_count=metrics["inconclusive_count"],
            human_overridden=metrics.get("human_overridden", 0),
            token_usage=metrics.get("token_usage", 0),
        )
        session.add(m)
        session.commit()


def apply_override(
    run_id: str,
    classification_id: str,
    package_name: str,
    original: str,
    new: str,
    reason: str,
    human_id: str,
) -> None:
    with get_session() as session:
        override = OverrideRecord(
            run_id=run_id,
            classification_id=classification_id,
            package_name=package_name,
            original_classification=original,
            new_classification=new,
            reason=reason,
            human_id=human_id,
        )
        session.add(override)
        stmt = select(Classification).where(Classification.id == classification_id)
        row = session.execute(stmt).first()
        if row:
            cls = row[0]
            cls.classification = new
            cls.confidence = 1.0
            cls.human_overridden = True
            cls.reasoning = f"[OVERRIDDEN by {human_id}] {reason}"
        session.commit()


def get_run(run_id: str) -> dict | None:
    with get_session() as session:
        stmt = select(Run).where(Run.id == run_id)
        row = session.execute(stmt).first()
        if row:
            run = row[0]
            return {
                "id": run.id,
                "repo_url": run.repo_url,
                "commit_sha": run.commit_sha,
                "timestamp": run.timestamp,
                "status": run.status,
                "confidence_score": run.confidence_score,
                "build_instruction": run.build_instruction,
                "sbom_strategy": run.sbom_strategy,
                "reconciled_plan": run.reconciled_plan,
            }
    return None


def list_runs(repo_url: str | None = None, limit: int = 20) -> list[dict]:
    with get_session() as session:
        stmt = select(Run)
        if repo_url:
            stmt = stmt.where(Run.repo_url == repo_url)
        stmt = stmt.order_by(desc(Run.timestamp)).limit(limit)
        rows = session.execute(stmt).all()
        return [
            {
                "id": row[0].id,
                "repo_url": row[0].repo_url,
                "commit_sha": row[0].commit_sha,
                "timestamp": row[0].timestamp,
                "status": row[0].status,
                "confidence_score": row[0].confidence_score,
            }
            for row in rows
        ]


def get_diffs_for_run(run_id: str) -> list[dict]:
    with get_session() as session:
        stmt = select(SBOMDiff).where(SBOMDiff.run_id == run_id)
        rows = session.execute(stmt).all()
        return [
            {
                "id": row[0].id,
                "diff_type": row[0].diff_type,
                "package_name": row[0].package_name,
                "purl": row[0].purl,
                "sha256": row[0].sha256,
                "sbomit_value": row[0].sbomit_value,
                "syft_value": row[0].syft_value,
                "details": row[0].details,
            }
            for row in rows
        ]


def get_classifications_for_run(run_id: str) -> list[dict]:
    with get_session() as session:
        stmt = select(Classification).where(Classification.run_id == run_id)
        rows = session.execute(stmt).all()
        return [
            {
                "id": row[0].id,
                "run_id": row[0].run_id,
                "diff_id": row[0].diff_id,
                "classification": row[0].classification,
                "confidence": row[0].confidence,
                "reasoning": row[0].reasoning,
                "evidence_files": row[0].evidence_files,
                "human_overridden": row[0].human_overridden,
                "created_at": row[0].created_at,
            }
            for row in rows
        ]


def get_metrics_for_run(run_id: str) -> dict | None:
    with get_session() as session:
        stmt = select(AgentMetrics).where(AgentMetrics.run_id == run_id)
        row = session.execute(stmt).first()
        if row:
            m = row[0]
            return {
                "id": m.id,
                "run_id": m.run_id,
                "total_diffs": m.total_diffs,
                "classified": m.classified,
                "avg_confidence": m.avg_confidence,
                "sbomit_accuracy": m.sbomit_accuracy,
                "syft_accuracy": m.syft_accuracy,
                "inconclusive_count": m.inconclusive_count,
                "human_overridden": m.human_overridden,
                "token_usage": m.token_usage,
            }
    return None


def get_overrides_for_run(run_id: str) -> list[dict]:
    with get_session() as session:
        stmt = select(OverrideRecord).where(OverrideRecord.run_id == run_id)
        rows = session.execute(stmt).all()
        return [
            {
                "id": row[0].id,
                "run_id": row[0].run_id,
                "classification_id": row[0].classification_id,
                "package_name": row[0].package_name,
                "original_classification": row[0].original_classification,
                "new_classification": row[0].new_classification,
                "reason": row[0].reason,
                "human_id": row[0].human_id,
                "applied_at": row[0].applied_at,
            }
            for row in rows
        ]
