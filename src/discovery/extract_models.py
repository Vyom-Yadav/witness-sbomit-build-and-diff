from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.discovery.models import ReconciledDep, ToolchainDependency


class ExtractedBuildCommand(BaseModel):
    executable: str = Field(
        description="The base build executable (e.g., 'make', 'go', 'npm'). Do not include targets or flags here."
    )
    arguments: list[str] = Field(
        default_factory=list,
        description="The arguments, targets, and flags passed to the executable. For 'make build', this MUST be ['build']. For 'go build -o bin', this MUST be ['build', '-o', 'bin'].",
    )
    env_vars: dict[str, str] = Field(
        default_factory=dict,
        description="Required environment variables. For 'CGO_ENABLED=0 make build', this should be {'CGO_ENABLED': '0'}.",
    )


class ExtractedDependencies(BaseModel):
    install_deps: list[str] = Field(
        default_factory=list,
        description="System packages to install via apt-get before witness runs (e.g. ['libssl-dev', 'libsqlite3-dev']). NOT project dependencies. Use only for system libraries the build links against.",
    )
    toolchain_deps: list[ToolchainDependency] = Field(
        default_factory=list,
        description="Structured toolchain dependencies with version, install command, and verification. Use for Go, Node, Rust, Python, etc.",
    )


class ExtractedSBOMStrategy(BaseModel):
    inferred_target: Literal["source", "binary"] = Field(
        description="Whether SBOM targets source code or compiled binary"
    )
    syft_target_path: str = Field(
        description="Syft target with scheme prefix (e.g. 'file:./bin/app', 'dir:.')"
    )
    reasoning: str = Field(
        description="Which file/line informed this decision"
    )


class ExtractedOutputPath(BaseModel):
    output_path: str = Field(
        description="Path to the build output artifact relative to workspace root (e.g. 'bin/app', 'dist/', '.'). '.' means source-only repo."
    )
    reasoning: str = Field(
        description="How and where the output path was determined from the build configuration."
    )


class ConfidenceScore(BaseModel):
    """Wrapper so `with_structured_output` can accept a bare float."""
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0.")


class DiscoveryAnalysis(BaseModel):
    """Forced structured output for the reasoning step so the LLM cannot produce empty content."""
    analysis: str = Field(
        description="Step-by-step reasoning covering: build command, testing/linting exclusion, output path, dependencies, SBOM strategy, container build detection, and confidence assessment. Must be thorough — cite specific file names and line numbers from the tool exploration results."
    )


class ReconciledDepsList(BaseModel):
    deps_to_install: list[ReconciledDep] = Field(
        default_factory=list,
        description="Dependencies that must be installed",
    )
