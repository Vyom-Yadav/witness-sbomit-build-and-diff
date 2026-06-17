from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class BuildInstruction(BaseModel):
    executable: str = Field(
        description="The base build executable (e.g., 'make', 'go', 'npm'). Do not include targets or flags here."
    )
    arguments: list[str] = Field(
        default_factory=list, 
        description="The arguments, targets, and flags passed to the executable. For 'make build', this MUST be ['build']. For 'go build -o bin', this MUST be ['build', '-o', 'bin']."
    )
    env_vars: dict[str, str] = Field(
        default_factory=dict,
        description="Required environment variables. For 'CGO_ENABLED=0 make build', this should be {'CGO_ENABLED': '0'}.",
    )
    output_path: str = Field(
        description="Path to the build output artifact relative to workspace root (e.g. 'bin/app', 'dist/', '.'). '.' means source-only repo.",
    )
    container_project: bool = Field(
        default=False, description="True if CI builds Docker images, not native binaries"
    )
    binary_build_command: str | None = Field(
        default=None,
        description=(
            "If container_project=True, the underlying binary "
            "build extracted from Dockerfile"
        ),
    )
    install_deps: list[str] = Field(
        default_factory=list,
        description="System packages to install via apt-get before witness runs (e.g. ['golang', 'make']). NOT project dependencies.",
    )

class SBOMStrategy(BaseModel):
    inferred_target: Literal["source", "binary"] = Field(
        description="Whether SBOM targets source code or compiled binary"
    )
    syft_target_path: str = Field(description="Syft target with scheme prefix (e.g. 'file:./bin/app', 'dir:.')")
    reasoning: str = Field(description="Which file/line informed this decision")


class DiscoveryResult(BaseModel):
    analysis: str = Field(
        description="Step-by-step reasoning of why this specific build command and output path were chosen, how tests/linting targets were explicitly avoided, and the evidence found."
    )
    build_instruction: BuildInstruction = Field(description="The strictly formatted build command configuration.")
    sbom_strategy: SBOMStrategy = Field(description="The strictly formatted SBOM extraction configuration.")
    confidence_score: float = Field(description="Confidence from 0.0 to 1.0.")
    files_analyzed: list[str] = Field(description="List of exact filepaths read.")
