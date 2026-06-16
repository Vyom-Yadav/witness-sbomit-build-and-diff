from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class BuildInstruction(BaseModel):
    executable: str = Field(description="Build executable (e.g. 'make', 'go')")
    arguments: list[str] = Field(default_factory=list, description="Arguments to the executable")
    env_vars: dict[str, str] = Field(
        default_factory=dict,
        description="Required environment variables",
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
    build_instruction: BuildInstruction
    sbom_strategy: SBOMStrategy
    confidence_score: float = Field(ge=0.0, le=1.0)
    files_analyzed: list[str] = Field(default_factory=list)
