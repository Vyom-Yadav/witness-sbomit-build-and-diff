from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ToolchainDependency(BaseModel):
    name: str = Field(description="Tool name (e.g., 'go', 'node', 'gcc', 'rust')")
    version: str | None = Field(
        default=None,
        description="Required version (e.g., '1.21.0', '20.0.0'). Use semantic versioning.",
    )
    install_command: str = Field(
        description="Full command to install the toolchain. For apt: 'apt-get install -y <package-name>'. For binary: download + extract command.",
    )
    install_method: Literal[
        "apt", "binary", "go install", "npm", "pip", "cargo", "rustup", "source"
    ] = Field(
        description="Installation method: apt (system packages), binary (official binaries), go install, npm, pip, cargo, rustup, source (compile from source)",
    )
    verify_command: str = Field(
        description="Command to verify installation and get version (e.g., 'go version', 'node --version', 'gcc --version')",
    )
    version_match_hint: str | None = Field(
        default=None,
        description="Pattern to match version in verify output (e.g., 'go1.21' for 'go version go1.21.0')",
    )


class BuildInstruction(BaseModel):
    executable: str = Field(
        description="The base build executable (e.g., 'make', 'go', 'npm'). Do not include targets or flags here."
    )
    arguments: list[str] = Field(
        default_factory=list,
        description="The arguments, targets, and flags passed to the executable. For 'make build', "
        "this MUST be ['build']. For 'go build -o bin', this MUST be ['build', '-o', 'bin']."
    )
    env_vars: dict[str, str] = Field(
        default_factory=dict,
        description="Required environment variables. For 'CGO_ENABLED=0 make build', this should be {'CGO_ENABLED': '0'}.",
    )
    output_path: str = Field(
        description="Path to the build output artifact relative to workspace root (e.g. 'bin/app', 'dist/', '.'). '.' means source-only repo.",
    )
    install_deps: list[str] = Field(
        default_factory=list,
        description="System packages to install via apt-get before witness runs (e.g. ['golang', 'make']). NOT project dependencies. Use only for C/C++ toolchains like gcc, cmake, autoconf, make.",
    )
    toolchain_deps: list[ToolchainDependency] = Field(
        default_factory=list,
        description="Structured toolchain dependencies with version, install command, and verification. Use this instead of install_deps for non-C/C++ tools (Go, Node, Rust, Python, etc.).",
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


class ReconciledDep(BaseModel):
    """A single dependency the reconciler decided still needs to be installed."""

    name: str = Field(description="Dependency/tool name (e.g. 'node', 'libssl-dev').")
    install_method: Literal[
        "apt", "binary", "go install", "npm", "pip", "cargo", "rustup", "source"
    ] = Field(description="How to install it.")
    install_command: str = Field(description="Exact shell command to install it.")
    reason: str = Field(
        description="Why it is needed and not already satisfied (e.g. 'absent', 'version 18 < required 20')."
    )
    verify_command: str | None = Field(
        default=None, description="Optional command to verify installation afterward."
    )


class ReconciledPlan(BaseModel):
    """The minimal, deduped set of install actions after probing the live container.

    Only dependencies that are genuinely missing or version-mismatched appear here.
    Anything already present in the base image is omitted.
    """

    reasoning: str = Field(
        description="Brief explanation of what was already present and therefore skipped."
    )
    deps_to_install: list[ReconciledDep] = Field(
        default_factory=list,
        description="Ordered list of dependencies that must be installed before the build.",
    )
