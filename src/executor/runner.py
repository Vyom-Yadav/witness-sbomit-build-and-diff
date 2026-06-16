from __future__ import annotations

import shlex
from pathlib import Path

import dagger
from temporalio import activity

ATTESTATION_CONTAINER_PATH = "/workspace/attestation.json"
SBOM_SYFT_CONTAINER_PATH = "/workspace/sbom-syft.json"
SBOM_SBOMIT_CONTAINER_PATH = "/workspace/sbom-sbomit.json"


async def run_build(
    repo_url: str,
    commit_sha: str | None,
    build_instruction: dict,
    witness_label: str,
    repo_path: str,
    base_image: str = "sbomit-analyzer:base",
) -> dict:
    output_dir = Path("/tmp") / f"build_{witness_label}"
    output_dir.mkdir(parents=True, exist_ok=True)

    dagger_log_path = output_dir / "dagger.log"
    with open(str(dagger_log_path), "a") as dagger_log:
        async with dagger.Connection(dagger.Config(log_output=dagger_log)) as client:
            container = await _setup_container(client, base_image)

            repo_dir = client.host().directory(repo_path)
            container = container.with_mounted_directory("/workspace/repo", repo_dir)
            container = container.with_workdir("/workspace/repo")

            install_deps = build_instruction.get("install_deps", [])
            if install_deps:
                activity.heartbeat(f"Installing system packages: {install_deps}")
                container = container.with_exec(["apt-get", "update"])
                container = container.with_exec(["apt-get", "install", "-y"] + install_deps)

            executable = build_instruction["executable"]
            arguments = build_instruction.get("arguments", [])
            env_vars = build_instruction.get("env_vars", {})

            for key, value in env_vars.items():
                container = container.with_env_variable(key, value)

            witness_cmd = [
                "witness",
                "run",
                "--step", "build",
                "-c", "/root/.witness.yaml",
                "-k", "/root/testkey.pem",
                "-o", ATTESTATION_CONTAINER_PATH,
                "--experimental",
                "-a", "network-trace",
                "--attestor-network-trace-ca-cert-path", "/root/witness_nettrace_proxy/ca_cert.pem",
                "--attestor-network-trace-ca-key-path", "/root/witness_nettrace_proxy/ca_key.pem",
                "--",
                executable,
            ] + arguments

            witness_cmd_str = shlex.join(witness_cmd)

            combined_script = (
                "mkdir -p /sys/kernel/tracing && mount -t tracefs nodev /sys/kernel/tracing || true; "
                "mkdir -p /sys/kernel/debug && mount -t debugfs nodev /sys/kernel/debug || true; "
                f"exec {witness_cmd_str}"
            )

            witness_log_host = output_dir / "witness.log"

            activity.heartbeat(f"Running witness: {executable} {' '.join(arguments)}")
            try:
                container = await container.with_exec(
                    ["sh", "-c", combined_script],
                    insecure_root_capabilities=True,
                ).sync()
            except dagger.ExecError as e:
                combined_output = f"STDOUT:\n{e.stdout}\n\nSTDERR:\n{e.stderr}"
                witness_log_host.write_text(combined_output)
                tail = "\n".join(combined_output.splitlines()[-50:])
                error_log_path = Path(f"/tmp/build_{witness_label}_witness_error.log")
                error_log_path.write_text(
                    f"Witness failed (exit {e.exit_code}):\n{tail}"
                )
                raise RuntimeError(f"Witness failed (exit {e.exit_code}). Log at {witness_log_host}")

            witness_log_host.write_text("Witness succeeded. Attestation at attestation.json")

            attestation_host_path = output_dir / "attestation.json"
            attestation_host_path.write_text(
                await container.file(ATTESTATION_CONTAINER_PATH).contents()
            )

            binary_host_path = output_dir / "binary"

            output_rel = build_instruction.get("output_path", ".")
            if output_rel != ".":
                binary_container_path = f"/workspace/repo/{output_rel}"
                binary_host_path.write_text(
                    await container.file(binary_container_path).contents()
                )

            activity.heartbeat("Extracting build artifacts and generating SBOMs...")

            syft_log_host = output_dir / "syft.log"
            sbom_syft_host: Path = Path("")
            try:
                sbom_syft_host = await _generate_syft_sbom(
                    client, container, build_instruction, output_dir, repo_path
                )
                syft_log_host.write_text("Syft scan succeeded.")
            except dagger.ExecError as e:
                syft_log_host.write_text(f"STDERR:\n{e.stderr}\n\nSTDOUT:\n{e.stdout}")
                raise

            sbomit_log_host = output_dir / "sbomit.log"
            sbom_sbomit_host: Path = Path("")
            try:
                sbom_sbomit_host = await _generate_sbom_sbomit(container, output_dir, repo_path)
                sbomit_log_host.write_text("SBOMit generation succeeded.")
            except dagger.ExecError as e:
                sbomit_log_host.write_text(f"STDERR:\n{e.stderr}\n\nSTDOUT:\n{e.stdout}")
                raise

            return {
                "witness_version": witness_label,
                "binary_path": str(binary_host_path) if output_rel != "." else "",
                "attestation_path": str(attestation_host_path),
                "sbom_syft_path": str(sbom_syft_host),
                "sbom_sbomit_path": str(sbom_sbomit_host),
                "witness_log_path": str(witness_log_host),
                "syft_log_path": str(syft_log_host),
                "sbomit_log_path": str(sbomit_log_host),
                "dagger_log_path": str(dagger_log_path),
                "logs": f"Build completed with witness {witness_label}",
                "output_dir": str(output_dir),
            }


async def _setup_container(
    client: dagger.Client,
    base_image: str,
) -> dagger.Container:
    image_tar = client.host().file("/tmp/sbomit-base.tar")
    container = client.container().import_(image_tar)
    return container


async def _generate_syft_sbom(
    client: dagger.Client,
    container: dagger.Container,
    build_instruction: dict,
    output_dir: Path,
    repo_path: str,
) -> Path:
    sbom_strategy = build_instruction.get("sbom_strategy", {})
    inferred_target = sbom_strategy.get("inferred_target", "binary")

    if inferred_target == "source":
        clean_dir = client.host().directory(repo_path)
        container = container.with_mounted_directory("/workspace/source", clean_dir)
        syft_target = "dir:/workspace/source"
    else:
        output_rel = build_instruction.get("output_path", ".")
        syft_target = sbom_strategy.get("syft_target_path", f"file:./{output_rel}")

    syft_cmd = [
        "syft", "scan", syft_target,
        "-o", f"spdx-json={SBOM_SYFT_CONTAINER_PATH}",
    ]

    container = container.with_exec(syft_cmd)

    host_path = output_dir / "sbom-syft.json"
    host_path.write_text(
        await container.file(SBOM_SYFT_CONTAINER_PATH).contents()
    )
    return host_path


async def _generate_sbom_sbomit(
    container: dagger.Container,
    output_dir: Path,
    repo_path: str,
) -> Path:
    sbomit_cmd = [
        "sbomit", "generate", ATTESTATION_CONTAINER_PATH,
        "--format", "spdx23",
        "-o", SBOM_SBOMIT_CONTAINER_PATH,
    ]

    container = container.with_exec(sbomit_cmd)

    host_path = output_dir / "sbom-sbomit.json"
    host_path.write_text(
        await container.file(SBOM_SBOMIT_CONTAINER_PATH).contents()
    )
    return host_path
