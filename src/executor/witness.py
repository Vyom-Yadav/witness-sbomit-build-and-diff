from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class WitnessConfig:
    binary_path: str
    label: str


def get_witness_configs(v_a_path: str, v_b_path: str) -> tuple[WitnessConfig, WitnessConfig]:
    return (
        WitnessConfig(binary_path=v_a_path, label="A"),
        WitnessConfig(binary_path=v_b_path, label="B"),
    )


def build_witness_command(
    witness_path: str,
    step: str,
    executable: str,
    arguments: list[str],
) -> str:
    args_str = " ".join(arguments)
    return f"{witness_path} run --step {step} -- {executable} {args_str}"


def parse_attestation(attestation_path: str) -> dict:
    path = Path(attestation_path)
    if not path.exists():
        return {}
    import json
    return json.loads(path.read_text())
