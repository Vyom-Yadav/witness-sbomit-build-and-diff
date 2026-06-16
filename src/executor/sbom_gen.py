


def generate_sbom_command(
    tool: str,
    target: str,
    output_path: str,
    output_format: str = "spdx-json",
) -> str:
    return f"{tool} {target} -o {output_format}={output_path}"


def detect_sbom_target(build_instruction: dict) -> str:
    if build_instruction.get("container_project"):
        return "dir:."
    return "dir:."
