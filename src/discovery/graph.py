from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from src.config import settings
from src.discovery.extract_models import (
    DiscoveryAnalysis,
    ExtractedBuildCommand,
    ExtractedDependencies,
    ExtractedOutputPath,
    ExtractedSBOMStrategy,
    ConfidenceScore,
)
from src.discovery.models import DiscoveryResult
from src.discovery.prompts import (
    BUILD_COMMAND_PROMPT,
    DEPENDENCIES_PROMPT,
    DISCOVERY_REASONING_PROMPT,
    DISCOVERY_SYSTEM_PROMPT,
    OUTPUT_PATH_PROMPT,
    SBOM_STRATEGY_PROMPT,
)
from src.discovery.tools import (
    build_signal_manifest,
    list_directory,
    read_file_content,
    read_file_grep,
)

MAX_TOOL_OUTPUT = 8000
MAX_CONTEXT_CHARS = 300000


@tool
def list_dir(path: str, max_depth: int = 3) -> str:
    """List directory structure at the given path, ignoring .git, node_modules, vendor, tests."""
    result = list_directory(path, max_depth)
    if len(result) > MAX_TOOL_OUTPUT:
        truncated = result[:MAX_TOOL_OUTPUT]
        return (
            truncated
            + f"\n... ({len(result) - MAX_TOOL_OUTPUT} chars truncated). "
            + "Use grep_file with regex patterns to search the full output."
        )
    return result


@tool
def read_file(filepath: str) -> str:
    """Read the full content of a file. Fails if the file exceeds 1000 lines."""
    result = read_file_content(filepath)
    if len(result) > MAX_TOOL_OUTPUT:
        truncated = result[:MAX_TOOL_OUTPUT]
        return (
            truncated
            + f"\n... ({len(result) - MAX_TOOL_OUTPUT} chars truncated). "
            + "Use grep_file with regex patterns on this filepath to search deeper."
        )
    return result


@tool
def grep_file(filepath: str, regex: str) -> str:
    """Search a file for lines matching a regex pattern with 2 lines of surrounding context."""
    result = read_file_grep(filepath, regex)
    if len(result) > 5000:
        truncated = result[:5000]
        return (
            truncated
            + f"\n... ({len(result) - 5000} chars truncated). "
            + "Try a more specific regex to narrow results."
        )
    return result


TOOLS = [list_dir, read_file, grep_file]


class DiscoveryState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    loop_count: int
    files_analyzed: list[str]
    repo_url: str
    repo_path: str
    commit_sha: str


def _build_graph() -> StateGraph:
    graph = StateGraph(DiscoveryState)

    graph.add_node("agent", _agent_node)
    graph.add_node("tools", ToolNode(TOOLS))
    graph.add_node("format_output", _format_output)

    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", _should_continue, {
        "continue": "tools",
        "finish": "format_output",
    })
    graph.add_edge("tools", "agent")
    graph.add_edge("format_output", END)

    return graph


def _trim_messages(messages: list[BaseMessage], max_chars: int) -> list[BaseMessage]:
    """Trim old messages to keep total context under max_chars.

    CRITICAL: Always preserves SystemMessage context guidelines and the initial Human target message.
    """
    if not messages:
        return []

    # Find and isolate foundation messages we cannot afford to lose
    preserved: list[BaseMessage] = [m for m in messages if isinstance(m, SystemMessage)]
    first_human = next((m for m in messages if isinstance(m, HumanMessage)), None)
    if first_human and first_human not in preserved:
        preserved.append(first_human)

    # Compute their footprint
    preserved_chars = sum(len(m.content if isinstance(m.content, str) else str(m.content)) for m in preserved)
    total = preserved_chars
    kept: list[BaseMessage] = []

    # Work backwards through history, packing only what fits
    for msg in reversed(messages):
        if msg in preserved:
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        content_len = len(content)
        if total + content_len > max_chars:
            break
        total += content_len
        kept.insert(0, msg)

    return preserved + kept


def _agent_node(state: DiscoveryState) -> dict[str, Any]:
    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_with_tools = llm.bind_tools(TOOLS)

    system_prompt = DISCOVERY_SYSTEM_PROMPT.format(max_tool_calls=settings.max_tool_calls)

    # Bundle system instructions into message state before passing to the trimmer
    messages_with_system = [SystemMessage(content=system_prompt)] + state["messages"]
    trimmed = _trim_messages(messages_with_system, MAX_CONTEXT_CHARS)

    response = llm_with_tools.invoke(trimmed)

    new_loop_count = state["loop_count"] + 1
    return {
        "messages": [response],
        "loop_count": new_loop_count,
    }


def _should_continue(state: DiscoveryState) -> Literal["continue", "finish"]:
    if state["loop_count"] >= settings.max_tool_calls:
        return "finish"

    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "continue"
    return "finish"


def _format_output(state: DiscoveryState) -> dict[str, Any]:
    """Extract fields from tool call history step-by-step.

    Instead of asking the LLM to produce a deeply nested DiscoveryResult all at once,
    we break it down into focused sub-calls: reasoning first (free text), then each
    structurable field extracted from that reasoning.
    """
    import logging
    import traceback

    from langchain_core.messages import ToolMessage
    from langchain_openrouter import ChatOpenRouter

    logger = logging.getLogger(__name__)

    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
        max_tokens=16384,
    )

    tool_messages_raw = state["messages"]
    files_analyzed = _derive_files_analyzed(tool_messages_raw)

    # ---- Step 1: Reasoning (forced structured output) ----
    # Filter out ALL AIMessages — the agent's monologue and final answer are not
    # ground truth. Keep only ToolMessages (tool results) + the initial HumanMessage.
    reasoning_context: list[BaseMessage] = []
    for msg in tool_messages_raw:
        if isinstance(msg, ToolMessage):
            reasoning_context.append(msg)
        elif isinstance(msg, HumanMessage):
            reasoning_context.append(msg)

    # Append the request at the END — a HumanMessage at the end triggers a response
    reasoning_context.append(
        HumanMessage(content=(
            "Based on the above tool exploration results, produce a detailed "
            "step-by-step analysis covering ALL of the following:\n"
            "1. Build Command: exact executable, arguments, env vars, and which "
            "file they came from\n"
            "2. Testing/Linting Exclusion: confirm the selected target is "
            "build-only\n"
            "3. Output Path: where the artifact lands relative to workspace root\n"
            "4. Dependencies: system libraries and language toolchains with versions\n"
            "5. SBOM Strategy: syft target and which file informed the decision\n"
            "6. Container Build Detection: is this containerized? what is the "
            "underlying binary build?\n"
            "7. Confidence Assessment: confidence (0.0-1.0) and specific "
            "uncertainties\n\n"
            "Write at least 500 words. Be specific — cite file names and line "
            "numbers from the tool results above."
        ))
    )

    reasoning_messages: list[BaseMessage] = [
        SystemMessage(content=DISCOVERY_REASONING_PROMPT),
    ] + reasoning_context

    reasoning_llm = llm.with_structured_output(DiscoveryAnalysis)

    try:
        raw_analysis: Any = reasoning_llm.invoke(reasoning_messages)
        if isinstance(raw_analysis, DiscoveryAnalysis):
            analysis_text = raw_analysis.analysis
        elif isinstance(raw_analysis, dict):
            analysis_text = raw_analysis.get("analysis", "")
        else:
            analysis_text = ""
    except Exception:
        logger.error(f"Reasoning LLM call failed: {traceback.format_exc()}")
        analysis_text = (
            "LLM reasoning call failed. The tool exploration did not produce "
            "a usable analysis. Setting confidence to 0."
        )

    # ---- Step 2: Build Command (executable, arguments, env_vars) ----
    build_cmd_llm = llm.with_structured_output(ExtractedBuildCommand)
    build_cmd_messages: list[BaseMessage] = [
        SystemMessage(
            content=BUILD_COMMAND_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
        ),
    ]

    try:
        raw_cmd: Any = build_cmd_llm.invoke(build_cmd_messages)
        if isinstance(raw_cmd, ExtractedBuildCommand):
            build_cmd = raw_cmd
        elif isinstance(raw_cmd, dict):
            build_cmd = ExtractedBuildCommand(**raw_cmd)
        else:
            build_cmd = ExtractedBuildCommand(executable="", arguments=[], env_vars={})
    except Exception:
        logger.warning(f"Build command extraction failed: {traceback.format_exc()}")
        build_cmd = ExtractedBuildCommand(executable="", arguments=[], env_vars={})

    build_cmd_json = json.dumps(build_cmd.model_dump())

    # ---- Step 3: Dependencies (install_deps + toolchain_deps) ----
    deps_llm = llm.with_structured_output(ExtractedDependencies)
    deps_messages: list[BaseMessage] = [
        SystemMessage(
            content=DEPENDENCIES_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_cmd_json
        ),
    ]

    try:
        raw_deps: Any = deps_llm.invoke(deps_messages)
        if isinstance(raw_deps, ExtractedDependencies):
            deps = raw_deps
        elif isinstance(raw_deps, dict):
            deps = ExtractedDependencies(**raw_deps)
        else:
            deps = ExtractedDependencies(install_deps=[], toolchain_deps=[])
    except Exception:
        logger.warning(f"Dependency extraction failed: {traceback.format_exc()}")
        deps = ExtractedDependencies(install_deps=[], toolchain_deps=[])

    deps_json = json.dumps(deps.model_dump())

    # ---- Step 4: SBOM Strategy ----
    sbom_llm = llm.with_structured_output(ExtractedSBOMStrategy)
    sbom_messages: list[BaseMessage] = [
        SystemMessage(
            content=SBOM_STRATEGY_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_cmd_json
        ),
    ]

    try:
        raw_sbom: Any = sbom_llm.invoke(sbom_messages)
        if isinstance(raw_sbom, ExtractedSBOMStrategy):
            sbom_strat = raw_sbom
        elif isinstance(raw_sbom, dict):
            sbom_strat = ExtractedSBOMStrategy(**raw_sbom)
        else:
            sbom_strat = ExtractedSBOMStrategy(
                inferred_target="source",
                syft_target_path="dir:.",
                reasoning="Extraction failed; defaulting to source scan.",
            )
    except Exception:
        logger.warning(f"SBOM strategy extraction failed: {traceback.format_exc()}")
        sbom_strat = ExtractedSBOMStrategy(
            inferred_target="source",
            syft_target_path="dir:.",
            reasoning="Extraction failed; defaulting to source scan.",
        )

    # ---- Step 5: Output Path ----
    output_llm = llm.with_structured_output(ExtractedOutputPath)
    output_messages: list[BaseMessage] = [
        SystemMessage(
            content=OUTPUT_PATH_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_cmd_json
        ),
    ]

    try:
        raw_output: Any = output_llm.invoke(output_messages)
        if isinstance(raw_output, ExtractedOutputPath):
            output_path = raw_output
        elif isinstance(raw_output, dict):
            output_path = ExtractedOutputPath(**raw_output)
        else:
            output_path = ExtractedOutputPath(
                output_path=".",
                reasoning="Extraction failed; defaulting to workspace root.",
            )
    except Exception:
        logger.warning(f"Output path extraction failed: {traceback.format_exc()}")
        output_path = ExtractedOutputPath(
            output_path=".",
            reasoning="Extraction failed; defaulting to workspace root.",
        )

    # ---- Step 6: Confidence Score ----
    confidence_llm = llm.with_structured_output(ConfidenceScore)
    confidence_messages: list[BaseMessage] = [
        SystemMessage(
            content=(
                "Based on the analysis below, output a confidence score "
                "between 0.0 and 1.0.\n\n"
                "=== ANALYSIS ===\n"
                + analysis_text
            )
        ),
    ]

    try:
        raw_conf: Any = confidence_llm.invoke(confidence_messages)
        if isinstance(raw_conf, ConfidenceScore):
            confidence_score = raw_conf.confidence
        elif isinstance(raw_conf, dict):
            confidence_score = float(raw_conf.get("confidence", 0.0))
        else:
            confidence_score = 0.0
    except Exception:
        logger.warning(f"Confidence extraction failed: {traceback.format_exc()}")
        confidence_score = 0.0

    # ---- Assemble final DiscoveryResult dict ----
    result = {
        "analysis": analysis_text,
        "build_instruction": {
            "executable": build_cmd.executable,
            "arguments": build_cmd.arguments,
            "env_vars": build_cmd.env_vars,
            "output_path": output_path.output_path,
            "install_deps": deps.install_deps,
            "toolchain_deps": [t.model_dump() for t in deps.toolchain_deps],
        },
        "sbom_strategy": sbom_strat.model_dump(),
        "confidence_score": confidence_score,
        "files_analyzed": files_analyzed,
    }

    return {"messages": [HumanMessage(content=json.dumps(result))]}


def _derive_files_analyzed(messages: list[BaseMessage]) -> list[str]:
    """Extract file paths from tool call history deterministically.

    Only extracts from ``filepath`` and ``path`` keys — skips ``regex`` and
    other non-path arguments to avoid capturing grep patterns as file paths.
    """
    files: set[str] = set()
    for msg in messages:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                args = tc.get("args") if isinstance(tc, dict) else {}
                if not isinstance(args, dict):
                    continue
                for key in ("filepath", "path"):
                    val = args.get(key)
                    if isinstance(val, str):
                        files.add(val)
    return sorted(list(files))


async def discover_build(repo_url: str, commit_sha: str, repo_path: str) -> dict[str, Any]:
    """Run the discovery agent and return the result as a dict."""
    graph = _build_graph().compile()
    manifest = build_signal_manifest(repo_path)
    initial_state: DiscoveryState = {
        "messages": [
            HumanMessage(
                content=(
                    f"Analyze the repository at {repo_url} (commit {commit_sha}) "
                    f"cloned locally at {repo_path} and determine the build instructions.\n\n"
                    f"The following build-signal files were detected in the repository. "
                    f"These are the authoritative places to find the build command, required "
                    f"environment variables, and dependencies. You MUST inspect the relevant "
                    f"CI / BUILD / MANIFEST / CONTAINER files before concluding. Use "
                    f"grep_file (preferred, token-cheap) or read_file to extract the exact "
                    f"command, env vars, and deps. Treat DOCS as a fallback source to grep "
                    f"only if the structured files are inconclusive.\n\n"
                    f"=== BUILD SIGNAL MANIFEST ===\n{manifest}\n"
                    f"=== END MANIFEST ===\n\n"
                    f"You may also use list_dir('{repo_path}') if you need to explore beyond "
                    f"the listed files."
                )
            )
        ],
        "loop_count": 0,
        "files_analyzed": [],
        "repo_url": repo_url,
        "repo_path": repo_path,
        "commit_sha": commit_sha,
    }

    result = await graph.ainvoke(initial_state)

    system_prompt_text = DISCOVERY_SYSTEM_PROMPT.format(max_tool_calls=settings.max_tool_calls)
    messages_payload = [
        {"role": "SystemMessage", "content": system_prompt_text}
    ] + [
        {
            "role": type(m).__name__,
            "content": m.content if isinstance(m.content, str) else str(m.content),
        }
        for m in result["messages"]
    ]
    context_path = Path(repo_path).parent / "discovery_context.json"
    context_path.write_text(json.dumps(messages_payload, indent=2, default=str))

    last_msg = result["messages"][-1]
    content = last_msg.content if hasattr(last_msg, "content") else str(last_msg)

    try:
        parsed = json.loads(content)
        return {
            "analysis": parsed.get("analysis", ""),
            "build_instruction": parsed.get("build_instruction", {}),
            "sbom_strategy": parsed.get("sbom_strategy", {}),
            "confidence_score": parsed.get("confidence_score", 0.0),
            "files_analyzed": parsed.get("files_analyzed", []),
            "discovery_context_path": str(context_path),
        }
    except json.JSONDecodeError:
        return {
            "analysis": "Failed to parse structured response from model.",
            "build_instruction": {
                "executable": "",
                "arguments": [],
                "env_vars": {},
                "output_path": ".",
                "install_deps": [],
                "toolchain_deps": [],
            },
            "sbom_strategy": {
                "inferred_target": "source",
                "syft_target_path": "dir:.",
                "reasoning": "Fallback default due to JSON parse failure."
            },
            "confidence_score": 0.0,
            "files_analyzed": [],
            "discovery_context_path": str(context_path),
        }
