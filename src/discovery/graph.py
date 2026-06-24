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
)
from src.discovery.models import DiscoveryResult
from src.discovery.prompts import (
    DISCOVERY_REASONING_PROMPT,
    DISCOVERY_SYSTEM_PROMPT,
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
        if isinstance(msg, (ToolMessage, HumanMessage)):
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

    # ---- Step 1: Reasoning (forced structured output) ----
    # ...reasoning code stays... (kept as-is above) ...

    # ========================================================================
    # Return ONLY the reasoning text and files_analyzed.
    # Extraction steps are now individual Temporal activities so each step's
    # input/output is recorded in the event history.
    # ========================================================================
    result = {
        "analysis_text": analysis_text,
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
            "analysis_text": parsed.get("analysis_text", ""),
            "files_analyzed": parsed.get("files_analyzed", []),
            "discovery_context_path": str(context_path),
            "repo_path": repo_path,
        }
    except json.JSONDecodeError:
        return {
            "analysis_text": "Failed to parse structured response from model.",
            "files_analyzed": [],
            "discovery_context_path": str(context_path),
            "repo_path": repo_path,
        }
