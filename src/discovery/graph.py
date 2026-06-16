from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from src.config import settings
from src.discovery.models import DiscoveryResult
from src.discovery.prompts import DISCOVERY_SYSTEM_PROMPT
from src.discovery.tools import list_directory, read_file_content, read_file_grep


MAX_TOOL_OUTPUT = 8000
MAX_CONTEXT_CHARS = 300000


@tool
def list_dir(path: str, max_depth: int = 2) -> str:
    """List directory structure at the given path, ignoring .git, node_modules, vendor, tests."""
    result = list_directory(path, max_depth)
    if len(result) > MAX_TOOL_OUTPUT:
        truncated = result[:MAX_TOOL_OUTPUT]
        line_count = result.count("\n") + 1
        return (
            truncated
            + f"\n... ({line_count} lines total, {len(result) - MAX_TOOL_OUTPUT} chars truncated). "
            + "Use grep_file with regex patterns to search the full output."
        )
    return result


@tool
def read_file(filepath: str) -> str:
    """Read the full content of a file. Fails if the file exceeds 1000 lines."""
    result = read_file_content(filepath)
    if len(result) > MAX_TOOL_OUTPUT:
        truncated = result[:MAX_TOOL_OUTPUT]
        line_count = result.count("\n") + 1
        return (
            truncated
            + f"\n... ({line_count} lines total, {len(result) - MAX_TOOL_OUTPUT} chars truncated). "
            + "Use grep_file with regex patterns on this filepath to search deeper."
        )
    return result


@tool
def grep_file(filepath: str, regex: str) -> str:
    """Search a file for lines matching a regex pattern with 2 lines of surrounding context."""
    result = read_file_grep(filepath, regex)
    if len(result) > 5000:
        truncated = result[:5000]
        lines_shown = truncated.count("\n") + 1
        return (
            truncated
            + f"\n... ({lines_shown} matches shown, {len(result) - 5000} chars truncated). "
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
    """Trim old messages to keep total context under max_chars."""
    total = 0
    kept: list[BaseMessage] = []
    for msg in reversed(messages):
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        total += len(content)
        if total > max_chars:
            break
        kept.insert(0, msg)
    return kept


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
    trimmed = _trim_messages(state["messages"], MAX_CONTEXT_CHARS)
    messages = [SystemMessage(content=system_prompt)] + trimmed

    response = llm_with_tools.invoke(messages)

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
    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
        max_tokens=16384,
    )
    llm_structured = llm.with_structured_output(DiscoveryResult)

    format_messages = [
        SystemMessage(content=(
            "Based on the analysis above, output a DiscoveryResult JSON. "
            "If build command was not found, set confidence_score below 0.5. "
            "Extract exact strings only — do not hallucinate."
        )),
    ] + _trim_messages(state["messages"], MAX_CONTEXT_CHARS // 2)

    result: Any = llm_structured.invoke(format_messages)
    if hasattr(result, "model_dump_json"):
        return {"messages": [HumanMessage(content=result.model_dump_json())]}
    return {"messages": [HumanMessage(content=str(result))]}


async def discover_build(repo_url: str, commit_sha: str, repo_path: str) -> dict[str, Any]:
    """Run the discovery agent and return the result as a dict.

    Returns dict with keys: build_instruction, sbom_strategy, confidence_score, files_analyzed, discovery_context_path.
    """
    import json
    from pathlib import Path

    graph = _build_graph().compile()
    initial_state: DiscoveryState = {
        "messages": [
            HumanMessage(
                content=(
                    f"Analyze the repository at {repo_url} (commit {commit_sha}) "
                    f"cloned locally at {repo_path} and determine the build instructions. "
                    f"Use list_dir('{repo_path}') to explore the project structure, "
                    f"then read_file and grep_file to inspect build config files."
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
            "build_instruction": parsed.get("build_instruction", {}),
            "sbom_strategy": parsed.get("sbom_strategy", {}),
            "confidence_score": parsed.get("confidence_score", 0.0),
            "files_analyzed": parsed.get("files_analyzed", []),
            "discovery_context_path": str(context_path),
        }
    except json.JSONDecodeError:
        return {
            "build_instruction": {},
            "sbom_strategy": {},
            "confidence_score": 0.0,
            "files_analyzed": [],
            "discovery_context_path": str(context_path),
        }
