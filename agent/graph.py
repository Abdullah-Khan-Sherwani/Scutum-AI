"""
LangGraph state machine: an `agent` node calls the LLM (bound to the three
tools); if the LLM's reply requests tool calls, a `tools` node executes them
and loops back to `agent`. When the LLM replies without requesting a tool
call, it has produced its final report and the graph ends. State (message
history) persists via a checkpointer so a run can be inspected or resumed.
"""
import json
import os
from pathlib import Path
from typing import Annotated, TypedDict

import openai
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from tools import TOOLS

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())

SYSTEM_PROMPT = f"""You are an authorized security assessment agent operating \
in an isolated local lab. Your ONLY approved target is {CONFIG['target_url']} \
(OWASP Juice Shop), a container deliberately built with known vulnerabilities \
for security education. You must never suggest or attempt to act on any other \
host.

Available tools:
- scan_web: runs an OWASP ZAP baseline scan against the approved target.
- scan_dependencies: runs npm audit against the target's actual installed \
dependencies, returning CVE/GHSA-tagged findings.
- lookup_cve: given a CVE ID found by scan_dependencies, returns its CVSS \
score and any linked Exploit-DB entry.

Process: call scan_web and scan_dependencies (in either order). scan_dependencies \
may return many vulnerable packages, each tagged with a real CVE ID where \
one exists -- call lookup_cve on every CVE ID belonging to a critical- or \
high-severity finding, up to 15 lookup_cve calls total (prioritize critical \
first). Do not look up moderate/low severity CVEs individually; report those \
directly from scan_dependencies' own output instead, with cvss set to null. \
Once you have called scan_web, scan_dependencies, and up to 15 lookup_cve \
calls, stop calling tools and reply with ONLY a JSON object (no prose, no \
markdown fences) with this shape:

{{
  "target": "{CONFIG['target_url']}",
  "findings": [
    {{
      "id": "F1",
      "source": "zap" | "npm_audit",
      "title": "...",
      "evidence": "...",
      "cve": "CVE-XXXX-XXXXX or null",
      "cvss": "number from lookup_cve, or null if not looked up",
      "exploit_db": "url or null",
      "remediation": "..."
    }}
  ]
}}

Include one finding entry per distinct ZAP alert type and per vulnerable \
package from npm audit. Do not fabricate a CVE or CVSS score. Use null for \
cve when scan_dependencies gave none, and null for cvss whenever you did not \
call lookup_cve for that finding -- never default cvss to 0.0. Do not \
classify findings against OWASP Top 10 or CWE categories; that mapping is \
done manually afterward."""


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]


def _make_llm(model_id: str):
    return ChatOpenAI(
        model=model_id,
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ["OPENROUTER_API_KEY"],
        timeout=90,
        max_retries=2,
    ).bind_tools(TOOLS)


def build_graph():
    model_ids = CONFIG["openrouter_models"]
    state = {"idx": 0, "llm": _make_llm(model_ids[0])}

    def agent_node(agent_state: AgentState):
        while True:
            try:
                return {"messages": [state["llm"].invoke(agent_state["messages"])]}
            except (openai.RateLimitError, openai.NotFoundError, openai.APIStatusError) as e:
                state["idx"] += 1
                if state["idx"] >= len(model_ids):
                    raise
                next_model = model_ids[state["idx"]]
                print(f"Model {model_ids[state['idx'] - 1]} failed ({type(e).__name__}); "
                      f"falling back to {next_model}")
                state["llm"] = _make_llm(next_model)

    def should_continue(state: AgentState):
        last = state["messages"][-1]
        return "tools" if getattr(last, "tool_calls", None) else END

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(TOOLS))
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile(checkpointer=MemorySaver())


def initial_messages():
    return [
        SystemMessage(content=SYSTEM_PROMPT),
        {"role": "user", "content": "Begin the vulnerability assessment."},
    ]
