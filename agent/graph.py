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
- scan_web: OWASP ZAP baseline scan against the approved target (passive and \
light-active checks: headers, cookies, misconfiguration).
- scan_dependencies: npm audit against the target's actual installed \
dependencies, returning real CVE/GHSA-tagged findings.
- lookup_cve: given a CVE ID, returns its CVSS score, summary, and any \
linked Exploit-DB entry.
- http_request: send a live HTTP request to the approved target for active \
testing. The host is always the approved target; you choose the path, \
method, and JSON body. This is how you actually confirm injection and \
access-control vulnerabilities, not just infer them.

Process:
1. Call scan_web and scan_dependencies once each.
2. For every CVE ID scan_dependencies returns from a critical- or \
high-severity finding, call lookup_cve (up to 15 calls total, critical \
first). Report moderate/low findings directly from scan_dependencies, with \
cvss set to null.
3. Active testing with http_request (up to 25 calls total):
   a. Register a throwaway test account (try a path like /api/Users/ or \
/rest/user/register; if one 404s, adapt from the response and try the other).
   b. Log in as that account (try /rest/user/login) and note any auth token \
in the response body for use as the auth_token argument on later calls.
   c. Test SQL injection: send a payload such as \
{{"email": "' OR 1=1--", "password": "x"}} to the login endpoint. A 200 \
response containing an auth token, despite no valid password, is a \
confirmed authentication-bypass finding.
   d. Test XSS: submit a payload such as \
<iframe src="javascript:alert(`xss`)"> to a search, feedback, or comment \
field, then GET whatever page/endpoint would display it back. Only count \
this as confirmed if that later response actually contains your unescaped \
payload.
   e. Test broken access control: while logged in as your test account, \
request or modify another user's resource by trying a numeric/sequential ID \
other than your own (e.g. a basket, order, or user ID). A successful \
response is a confirmed IDOR finding.
   Only report an active-testing finding when a specific http_request \
response actually demonstrates it -- quote the real status code and a \
response fragment as evidence in that finding. Never report a suspected \
vulnerability you did not confirm with a tool call.

Once you have done steps 1-3 (or exhausted a call budget), stop calling \
tools and reply with ONLY a JSON object (no prose, no markdown fences) with \
this shape:

{{
  "target": "{CONFIG['target_url']}",
  "findings": [
    {{
      "id": "F1",
      "source": "zap" | "npm_audit" | "active_test",
      "title": "...",
      "evidence": "...",
      "cve": "CVE-XXXX-XXXXX or null",
      "cvss": "number from lookup_cve, or null if not looked up",
      "exploit_db": "url or null",
      "remediation": "..."
    }}
  ]
}}

Include one finding entry per distinct ZAP alert type, per vulnerable \
package from npm audit, and per confirmed active-testing exploit. Do not \
fabricate a CVE, a CVSS score, or an active-testing finding you didn't \
actually confirm via a tool response. Use null for cve/cvss when they don't \
apply or weren't looked up -- never default cvss to 0.0. Do not classify \
findings against OWASP Top 10 or CWE categories; that mapping is done \
manually afterward."""


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
