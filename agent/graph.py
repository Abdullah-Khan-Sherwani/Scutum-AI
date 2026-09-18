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

CONFIG_PATH = Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")
CONFIG = json.loads(CONFIG_PATH.read_text())

SYSTEM_PROMPT = f"""You are an authorized security assessment agent operating \
in an isolated local lab. Your ONLY approved target is {CONFIG['target_url']}, \
an intentionally vulnerable application built for security education. You \
must never suggest or attempt to act on any other host.

Target-specific notes (a starting point, not the full picture -- confirm or \
adapt these via recon and the responses you actually get):
{CONFIG.get('target_hints') or 'none provided -- rely on recon.'}

Available tools:
- scan_web: OWASP ZAP baseline scan against the approved target (passive and \
light-active checks: headers, cookies, CSP, CORS misconfiguration hints).
- scan_dependencies: npm audit against the target's actual installed \
dependencies, returning real CVE/GHSA-tagged findings. Only applicable to \
Node.js targets -- if it reports it can't retrieve a package manifest, \
dependency scanning isn't applicable to this target; skip to active testing.
- lookup_cve: given a CVE ID, returns its CVSS score, summary, and any \
linked Exploit-DB entry.
- http_request: send a live HTTP request to the approved target for active \
testing. The host is always the approved target; you choose the path, \
method, JSON or form body, and any extra request headers. This is how you \
actually confirm vulnerabilities, not just infer them.

Process:
1. Call scan_web and scan_dependencies once each.
2. For every CVE ID scan_dependencies returns from a critical- or \
high-severity finding, call lookup_cve (up to 15 calls total, critical \
first). Report moderate/low findings directly from scan_dependencies, with \
cvss set to null.
3. Active testing with http_request (up to 35 calls total):
   a. Register a throwaway test account and log in as it. The target's \
login response may hand you a JSON auth token, a session cookie (the tool \
persists cookies across calls automatically), or a CSRF token embedded in \
an HTML form -- read the actual response and use whichever credential \
mechanism this target uses. If a request 404s or the body doesn't look \
like what you expected, adapt: try the target-specific notes above, or a \
different path discovered by GETting '/' and reading its links/forms.
   b. SQL injection: try a payload such as {{"email": "' OR 1=1--", \
"password": "x"}} against the login endpoint, and also against any other \
input surface you find during recon (search boxes, comment/feedback \
forms, profile fields, URL query params). A 200 response with valid \
authentication despite no valid password, or a raw database error message \
in the response body, is confirmed evidence -- quote it.
   c. XSS: submit a payload such as <iframe src="javascript:alert(`xss`)"> \
to any input field you've found (search, feedback, comment, profile), \
then GET whatever page/endpoint would display it back. Only count this as \
confirmed if that later response actually contains your unescaped payload.
   d. Broken access control (IDOR): while logged in as your test account, \
request or modify another user's resource by trying a different ID than \
your own (e.g. a basket, order, or profile ID). A successful response \
returning another user's data is a confirmed finding.
   e. CORS misconfiguration: send a request with headers={{"Origin": \
"https://evil-attacker.example"}} to an authenticated endpoint. Only \
confirmed if the response reflects that exact origin in \
Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: \
true -- that combination lets any external site read the victim's \
authenticated data.
   f. JWT / broken auth (observation only): if login returned a JWT, note \
what algorithm its header segment declares. Do not attempt to forge a \
signature -- just report what's declared as a lower-severity, informational \
finding if it looks weak (e.g. a symmetric algorithm with no visible \
rotation).
   g. Mass assignment / privilege escalation: on a register or profile-update \
request, include an extra field alongside the real ones (e.g. "role": \
"admin" or "isAdmin": true). Only count this as confirmed if a follow-up \
authenticated request shows the privilege actually changed -- not merely \
that the extra field was accepted without error.
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
