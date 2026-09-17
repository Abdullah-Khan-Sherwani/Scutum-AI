# Agentic Vulnerability Assessment (Task 2)

LangGraph agent that assesses a local OWASP Juice Shop instance, correlates
findings to CVEs/Exploit-DB, and writes a structured report. No manual
step-by-step scanning -- the agent decides which tool to call and when it has
enough evidence.

## Architecture
- `agent` node: calls an OpenRouter free model bound to three tools.
- `tools` node: executes whichever tool the model requested (LangGraph
  `ToolNode`), then loops back to `agent`.
- The model stops calling tools and replies with a final JSON report once it
  judges it has enough evidence -- that's the graph's exit condition.
- State persists via `MemorySaver` (`thread_id=assessment-run-1`), so a run's
  message history can be inspected/resumed rather than being lost.

Tools (all act only on the config.json target -- the model cannot redirect
them):
- `scan_web` -- OWASP ZAP baseline scan (Docker) for web-layer alerts.
- `scan_dependencies` -- `npm audit` against the container's actual installed
  packages, for real published CVEs in Juice Shop's deliberately outdated deps.
- `lookup_cve` -- NVD lookup for CVSS score + Exploit-DB reference.

## Setup
1. `pip install -r requirements.txt`
2. `cp .env.example .env` and put in a free API key from https://openrouter.ai/keys
3. Confirm Docker Desktop is running.
4. `python main.py`

First run will pull `bkimminich/juice-shop` and `zaproxy/zap-stable` images
(a few hundred MB) -- do this first if bandwidth is a concern.

## Output
Everything lands in `output/`:
- `zap-report.json`, `npm-audit.json` -- raw tool output.
- `transcript.json` -- full agent message history (tool calls + results).
- `report.json` / `report_raw.txt` -- the agent's final structured findings.

`report.json`'s findings have no OWASP Top 10 / CWE category column by
design -- that mapping is a manual, no-GenAI step per the assignment rules.
Add it as a column when you write up Task 2/3.

## Generalizing to a new target
Add the target URL to `allowed_targets` in `config.json`, and point
`target_url` / `juiceshop_container` / `juiceshop_image` at it (or add a
second container + a second `ensure_*_running` helper in `tools.py` if it's
not Juice Shop). No other code changes needed -- the allowlist check in
`tools.py` fails closed if the configured target isn't on the list.

## If the model's tool-calling is unreliable
Free-tier OpenRouter models vary in tool-calling support. If `python main.py`
errors out on malformed tool calls, swap `openrouter_model` in `config.json`
for another free model tagged "tools" at https://openrouter.ai/models.
