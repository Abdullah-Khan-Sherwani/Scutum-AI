# Agentic Vulnerability Assessment (Task 2)

LangGraph agent that assesses a local OWASP Juice Shop instance, actively
tests it for injection/access-control flaws, correlates findings to real
CVEs/Exploit-DB, and writes a structured report. No manual step-by-step
scanning -- the agent decides which tool to call and when it has enough
evidence.

## Architecture
- `agent` node: calls an OpenRouter model (with automatic fallback across
  `config.json`'s `openrouter_models` list if one is rate-limited or
  deprecated) bound to four tools.
- `tools` node: executes whichever tool the model requested (LangGraph
  `ToolNode`), then loops back to `agent`.
- The model stops calling tools and replies with a final JSON report once it
  judges it has enough evidence -- that's the graph's exit condition.
- State persists via `MemorySaver` (`thread_id=assessment-run-1`), so a run's
  message history can be inspected/resumed rather than being lost.

Tools:
- `scan_web` -- OWASP ZAP baseline scan (Docker) for web-layer misconfig
  (headers, cookies, CSP).
- `scan_dependencies` -- `npm audit` against the container's actual installed
  packages, resolved from GHSA to real CVE IDs via OSV.dev.
- `lookup_cve` -- NVD lookup for CVSS score, plus Exploit-DB matching both
  via NVD's own references and a direct match against Exploit-DB's published
  CVE index.
- `http_request` -- the one tool that takes model-supplied input: the model
  chooses path/method/JSON body to actively register an account, log in, and
  test for SQL injection, XSS, and broken access control. The **host** is
  still always the configured target regardless of what the model sends; a
  full URL or a different host is rejected outright, so this can't be
  steered off-target.

## Setup
1. `pip install -r requirements.txt`
2. `cp .env.example .env` and put in a free API key from https://openrouter.ai/keys
3. Confirm Docker Desktop is running.
4. `python main.py`

First run will pull `bkimminich/juice-shop` and `zaproxy/zap-stable` images
(a few hundred MB) -- do this first if bandwidth is a concern. A full run
(ZAP scan + dependency scan + CVE lookups + active testing) can take several
minutes; the active-testing phase alone may make up to 25 live HTTP requests.

## Output
Everything lands in `output/`:
- `zap-report.json`, `npm-audit.json`, `ghsa_cve_map.json` -- raw tool output.
- `transcript.json` -- full agent message history (tool calls + results) --
  the place to check if you want to verify the agent actually called real
  tools rather than just asserting things from its own training knowledge.
- `report.json` / `report_raw.txt` -- the agent's final structured findings,
  including `"source": "active_test"` entries only where an `http_request`
  response actually demonstrated the exploit.

`report.json`'s findings have no OWASP Top 10 / CWE category column by
design -- that mapping is a manual, no-GenAI step per the assignment rules.
Add it as a column when you write up Task 2/3.

## Generalizing to a new target
Copy `config.json` to a new file (e.g. `config.dvwa.json`), point
`target_url`/`allowed_targets` at the new target, and set
`container_name`/`container_image`/`container_port` if this project should
manage that target's container -- leave them empty if you start it
yourself. Write a short `target_hints` string describing that target's
login mechanism and any known endpoints/leads; it gets injected straight
into `SYSTEM_PROMPT`. Run it with:

```bash
SCUTUM_CONFIG=config.dvwa.json python main.py
```

(PowerShell: `$env:SCUTUM_CONFIG="config.dvwa.json"; python main.py`.) No
code changes needed -- every module reads `CONFIG` from whichever file
`SCUTUM_CONFIG` names, defaulting to `config.json`, and the allowlist check
in `tools.py` fails closed if the configured target isn't on that file's
own `allowed_targets`. See `config.dvwa.json` for a worked second example.

## If the model's tool-calling is unreliable
Free-tier OpenRouter models vary in tool-calling support and availability
(this project has already hit both a deprecated model ID and a rate-limited
one). If a run fails outright rather than falling back, check
`openrouter_models` in `config.json` against
`GET https://openrouter.ai/api/v1/models` and swap in a current free model
tagged "tools".
