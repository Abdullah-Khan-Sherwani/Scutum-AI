# agent/CLAUDE.md

Context for this folder specifically. See the root `CLAUDE.md` for
project-wide rules; see `README.md` for setup/run instructions.

## What's here
- `config.json` — the only place target URL, container name, docker
  network, and the OpenRouter model fallback list are set. Nothing else
  should hardcode these.
- `tools.py` — the three deterministic tools (`scan_web`,
  `scan_dependencies`, `lookup_cve`) plus `ensure_juiceshop_running`. Tools
  take no target argument from the model; they always act on `CONFIG`.
  `scan_dependencies` resolves npm audit's GHSA advisory IDs to real CVE
  IDs via OSV.dev (`api.osv.dev/v1/vulns/{ghsa_id}`, `aliases` field) before
  handing results to the model — npm audit alone only gives GHSA IDs, not
  CVEs, so without this step the model could only report a CVE for
  packages famous enough that it already knew the number from training.
  This adds ~60s to the tool call (one OSV request per unique GHSA ID,
  sequential, cached within the call) — a known tradeoff, not a bug.
- `graph.py` — the LangGraph `StateGraph`: an `agent` node (LLM + tools,
  handles model-fallback rotation on rate-limit/404) looping with a `tools`
  node until the model replies without requesting a tool call.
  `SYSTEM_PROMPT` here is the actual behavioral contract for a run — read it
  before assuming what the agent will or won't do.
- `main.py` — entry point: Docker checks, starts Juice Shop, invokes the
  graph, writes `output/`.
- `output/` — generated, not committed: `zap-report.json`,
  `npm-audit.json`, `transcript.json`, `report.json` / `report_raw.txt`.

## Folder-specific rules
- Any new tool goes in `tools.py`, gets added to the `TOOLS` list, and must
  read its target from `CONFIG` like the existing three — never from a
  model-supplied argument.
- If you add a tool, update `SYSTEM_PROMPT` in `graph.py` to describe it and
  say when to call it, or the model won't know it exists.
- `config.json`'s `openrouter_models` is a list, not a single string,
  specifically because free-tier models get rate-limited or silently
  deprecated (this has already happened twice while building this project)
  — keep it a list with at least 2 entries, ordered by preference.
- Windows-specific gotchas already hit here (npm `.cmd` resolution,
  distroless Juice Shop image needing `docker cp` not `docker exec`) are
  documented in the root `CLAUDE.md`, not duplicated here.
