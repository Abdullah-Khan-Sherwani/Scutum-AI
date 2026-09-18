# agent/CLAUDE.md

Context for this folder specifically. See the root `CLAUDE.md` for
project-wide rules; see `README.md` for setup/run instructions.

## What's here
- `config.json` — the only place target URL, container name/image/port, and
  the OpenRouter model fallback list are set. Nothing else should hardcode
  these. Select a different config file (e.g. for a second target) with the
  `SCUTUM_CONFIG` env var — `tools.py`, `graph.py`, and `main.py` each read
  `Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")`,
  so pointing this project at a new target is a config change, not a code
  change. `target_hints` is a free-text string injected into `SYSTEM_PROMPT`
  as a starting point for that specific target — endpoint shapes, login
  mechanism, known leads — not a hard requirement the agent is limited to.
- `tools.py` — four tools (`scan_web`, `scan_dependencies`, `lookup_cve`,
  `http_request`) plus `ensure_target_running`. All but `http_request` take
  no target argument from the model; they always act on `CONFIG`.
  `http_request` is the deliberate exception: its job is active testing, so
  the model supplies path/method/JSON-or-form body/extra headers — but the
  host is still always `TARGET_URL` (a full URL or `//other-host` path is
  rejected), so the model can steer *what* gets sent but never *where*. It
  returns every response header (not just `Content-Type`), needed for the
  model to actually see CORS/CSP headers rather than just infer them.
  `scan_web` reaches the target via `http://host.docker.internal:<HOST_PORT>`
  — the host-published port from `target_url` — not the custom Docker
  network, so it works whether or not the target is on `juiceshop-net` or
  even Dockerized at all.
  `ensure_target_running` only creates/starts a container when
  `container_image` is set in config; if it's empty, it assumes the target
  was started outside this project and just polls `target_url` until ready.
  `scan_dependencies` resolves npm audit's GHSA advisory IDs to real CVE
  IDs via OSV.dev (`api.osv.dev/v1/vulns/{ghsa_id}`, `aliases` field) before
  handing results to the model — npm audit alone only gives GHSA IDs, not
  CVEs, so without this step the model could only report a CVE for
  packages famous enough that it already knew the number from training.
  This adds ~60s to the tool call (one OSV request per unique GHSA ID,
  sequential, cached within the call) — a known tradeoff, not a bug. It's
  inherently Node/npm-specific (`docker cp` + `npm audit`) and won't apply
  to a non-Node target — that's an accepted limitation, not generalized.
  `lookup_cve` matches Exploit-DB two ways: NVD's own references, and a
  direct match against Exploit-DB's published CVE index (downloaded once
  per process from `gitlab.com/exploit-database/exploitdb`'s
  `files_exploits.csv`, ~10MB, cached in `_EXPLOITDB_INDEX` for the rest of
  the run). An empty result from both means no PoC has been published for
  that CVE — that's a real, common outcome for library-patch CVEs, not a
  broken lookup.
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
- `http_request`'s `headers` param is for legitimate request headers only
  (e.g. a spoofed `Origin` for CORS testing) — it cannot be used to change
  which host the request goes to; that's still hardcoded to `TARGET_URL`.
- Windows-specific gotchas already hit here (npm `.cmd` resolution,
  distroless Juice Shop image needing `docker cp` not `docker exec`) are
  documented in the root `CLAUDE.md`, not duplicated here.
