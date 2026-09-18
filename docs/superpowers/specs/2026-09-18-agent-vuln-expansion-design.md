# Agent Vulnerability-Testing Expansion & Target Generalization

**Date:** 2026-09-18
**Status:** Approved, implementing

## Problem

The agent's own reasoning work is currently thin: most of the report comes from
two canned scans (ZAP baseline, npm audit), with only three LLM-driven active
tests (SQLi login bypass, reflected XSS, basket IDOR). The final-submission
requirement also explicitly calls for a pipeline that is "generalized, not
hardcoded to a single target" -- today the architecture is described as
target-agnostic in `Plan/Task1_Workflow_Design.md` but has only ever run
against Juice Shop.

## Goals

1. Give the agent more distinct vulnerability classes to actively probe, using
   the existing `http_request` tool (no new tool), reasoned about generally
   so the instructions apply to any target, not just Juice Shop.
2. Make the two hardcoded Juice-Shop assumptions in the code
   (container management, prompt wording) config-driven instead.
3. Prove generalization with a real second run against DVWA, not just an
   architectural claim.

## Non-goals

- No multi-language SCA (`scan_dependencies` stays npm/Node-specific --
  accepted limitation).
- No cryptographic JWT forging -- unreliable for an LLM to construct
  correctly; the agent only *observes and reports* what a token's header
  segment declares.
- No coded second LLM provider. The user has an NVIDIA NIM key, but
  `CLAUDE.md` says OpenRouter only, never a provider hardcoded directly --
  NIM stays a manual, by-hand fallback (edit `.env`/`config.json` yourself)
  if OpenRouter's free-tier daily cap is hit mid-testing, not an automatic
  code path.
- No multi-container orchestration (e.g. DVWA+MySQL via compose) --
  if a target needs more than one container, the student starts it
  themselves and leaves `container_image` empty so this project only polls
  readiness instead of managing it.

## Design

### A. `tools.py` -- `http_request` gets two new optional params

- `headers: dict | None` -- arbitrary custom request headers (e.g. a spoofed
  `Origin` for CORS testing). If both `headers` and `auth_token` supply an
  `Authorization` value, the explicit `headers` entry wins.
- `form: bool = False` -- when true, send `data=body` (form-urlencoded)
  instead of `json=body`, for HTML-form-based logins (DVWA).
- The response now returns **all** response headers, not just
  `Content-Type` -- this is the actual blocker for CORS/JWT inspection today.

### B. `graph.py` -- `SYSTEM_PROMPT` active-testing phase, expanded and generalized

New probe categories, all phrased generally (apply to whatever the target
actually exposes, not hardcoded to Juice Shop paths):

- **CORS misconfiguration**: send a request with a spoofed `Origin` header to
  an authenticated endpoint; confirmed only if the response reflects that
  origin in `Access-Control-Allow-Origin` *and* sets
  `Access-Control-Allow-Credentials: true`.
- **JWT / broken auth (observation only)**: report the algorithm declared in
  the login token's header segment. No forged-signature attempts.
- **Mass assignment / privilege escalation**: include an extra field (e.g.
  `"role": "admin"`) on a register/update request; confirmed only if a
  follow-up authenticated request shows the privilege actually changed, not
  just that the field was silently accepted.
- **Broadened injection surface**: SQLi/XSS testing is no longer login-only --
  the prompt now says to try other input surfaces discovered during recon
  (search boxes, comment/feedback forms, profile fields, URL query params).
  Target-specific tips (e.g. "Juice Shop's product search previously
  returned a raw SQLite error") live in that target's `target_hints` config
  string, not in the general prompt.
- **Format-agnostic credential handling**: instructions no longer assume a
  JSON auth token -- the agent is told to extract whatever credential the
  target actually uses (JSON token, session cookie, or CSRF form field)
  based on what the login response looks like. `requests.Session()` already
  persists cookies automatically across calls.
- Active-testing call budget raised (~25 -> ~35) to fit the extra probes;
  `max_recursion` in `config.json` raised proportionally (110 -> 160).
- Report schema (`report.json`) is unchanged -- every new probe still reports
  with `source: "active_test"`.
- CSP: no change needed -- ZAP's passive scan already catches this
  (`Findings_Summary.txt` F1).

### C. Generalization -- `config.json` + `tools.py`, mechanical

- Rename: `juiceshop_container` -> `container_name`,
  `juiceshop_image` -> `container_image`. Add `container_port` (the
  container's internal port) and `container_app_path` (default
  `/juice-shop`, used by `scan_dependencies`'s `docker cp`).
- Host-side port is parsed from `target_url` (`urlparse(...).port`) instead
  of the hardcoded `"3000:3000"`.
- `ensure_juiceshop_running` -> `ensure_target_running`: if `container_image`
  is empty, container creation is skipped entirely and the function just
  polls `target_url` until ready -- supports a target started outside this
  project (e.g. DVWA run by hand).
- Juice-Shop-specific example paths move out of hardcoded prompt prose into
  a `target_hints` string in `config.json`, injected into the prompt as a
  starting point for that specific target.

### D. Verification -- real DVWA run

- `docker run -p 4280:80 vulnerables/web-dvwa`.
- Temporarily point `config.json` at it (`target_url`, `allowed_targets`,
  `container_name`/`container_image`/`container_port` left empty since DVWA
  is started by hand, and a DVWA-specific `target_hints` string: default
  credentials `admin`/`password`, must POST `security.php` to set
  `security=low` before the vulnerability pages respond, form-urlencoded
  login).
- Run `main.py` for real, capture its `report.json`/`transcript.json` as a
  **separate** output file so the existing Juice Shop evidence in
  `agent/output/` is not overwritten.
- Revert `config.json` back to the Juice Shop values afterward as the
  committed default.

## Model / rate-limit resilience

Live-checked against OpenRouter's `/models` endpoint (2026-09-18): all three
configured free models are currently valid and genuinely free. Two more free
candidates exist right now and will be added to the fallback list for extra
redundancy: `qwen/qwen3.8-27b:free`, `deepseek/deepseek-v4-flash-0731:free`.
This protects against a single model being deprecated or rate-limited, not
against OpenRouter's account-wide daily free-request cap -- running two full
assessments today (Juice Shop, then DVWA) with a larger call budget makes
that cap more likely to be hit. No code-level mitigation for that beyond the
existing model-fallback rotation; if it happens, it's a manual, visible
decision (switch to the NIM key by hand for that run), not automatic.

## Success criteria

- Juice Shop run still produces its existing confirmed SQLi/IDOR findings,
  plus new confirmed-or-denied CORS, JWT-observation, and mass-assignment
  findings.
- DVWA run completes end-to-end and produces at least one real finding,
  using the identical codebase with only `config.json` changed.
- `report.json` schema unchanged; no category/CWE field added (manual
  concept-mapping step stays hand-authored per the assignment's no-GenAI
  rule).
