# Agent Vulnerability-Testing Expansion & Target Generalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the agent more vulnerability classes to actively probe (CORS, JWT observation, mass assignment, broadened SQLi/XSS), and make the pipeline actually config-swappable to a second target (DVWA), with a real run proving it.

**Architecture:** No new tools. `http_request` (the one tool the model already drives) gains `headers`/`form` params and echoes full response headers. `SYSTEM_PROMPT` in `graph.py` gets a wider, target-agnostic active-testing phase. `config.json`'s Juice-Shop-specific field names and the ZAP/docker-cp code paths that assumed Juice Shop's container networking become config-driven, selected via a `SCUTUM_CONFIG` env var so a second target is a second checked-in JSON file, not a code change.

**Tech Stack:** Python 3, stdlib `unittest`/`unittest.mock` for the one pure-logic unit (no new dependency — `unittest` is stdlib, nothing added to `requirements.txt`).

## Global Constraints

- Stdlib + whatever is already in `agent/requirements.txt` only — no new dependency added by this plan.
- Every tool still reads its target from `CONFIG`, never a model-supplied host — `http_request`'s new `headers` param is request headers only, it cannot change the connection host.
- `report.json` schema is unchanged — no category/CWE field (manual, no-GenAI step).
- Match existing style: flat files (`tools.py`, `graph.py`, `main.py`), functions not classes, no abstractions for single-use code.
- Commits atomic, no AI co-authorship trailer (per root `CLAUDE.md`) for commits to files other than this plan/spec doc pair, which already carry the standard attribution per this session's system instructions.

---

### Task 1: `http_request` — custom headers, form-encoding, full response headers

**Files:**
- Modify: `agent/tools.py:246-285`
- Create: `agent/tests/test_http_request.py`

**Interfaces:**
- Produces: `http_request(method: str, path: str, body: dict | None = None, auth_token: str | None = None, headers: dict | None = None, form: bool = False) -> str` — same name, same import (`from tools import TOOLS`) used by `graph.py`. `headers` merges with `auth_token`; an explicit `Authorization` entry in `headers` wins over `auth_token`. `form=True` sends `body` as `data=` (form-urlencoded) instead of `json=`. The returned string now includes every response header, not just `Content-Type`.

- [ ] **Step 1: Write the failing tests**

Create `agent/tests/test_http_request.py`:

```python
"""Unit tests for http_request's header/form handling -- the only pure
logic added by the vuln-testing expansion. Everything else (container
management, live probes) needs Docker/a real target and is verified by an
actual run, not a mock."""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import tools


def _fake_response(status=200, headers=None, text="{}"):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = text
    return resp


class HttpRequestTests(unittest.TestCase):
    def test_auth_token_sets_authorization_header(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1", "auth_token": "abc123"
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc123")

    def test_explicit_authorization_header_overrides_auth_token(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1", "auth_token": "abc123",
                "headers": {"Authorization": "Bearer override"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer override")

    def test_custom_header_passed_through_for_cors_testing(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1",
                "headers": {"Origin": "https://evil-attacker.example"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Origin"], "https://evil-attacker.example")

    def test_form_true_sends_data_not_json(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "POST", "path": "/login.php",
                "body": {"username": "admin", "password": "password"}, "form": True
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["data"], {"username": "admin", "password": "password"})
        self.assertNotIn("json", kwargs)

    def test_form_false_default_sends_json(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "POST", "path": "/rest/user/login",
                "body": {"email": "a@b.com", "password": "x"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["json"], {"email": "a@b.com", "password": "x"})
        self.assertNotIn("data", kwargs)

    def test_response_includes_all_headers_not_just_content_type(self):
        headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://evil-attacker.example",
            "Access-Control-Allow-Credentials": "true",
        }
        with patch.object(tools._HTTP_SESSION, "request",
                           return_value=_fake_response(headers=headers, text='{"ok":true}')):
            result = tools.http_request.invoke({"method": "GET", "path": "/rest/basket/1"})
        self.assertIn("Access-Control-Allow-Origin: https://evil-attacker.example", result)
        self.assertIn("Access-Control-Allow-Credentials: true", result)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run (from `agent/`):
```bash
./.venv/Scripts/python.exe -m unittest tests/test_http_request.py -v
```
Expected: FAIL — `headers`/`form` aren't accepted by the current `http_request` signature, so `.invoke({...})` raises a validation error on the first four tests; the last two currently pass by coincidence (drop `form`/`headers` from those specific calls if needed to confirm the *header-echo* assertions genuinely fail against current behavior — current code only returns `Content-Type`, so `test_response_includes_all_headers_not_just_content_type` should fail on the `assertIn` checks).

- [ ] **Step 3: Implement the minimal change**

Replace `agent/tools.py:246-286` (from `_HTTP_SESSION = requests.Session()` through the end of the file) with:

```python
_HTTP_SESSION = requests.Session()
_METHOD_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)$")


@tool
def http_request(method: str, path: str, body: dict | None = None,
                  auth_token: str | None = None, headers: dict | None = None,
                  form: bool = False) -> str:
    """Send a live HTTP request to the approved target for active testing --
    registering an account, logging in, and probing for SQL injection, XSS,
    CORS misconfiguration, broken access control, mass assignment, and other
    web vulnerabilities. `path` must be a path on the target (e.g.
    '/rest/user/login'), never a full URL or another host. `body` is sent as
    the JSON request body for POST/PUT/PATCH -- set `form=True` to send it
    form-urlencoded instead (needed for HTML-form-based logins). `auth_token`,
    if you have one from a prior login response, is sent as an
    `Authorization: Bearer <token>` header. `headers` lets you set arbitrary
    extra request headers (e.g. a spoofed `Origin` to test CORS); an
    `Authorization` entry in `headers` overrides `auth_token`. Returns the
    status code, every response header, and a truncated body preview -- only
    report a vulnerability as confirmed if this response actually
    demonstrates it."""
    method = method.strip().upper()
    if not _METHOD_RE.match(method):
        return f"Unsupported method '{method}'. Use GET, POST, PUT, PATCH, or DELETE."
    if "://" in path or path.startswith("//"):
        return "path must be relative on the approved target, e.g. '/rest/user/login' -- not a full URL."
    if not path.startswith("/"):
        path = "/" + path

    req_headers = dict(headers) if headers else {}
    if auth_token and "Authorization" not in req_headers:
        req_headers["Authorization"] = f"Bearer {auth_token}"

    try:
        if form:
            resp = _HTTP_SESSION.request(
                method, TARGET_URL + path, data=body, headers=req_headers, timeout=15
            )
        else:
            resp = _HTTP_SESSION.request(
                method, TARGET_URL + path, json=body, headers=req_headers, timeout=15
            )
    except requests.RequestException as e:
        return f"Request failed: {e}"

    header_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return (
        f"{method} {path} -> HTTP {resp.status_code}\n"
        f"Response headers:\n{header_lines}\n"
        f"Body (truncated to 1500 chars):\n{resp.text[:1500]}"
    )


TOOLS = [scan_web, scan_dependencies, lookup_cve, http_request]
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
./.venv/Scripts/python.exe -m unittest tests/test_http_request.py -v
```
Expected: `OK` — all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add agent/tools.py agent/tests/test_http_request.py
git commit -m "Add custom headers and form-encoding to http_request, echo full response headers"
```

---

### Task 2: Config-driven target generalization

**Files:**
- Modify: `agent/config.json` (full rewrite)
- Modify: `agent/tools.py:1-67` (imports/CONFIG block, `ensure_juiceshop_running`, `scan_web`, `scan_dependencies`'s `docker cp` path)
- Modify: `agent/graph.py:1-23` (CONFIG load)
- Modify: `agent/main.py:1-17,28-38` (CONFIG load, container-start call)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `ensure_target_running()` (renamed from `ensure_juiceshop_running`), module-level `CONTAINER_PORT`, `CONTAINER_APP_PATH`, `HOST_PORT` in `tools.py`; `CONFIG` in all three files now loads from `Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")`, so `SCUTUM_CONFIG=config.dvwa.json` (Task 6) swaps every module's config with no code change.

No unit test here — this is Docker/subprocess orchestration, meaningfully verified only by a real run (Tasks 5 and 6 exercise both branches: managed container, and externally-started target).

- [ ] **Step 1: Rewrite `agent/config.json`**

```json
{
  "allowed_targets": ["http://localhost:3000"],
  "target_url": "http://localhost:3000",
  "container_name": "juiceshop",
  "container_image": "bkimminich/juice-shop",
  "container_port": 3000,
  "container_app_path": "/juice-shop",
  "docker_network": "juiceshop-net",
  "target_hints": "OWASP Juice Shop: JSON REST API under /rest/ and /api/. Register: POST /rest/user/register {\"email\":...,\"password\":...,\"passwordRepeat\":...}. Login: POST /rest/user/login {\"email\":...,\"password\":...} -- a 200 response body contains an 'authentication.token' JWT; send it as auth_token on later calls. Baskets are IDOR candidates: GET /rest/basket/{id}, ids are small sequential integers, try one that isn't yours. Product search (GET /rest/products/search?q=...) previously returned a raw SQLite error for a script-tag payload -- worth confirming as SQL injection, not just XSS. Feedback/comment fields are additional XSS candidates.",
  "openrouter_models": [
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3.5-lightning:free",
    "qwen/qwen3.8-27b:free",
    "deepseek/deepseek-v4-flash-0731:free"
  ],
  "max_recursion": 160
}
```

- [ ] **Step 2: Update `agent/tools.py`'s CONFIG block and container helper**

Replace `agent/tools.py:1-67` (from the module docstring through the end of `ensure_juiceshop_running`) with:

```python
"""
Deterministic tools the agent can call. Each tool acts only on the
pre-configured, allow-listed target loaded from config.json (or the file
named by the SCUTUM_CONFIG env var, for pointing this project at a
different target without touching code) -- the model never supplies a
model host/container. `http_request` is the one exception to "the model
supplies nothing": its whole job is active testing, so the model does
choose the path/method/payload -- but the host is still always pinned
to TARGET_URL and a full URL or different host is rejected, so the model
can steer *what* gets sent but never *where*.
"""
import csv
import io
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

NPM_CMD = shutil.which("npm") or "npm"  # Windows needs the resolved npm.cmd path

CONFIG_PATH = Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")
CONFIG = json.loads(CONFIG_PATH.read_text())
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

TARGET_URL = CONFIG["target_url"]
CONTAINER = CONFIG["container_name"]
NETWORK = CONFIG["docker_network"]
IMAGE = CONFIG["container_image"]
CONTAINER_PORT = CONFIG["container_port"]
CONTAINER_APP_PATH = CONFIG["container_app_path"]
HOST_PORT = urlparse(TARGET_URL).port

if TARGET_URL not in CONFIG["allowed_targets"]:
    raise RuntimeError(f"Configured target {TARGET_URL} is not on the allowlist")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ensure_target_running() -> None:
    """Idempotently create the isolated network and start the target
    container if one is configured and isn't already running, then wait
    until the target answers. If no container_image is configured, this
    assumes the target was started outside this project and only waits
    for it to respond -- e.g. a second target you started by hand."""
    if IMAGE:
        _run(["docker", "network", "create", NETWORK], timeout=15)  # ignore "already exists"

        inspect = _run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], timeout=15)
        if inspect.returncode != 0:
            started = _run(
                ["docker", "run", "-d", "--name", CONTAINER, "--network", NETWORK,
                 "-p", f"{HOST_PORT}:{CONTAINER_PORT}", IMAGE],
                timeout=60,
            )
            if started.returncode != 0:
                raise RuntimeError(f"Failed to start {CONTAINER}: {started.stderr}")
        elif inspect.stdout.strip() != "true":
            _run(["docker", "start", CONTAINER], timeout=30)

    for _ in range(30):
        try:
            if requests.get(TARGET_URL, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"Target did not become ready at {TARGET_URL} in time")
```

- [ ] **Step 3: Fix `scan_web` to reach the target via its host-published port, not the custom Docker network**

In `agent/tools.py`, replace the entire `scan_web` function (originally lines 70-103) with:

```python
@tool
def scan_web() -> str:
    """Run an OWASP ZAP baseline scan against the approved target and
    return a summary of alerts (XSS, missing security headers, insecure
    cookies, etc). Full JSON report is written to output/zap-report.json."""
    report_path = OUTPUT_DIR / "zap-report.json"
    zap_target = f"http://host.docker.internal:{HOST_PORT}"
    result = _run(
        [
            "docker", "run", "--rm",
            "-v", f"{OUTPUT_DIR}:/zap/wrk/:rw",
            "zaproxy/zap-stable", "zap-baseline.py",
            "-t", zap_target,
            "-J", "zap-report.json",
        ],
        timeout=600,
    )
    # zap-baseline.py exits non-zero when it finds WARN/FAIL alerts by design,
    # so a non-zero return code alone is not a failure -- only missing output is.
    if not report_path.exists():
        return f"ZAP scan failed to produce a report. stderr: {result.stderr[-2000:]}"

    data = json.loads(report_path.read_text())
    alerts = data.get("site", [{}])[0].get("alerts", [])
    if not alerts:
        return "ZAP baseline scan completed: no alerts found."

    lines = [f"ZAP baseline scan found {len(alerts)} alert type(s):"]
    for a in alerts:
        lines.append(
            f"- {a.get('name')} (risk={a.get('riskdesc')}, "
            f"instances={len(a.get('instances', []))}, "
            f"cweid={a.get('cweid')})"
        )
    return "\n".join(lines)
```

This drops `--network NETWORK` and the `http://{CONTAINER}:3000` internal address -- ZAP now reaches whatever's published on the host at `target_url`'s port via Docker Desktop's `host.docker.internal`, whether or not that target is on `juiceshop-net` or even Dockerized at all. Everything below the `docker run` call (report parsing) is unchanged from the original.

- [ ] **Step 4: Make `scan_dependencies`'s `docker cp` path configurable**

In `agent/tools.py`'s `scan_dependencies` function, change:

```python
        cp = _run(["docker", "cp", f"{CONTAINER}:/juice-shop/{fname}", str(pkg_dir / fname)],
                   timeout=30)
```

to:

```python
        cp = _run(["docker", "cp", f"{CONTAINER}:{CONTAINER_APP_PATH}/{fname}", str(pkg_dir / fname)],
                   timeout=30)
```

- [ ] **Step 5: Update `agent/graph.py`'s CONFIG load**

`agent/graph.py` already imports `os` at the top (line 9). In `agent/graph.py:23`, replace:

```python
CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())
```

with:

```python
CONFIG_PATH = Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")
CONFIG = json.loads(CONFIG_PATH.read_text())
```

- [ ] **Step 6: Update `agent/main.py`'s CONFIG load and container-start call**

Replace `agent/main.py:14`:
```python
CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())
```
with:
```python
CONFIG_PATH = Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")
CONFIG = json.loads(CONFIG_PATH.read_text())
```
and add `import os` to the top import block (`agent/main.py:5-10`).

Replace `agent/main.py:35-38`:
```python
    from tools import ensure_juiceshop_running
    print(f"Starting {CONFIG['juiceshop_container']} on {CONFIG['docker_network']} ...")
    ensure_juiceshop_running()
    print(f"Target ready at {CONFIG['target_url']}")
```
with:
```python
    from tools import ensure_target_running
    if CONFIG.get("container_image"):
        print(f"Starting {CONFIG['container_name']} on {CONFIG['docker_network']} ...")
    else:
        print("No container configured -- assuming target was started externally.")
    ensure_target_running()
    print(f"Target ready at {CONFIG['target_url']}")
```

- [ ] **Step 7: Smoke-test that all three modules still import and agree on config**

Run (from `agent/`):
```bash
./.venv/Scripts/python.exe -c "import tools, graph; print(tools.TARGET_URL, tools.CONTAINER, tools.HOST_PORT); print(graph.CONFIG['target_url'])"
```
Expected output: `http://localhost:3000 juiceshop 3000` then `http://localhost:3000` -- no exceptions.

- [ ] **Step 8: Run the existing unit tests to confirm this didn't break Task 1**

```bash
./.venv/Scripts/python.exe -m unittest tests/test_http_request.py -v
```
Expected: `OK`.

- [ ] **Step 9: Commit**

```bash
git add agent/config.json agent/tools.py agent/graph.py agent/main.py
git commit -m "Generalize target/container config; route ZAP via host-published port"
```

---

### Task 3: Broaden the active-testing phase in `SYSTEM_PROMPT`

**Files:**
- Modify: `agent/graph.py:25-98`

**Interfaces:**
- Consumes: `CONFIG['target_hints']` (Task 2, always present as a string, possibly empty).
- Produces: same `SYSTEM_PROMPT` name/shape (a module-level f-string), same `initial_messages()` contract -- no change to how `main.py` or `build_graph()` consume it.

No unit test (prompt text) -- verified by the live runs in Tasks 5 and 6, which is the only meaningful check for whether the model actually acts on new instructions.

- [ ] **Step 1: Replace `SYSTEM_PROMPT` in `agent/graph.py:25-98`**

```python
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
```

- [ ] **Step 2: Smoke-test the prompt renders without a KeyError/format error**

Run (from `agent/`):
```bash
./.venv/Scripts/python.exe -c "import graph; print(len(graph.SYSTEM_PROMPT)); print('CORS' in graph.SYSTEM_PROMPT, 'Mass assignment' in graph.SYSTEM_PROMPT)"
```
Expected: a length in the low thousands of characters, then `True True`.

- [ ] **Step 3: Commit**

```bash
git add agent/graph.py
git commit -m "Broaden active-testing phase: CORS, JWT observation, mass assignment, wider injection surface"
```

---

### Task 4: Update folder docs (`agent/CLAUDE.md`, `agent/README.md`)

**Files:**
- Modify: `agent/CLAUDE.md`
- Modify: `agent/README.md`

**Interfaces:** None (docs only).

- [ ] **Step 1: Update `agent/CLAUDE.md`'s "What's here" section**

In `agent/CLAUDE.md`, replace the `config.json` and `tools.py` bullets (current lines 6-30) with:

```markdown
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
```

- [ ] **Step 2: Update the "Folder-specific rules" bullet about `openrouter_models`**

In `agent/CLAUDE.md`, the existing bullet about `openrouter_models` being a list stays as-is (still true, now 5 entries instead of 3) — no edit needed there. Add one new bullet after it:

```markdown
- `http_request`'s `headers` param is for legitimate request headers only
  (e.g. a spoofed `Origin` for CORS testing) — it cannot be used to change
  which host the request goes to; that's still hardcoded to `TARGET_URL`.
```

- [ ] **Step 3: Update `agent/README.md`'s "Generalizing to a new target" section**

Replace the existing section (current lines 60-69):

```markdown
## Generalizing to a new target
Add the target URL to `allowed_targets` in `config.json`, and point
`target_url` / `juiceshop_container` / `juiceshop_image` at it (or add a
second container + a second `ensure_*_running` helper in `tools.py` if it's
not Juice Shop). `http_request`'s active-testing methodology lives in
`graph.py`'s `SYSTEM_PROMPT` as generic web-app patterns (login, search,
IDOR-by-ID), not Juice-Shop-specific code, but the prompt's example paths
are still worth re-checking against a different target's actual API. No
other code changes needed -- the allowlist check in `tools.py` fails closed
if the configured target isn't on the list.
```

with:

```markdown
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
```

- [ ] **Step 4: Commit**

```bash
git add agent/CLAUDE.md agent/README.md
git commit -m "Update agent docs for config-driven header/form testing and target generalization"
```

---

### Task 5: Live verification run against Juice Shop

**Files:** none modified (verification only, output files are gitignored per existing `.gitignore` behavior for `agent/output/`).

- [ ] **Step 1: Confirm Docker Desktop is running and OpenRouter key is set**

```bash
cd agent && docker info >/dev/null && echo "docker ok" && test -f .env && echo ".env present"
```
Expected: both lines print.

- [ ] **Step 2: Run the pipeline against the default (Juice Shop) config**

```bash
cd agent && ./.venv/Scripts/python.exe main.py
```
Expected: exits with `Done. N finding(s). See output/report.json and output/report_raw.txt` -- takes several minutes (ZAP scan is the slow step).

- [ ] **Step 3: Inspect the transcript for evidence the new probe categories were actually attempted**

```bash
cd agent && grep -o '"Origin"[^,}]*' output/transcript.json | head -5
```
Expected: at least one match showing a spoofed `Origin` header was actually sent (confirms the CORS probe ran, not just that the prompt mentions it).

- [ ] **Step 4: Confirm `report.json` is still valid and the existing finding types are preserved**

```bash
cd agent && ./.venv/Scripts/python.exe -c "
import json
r = json.load(open('output/report.json'))
sources = {f['source'] for f in r['findings']}
print('finding count:', len(r['findings']))
print('sources seen:', sources)
"
```
Expected: `finding count` is at or above the prior run's count (from `Plan/Task2_Execution_Report.md`), `sources seen` includes `zap`, `npm_audit`, and `active_test`.

- [ ] **Step 5: No commit needed** — `agent/output/` is generated/gitignored per `agent/CLAUDE.md`'s existing note. If this run's `report.json` should become the new basis for `Plan/Task2_Execution_Report.md`/`Plan/Findings_Summary.txt`, that's a separate, explicit follow-up task -- not silently done here.

---

### Task 6: DVWA config + live verification run

**Files:**
- Create: `agent/config.dvwa.json`

- [ ] **Step 1: Start DVWA locally**

```bash
docker run -d --rm --name dvwa -p 4280:80 vulnerables/web-dvwa
```
Expected: a container ID prints; `docker ps` shows `dvwa` as `Up`.

- [ ] **Step 2: Create `agent/config.dvwa.json`**

```json
{
  "allowed_targets": ["http://localhost:4280"],
  "target_url": "http://localhost:4280",
  "container_name": "",
  "container_image": "",
  "container_port": null,
  "container_app_path": "",
  "docker_network": "juiceshop-net",
  "target_hints": "DVWA (Damn Vulnerable Web Application), PHP/MySQL, form-based not JSON. Default login: POST /login.php form-urlencoded {\"username\":\"admin\",\"password\":\"password\",\"Login\":\"Login\",\"user_token\":<value>} -- user_token is a hidden CSRF field in the login page's HTML, GET /login.php first and read it out of the response body. After logging in, security level defaults to a locked-down setting; POST /security.php form-urlencoded {\"security\":\"low\",\"seclev_submit\":\"Submit\",\"user_token\":<value from that page>} to unlock the vulnerable pages. Vulnerability pages live under /vulnerabilities/ (e.g. /vulnerabilities/sqli/?id=1&Submit=Submit for SQL injection, /vulnerabilities/xss_r/?name=... for reflected XSS) -- use form=true and the session cookie the tool already persists automatically, not a Bearer token.",
  "openrouter_models": [
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3.5-lightning:free",
    "qwen/qwen3.8-27b:free",
    "deepseek/deepseek-v4-flash-0731:free"
  ],
  "max_recursion": 160
}
```

- [ ] **Step 3: Smoke-test the config loads and the target answers**

```bash
cd agent && SCUTUM_CONFIG=config.dvwa.json ./.venv/Scripts/python.exe -c "
import tools
print(tools.TARGET_URL, repr(tools.IMAGE), tools.HOST_PORT)
tools.ensure_target_running()
print('ready')
"
```
Expected: `http://localhost:4280 '' 4280` then `ready` (confirms the empty-`container_image` skip branch works and DVWA answers on the host port).

- [ ] **Step 4: Run the pipeline against DVWA**

```bash
cd agent && SCUTUM_CONFIG=config.dvwa.json ./.venv/Scripts/python.exe main.py
```
Expected: completes and prints a finding count. `scan_dependencies` is expected to report it can't retrieve a package manifest (DVWA is PHP, not Node) -- that's correct, not a bug, per `SYSTEM_PROMPT`'s "not applicable" guidance from Task 3.

- [ ] **Step 5: Preserve the DVWA run's output separately from the Juice Shop run's**

```bash
cd agent && mkdir -p output/dvwa && cp output/report.json output/dvwa/report.json && cp output/transcript.json output/dvwa/transcript.json && cp output/zap-report.json output/dvwa/zap-report.json
```

- [ ] **Step 6: Confirm the DVWA report has at least one real finding**

```bash
cd agent && ./.venv/Scripts/python.exe -c "
import json
r = json.load(open('output/dvwa/report.json'))
print('finding count:', len(r['findings']))
for f in r['findings']:
    print('-', f['source'], f['title'])
"
```
Expected: `finding count` >= 1.

- [ ] **Step 7: Stop the DVWA container** (it was started with `--rm`, so this also removes it)

```bash
docker stop dvwa
```

- [ ] **Step 8: Commit the DVWA config and its (small, human-readable) captured evidence**

```bash
cd "C:/Users/Cauti/OneDrive/Semester 7/Comsec/Assignment3" && git add agent/config.dvwa.json agent/output/dvwa/report.json agent/output/dvwa/transcript.json
git commit -m "Add DVWA target config and captured second-target verification run"
```

(`agent/output/` is otherwise gitignored per existing project convention -- this is a deliberate, explicit exception to keep the generalization proof in the repo, mirroring how `Plan/Task2_Execution_Report.md` keeps the Juice Shop run's evidence.)
