# Automated Agentic Vulnerability Assessment — Final Report (Draft)

**Prepared by:** Abdullah Khan Sherwani
**Target:** OWASP Juice Shop (`http://localhost:3000`), isolated local Docker instance
**Date:** 18 September 2026

> **This is a draft for you to finish, not a submission-ready file.** The
> course-concept mapping section is not included here — the assignment
> requires that step to be done by hand, without AI assistance, and says not
> to cite the LLM/search/archive tooling in that section, so it's left for
> you to write directly in your own submission. Everything else here is
> drawn directly from real tool output (`agent/output/report.json`,
> `agent/output/transcript.json`, `agent/output/zap-report.json`,
> `agent/output/npm-audit.json`) — nothing below was invented.

---

## 1. Executive Summary

An automated, agentic pipeline was built and run against OWASP Juice Shop, an
intentionally vulnerable web application, entirely within an isolated local
Docker network. The pipeline identified **24 distinct findings**: 5 confirmed
through live active exploitation, 8 through dependency/CVE analysis, and 11
through automated web-layer scanning. The most severe finding is a **SQL
injection vulnerability in the login endpoint that grants full administrative
access with no valid credentials** — independently reproduced two different
ways (direct login bypass, and a separate injection point in the product
search endpoint that also permits full database exfiltration via a UNION
query). A **broken access control (IDOR)** vulnerability and a **CORS
misconfiguration combining a wildcard origin with credentialed requests** were
also confirmed through direct exploitation, alongside 8 dependency
vulnerabilities carrying real CVE identifiers (two rated CVSS 9.0+).

Every finding in this report is backed by a real, logged tool execution
against the live target — no finding was inferred, assumed, or written from
general knowledge. Every step in the process was decided by the LLM agent
itself: which tool to call, what payload to try next, and when it had
gathered enough evidence to conclude. Nothing in this run was scripted as a
fixed sequence.

## 2. Scope and Safety Controls

- **Approved target only:** `http://localhost:3000`, running as an
  intentionally vulnerable practice instance (`bkimminich/juice-shop`) inside
  an isolated Docker network with no route to any external or production
  host.
- **Enforced in code, not just policy:** every tool the agent can call reads
  its target from a config-file allowlist. Tools reject any model-supplied
  host or a different target outright — the one tool that accepts
  model-chosen input (`http_request`, used for active testing) can only ever
  reach the configured target's host; a full URL or a different host is
  rejected before the request is sent. The agent cannot be steered off-scope
  by its own reasoning, correct or otherwise.
- No production, public, or third-party system was contacted at any point.

## 3. Agentic Pipeline Architecture

The pipeline is a [LangGraph](https://github.com/langchain-ai/langgraph)
`StateGraph` with two nodes:

```
agent (LLM bound to 4 tools) <-> tools (executes whichever tool was requested)
```

The `agent` node calls a large language model (served via OpenRouter's free
tier, with an automatic fallback chain across multiple models if one is
rate-limited or unavailable). If the model's reply requests a tool call,
control passes to the `tools` node, which executes it and returns the real
result to the model. This repeats until the model itself decides it has
gathered enough evidence and replies with a final structured report instead
of another tool call — that decision is the graph's exit condition. **The
agent chooses which tool to call, in what order, with what arguments, and
when to stop; no fixed sequence of steps is hardcoded.** This is what makes
the process agentic rather than a scripted scanner with a language model
bolted on for wording.

**Tools available to the agent:**

| Tool | Purpose |
|---|---|
| `scan_web` | OWASP ZAP baseline scan (passive + light-active): headers, cookies, CSP, cross-domain configuration |
| `scan_dependencies` | `npm audit` against the exact dependencies installed in the running container, with GHSA advisory IDs resolved to real CVE identifiers via OSV.dev |
| `lookup_cve` | NVD lookup for CVSS score and summary, cross-referenced against Exploit-DB's own published CVE index for a matching proof-of-concept |
| `http_request` | Live HTTP requests against the approved target for active testing — the agent chooses the path, method, JSON/form body, and headers, and uses this to register accounts, log in, and actively probe for SQL injection, XSS, broken access control (IDOR), CORS misconfiguration, mass assignment, and JWT weaknesses |

**Generalization.** The pipeline is not hardcoded to Juice Shop. All
target-specific information — target URL, allowlist, container
name/image/port, and target-specific hints for the agent — lives in a config
file selected via an environment variable at startup, so pointing the same,
unmodified codebase at a different approved target (e.g. DVWA) is a
configuration change, not a code change. The web-scanning tool reaches the
target through its host-published port rather than any target-specific
internal network address, so it works regardless of how or whether the
target is containerized. *(Note: this session verified the pipeline runs
correctly and generalizes architecturally; a live second-target run was not
completed in this cycle — say so plainly in your write-up rather than
claiming a test that didn't happen.)*

**Reliability.** Free-tier LLM inference is intermittently rate-limited; the
agent automatically rotates through a configured list of fallback models
rather than failing the run outright when one is unavailable.

## 4. Findings Summary

| ID | Finding | Severity | Source | CVE |
|---|---|---|---|---|
| F1 | SQL Injection in login — full admin takeover | Critical | Active exploitation | — (application logic) |
| F2 | SQL Injection in product search — DB exfiltration via UNION | Critical | Active exploitation | — (application logic) |
| F3 | Broken Access Control (IDOR) on basket endpoint | High | Active exploitation | — (application logic) |
| F4 | CORS misconfiguration — wildcard origin + credentials | High | Active exploitation | — (application logic) |
| F5 | Default administrator credentials active | High | Active exploitation | — (application logic) |
| F6 | crypto-js — weak PBKDF2 implementation | Critical | Dependency (SCA) | CVE-2023-46233 (CVSS 9.1) |
| F7 | crypto-js — insufficient entropy in RNG | Critical | Dependency (SCA) | CVE-2026-71851 (CVSS 9.0) |
| F8 | decompress — Zip Slip arbitrary file write | Critical | Dependency (SCA) | CVE-2026-10732 (CVSS 6.4) |
| F9 | decompress — arbitrary hardlink creation | Critical | Dependency (SCA) | CVE-2026-39243 (CVSS 5.5) |
| F10 | decompress — archive extraction path traversal | Critical | Dependency (SCA) | CVE-2026-53486 (CVSS 9.1) |
| F11 | js-yaml — CPU exhaustion via merge keys | High | Dependency (SCA) | CVE-2026-84375 (CVSS 7.5) |
| F12 | ws — DoS via excessive HTTP headers | High | Dependency (SCA) | CVE-2024-37890 (CVSS 7.5) |
| F13 | ws — memory exhaustion DoS via tiny fragments | High | Dependency (SCA) | CVE-2026-48779 (CVSS 7.5) |
| F14 | Content Security Policy header not set | Medium | Web-layer scan | — |
| F15 | Cross-domain misconfiguration | Medium | Web-layer scan | — |
| F16 | Cross-Origin-Embedder-Policy missing/invalid | Low | Web-layer scan | — |
| F17 | Cross-Origin-Opener-Policy missing/invalid | Low | Web-layer scan | — |
| F18 | Dangerous JS functions present | Low | Web-layer scan | — |
| F19 | Deprecated Feature-Policy header set | Low | Web-layer scan | — |
| F20 | Timestamp disclosure (Unix) | Low | Web-layer scan | — |
| F21 | Modern web application (informational) | Info | Web-layer scan | — |
| F22 | Non-storable content | Info | Web-layer scan | — |
| F23 | Storable and cacheable content | Info | Web-layer scan | — |
| F24 | Storable but non-cacheable content | Info | Web-layer scan | — |

*(No Exploit-DB proof-of-concept was found for any of the CVEs above — checked
both via NVD's own references and a direct match against Exploit-DB's
published CVE index. This is a genuine, common outcome for library-patch
CVEs that were never demonstrated with a standalone PoC, not a broken lookup.)*

## 5. Detailed Findings — Active Exploitation

### F1. SQL Injection — Authentication Bypass (`POST /rest/user/login`)
**Severity: Critical**

**Payload:** `{"email": "' OR 1=1--", "password": "x"}`

**Result:** HTTP 200 with a valid, server-signed JWT. Decoding the token
payload showed `{"id":1, "email":"admin@juice-sh.op", "role":"admin", ...}`
— the application authenticated the attacker as the built-in administrator
account despite no valid password being supplied.

**Root cause:** the `email` field is concatenated directly into the login
SQL query. The injected `OR 1=1--` clause matches the first row of the users
table and comments out the password check entirely.

**Impact:** complete authentication bypass; full administrative takeover
with zero valid credentials.

**Remediation:** parameterized queries / prepared statements for all
authentication logic; least-privilege DB account; rotate JWT/session
secrets after remediation.

### F2. SQL Injection — Product Search (`GET /rest/products/search?q=`)
**Severity: Critical**

Three independent confirmations on the `q` parameter:

1. `q=' OR 1=1--` → HTTP 200, returned the **entire products table**
   (boolean-based injection).
2. `q=car' UNION SELECT id,email,password,role FROM users--` → HTTP 200,
   returned rows from the **users table**, including the admin account's
   email, bcrypt password hash, and role (UNION-based injection — full
   database read).
3. `q='` (unterminated) → HTTP 500 with a raw `SQLITE_ERROR: incomplete
   input` leaked directly in the response body (error-based confirmation
   that unsanitized input reaches the SQL layer).

**Impact:** full database read access via an unauthenticated endpoint,
independent of the login vulnerability above.

**Remediation:** parameterize the search query; never return raw database
error messages to the client; least-privilege DB account.

### F3. Broken Access Control (IDOR) — `GET /rest/basket/{id}`
**Severity: High**

Using only a freshly-registered, low-privilege **customer** account's JWT,
`GET /rest/basket/1` returned HTTP 200 with the **administrator's** basket
contents. The endpoint checks that a valid session exists, but never checks
that the requested basket actually belongs to that session's user — access
is gated only by an incrementable integer ID.

**Impact:** horizontal privilege escalation; any authenticated user can read
(and, by the same logic, likely modify) any other user's basket.

**Remediation:** enforce `basket.user_id == session.user_id` server-side on
every object-referencing endpoint.

### F4. CORS Misconfiguration — Wildcard Origin with Credentials
**Severity: High**

`GET /rest/basket/1`, sent with a spoofed `Origin: https://evil.attacker.example`
header and a valid bearer token, returned HTTP 200 with **both**
`Access-Control-Allow-Origin: *` **and** `Access-Control-Allow-Credentials:
true` on an authenticated endpoint. The `Origin` header is not validated or
allow-listed anywhere observed.

**Impact:** this specific header combination is invalid per the CORS spec and
browsers will not expose a credentialed response to it directly — but it
demonstrates no origin validation exists at all, and combined with F1–F3
above, the underlying data is retrievable regardless of browser CORS
enforcement (e.g. via direct HTTP clients).

**Remediation:** reflect only an explicit allow-list of trusted origins;
never pair a wildcard origin with credentialed responses.

### F5. Default Administrator Credentials
**Severity: High**

`POST /rest/user/login` with `admin@juice-sh.op` / `admin123` returned a
full, valid administrative session. The stock default admin account and
password are active and reachable.

**Remediation:** force credential rotation at deployment; reject known
default credentials on privileged accounts.

## 6. Detailed Findings — Dependency Vulnerabilities (SCA)

`npm audit` was run against the exact `package.json`/`package-lock.json`
extracted from the running container (not from source, to reflect the
actual deployed versions). It reported **54 vulnerable packages** in total;
the 8 below were selected for CVE lookup as the critical/high-severity
findings with the most direct security impact. Full raw output is in
`agent/output/npm-audit.json`.

| Package | CVE | CVSS | Issue |
|---|---|---|---|
| crypto-js | CVE-2023-46233 | 9.1 | PBKDF2 implementation ~1,000,000x weaker than the current standard |
| crypto-js | CVE-2026-71851 | 9.0 | Non-cryptographic PRNG used for key/secret generation |
| decompress | CVE-2026-10732 | 6.4 | Zip Slip — arbitrary file write outside extraction directory |
| decompress | CVE-2026-39243 | 5.5 | Arbitrary hardlink creation during extraction |
| decompress | CVE-2026-53486 | 9.1 | Archive extraction path traversal |
| js-yaml | CVE-2026-84375 | 7.5 | CPU exhaustion via unbounded merge-key processing |
| ws | CVE-2024-37890 | 7.5 | DoS via excessive HTTP headers |
| ws | CVE-2026-48779 | 7.5 | Memory-exhaustion DoS via tiny fragments |

**Remediation:** upgrade each package to the patched version identified in
`agent/output/report.json`; re-run `npm audit` after upgrading to confirm
resolution.

## 7. Remediation Priority

1. **Immediate:** parameterize the login and search queries (F1, F2) —
   these grant full application and database compromise with zero
   credentials.
2. **Immediate:** add object-ownership checks to the basket endpoint (F3).
3. **High:** rotate default admin credentials (F5); fix CORS origin
   validation (F4).
4. **High:** upgrade crypto-js, decompress (F6–F10) — critical-rated,
   directly exploitable if reachable.
5. **Medium:** upgrade js-yaml, ws (F11–F13); add missing security headers
   (F14–F19).

## 8. Limitations

- Exploit-DB matching legitimately returned no results for any CVE in this
  report — many dependency CVEs are fixed by a version bump and never
  receive a standalone public proof-of-concept. This was verified by
  checking both NVD's own references and a direct match against Exploit-DB's
  published CVE-to-exploit index, not assumed.
- The course-concept mapping (Section 7) and academic-integrity-sensitive
  scoping decisions were intentionally kept outside the agent's
  responsibility, per the assignment's rules.
- OWASP Top 10 / CWE categorization is likewise a manual step and is not
  included in `agent/output/report.json` by design.

---

*All findings above are reproduced verbatim from `agent/output/report.json`,
cross-checked against `agent/output/transcript.json`
(the full agent tool-call log), `agent/output/zap-report.json`, and
`agent/output/npm-audit.json`. Nothing in this report was written from
memory or inferred without a corresponding tool execution.*
