"""
Deterministic tools the agent can call. Each tool acts only on the
pre-configured, allow-listed target loaded from config.json -- the model
never supplies a host/container. `http_request` is the one exception to
"the model supplies nothing": its whole job is active testing, so the model
does choose the path/method/payload -- but the host is still always pinned
to TARGET_URL and a full URL or different host is rejected, so the model
can steer *what* gets sent but never *where*.
"""
import csv
import io
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import requests
from langchain_core.tools import tool

NPM_CMD = shutil.which("npm") or "npm"  # Windows needs the resolved npm.cmd path

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

TARGET_URL = CONFIG["target_url"]
CONTAINER = CONFIG["juiceshop_container"]
NETWORK = CONFIG["docker_network"]
IMAGE = CONFIG["juiceshop_image"]

if TARGET_URL not in CONFIG["allowed_targets"]:
    raise RuntimeError(f"Configured target {TARGET_URL} is not on the allowlist")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ensure_juiceshop_running() -> None:
    """Idempotently create the isolated network and start the Juice Shop
    container if it isn't already running, then wait until it answers."""
    _run(["docker", "network", "create", NETWORK], timeout=15)  # ignore "already exists"

    inspect = _run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], timeout=15)
    if inspect.returncode != 0:
        started = _run(
            ["docker", "run", "-d", "--name", CONTAINER, "--network", NETWORK,
             "-p", "3000:3000", IMAGE],
            timeout=60,
        )
        if started.returncode != 0:
            raise RuntimeError(f"Failed to start Juice Shop container: {started.stderr}")
    elif inspect.stdout.strip() != "true":
        _run(["docker", "start", CONTAINER], timeout=30)

    for _ in range(30):
        try:
            if requests.get(TARGET_URL, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"Juice Shop did not become ready at {TARGET_URL} in time")


@tool
def scan_web() -> str:
    """Run an OWASP ZAP baseline scan against the approved target and
    return a summary of alerts (XSS, missing security headers, insecure
    cookies, etc). Full JSON report is written to output/zap-report.json."""
    report_path = OUTPUT_DIR / "zap-report.json"
    result = _run(
        [
            "docker", "run", "--rm", "--network", NETWORK,
            "-v", f"{OUTPUT_DIR}:/zap/wrk/:rw",
            "zaproxy/zap-stable", "zap-baseline.py",
            "-t", f"http://{CONTAINER}:3000",
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


@tool
def scan_dependencies() -> str:
    """Run a software-composition-analysis scan (npm audit) against the
    exact dependencies installed in the running Juice Shop container and
    return the vulnerable packages with their CVE/GHSA identifiers and
    severity. Full JSON is written to output/npm-audit.json."""
    audit_path = OUTPUT_DIR / "npm-audit.json"

    # The image is distroless (no shell, no npm binary inside), so `docker
    # exec` can't run anything. Instead, `docker cp` the manifest + lockfile
    # straight out of the container's filesystem and audit them with the
    # host's npm -- this reflects the exact versions actually deployed.
    pkg_dir = OUTPUT_DIR / "juiceshop_pkg"
    pkg_dir.mkdir(exist_ok=True)
    for fname in ("package.json", "package-lock.json"):
        cp = _run(["docker", "cp", f"{CONTAINER}:/juice-shop/{fname}", str(pkg_dir / fname)],
                   timeout=30)
        if cp.returncode != 0:
            return f"Could not copy {fname} out of the container: {cp.stderr[-500:]}"

    result = subprocess.run(
        [NPM_CMD, "audit", "--package-lock-only", "--json"],
        capture_output=True, text=True, timeout=60, cwd=str(pkg_dir),
    )
    raw = result.stdout.strip()

    if not raw:
        return f"npm audit produced no output. stderr: {result.stderr[-2000:]}"

    audit_path.write_text(raw)
    data = json.loads(raw)

    vulns = data.get("vulnerabilities", {})
    if not vulns:
        return "npm audit found no known-vulnerable dependencies."

    ghsa_cache: dict[str, list[str]] = {}

    def ghsa_to_cves(ghsa_id: str) -> list[str]:
        if ghsa_id not in ghsa_cache:
            try:
                r = requests.get(f"https://api.osv.dev/v1/vulns/{ghsa_id}", timeout=15)
                aliases = r.json().get("aliases", []) if r.status_code == 200 else []
            except requests.RequestException:
                aliases = []
            ghsa_cache[ghsa_id] = [a for a in aliases if CVE_RE.match(a)]
        return ghsa_cache[ghsa_id]

    lines = [f"npm audit found {len(vulns)} vulnerable package(s):"]
    for name, info in vulns.items():
        via = info.get("via", [])
        ghsa_ids = sorted({
            v["url"].rsplit("/", 1)[-1] for v in via
            if isinstance(v, dict) and "/advisories/GHSA-" in v.get("url", "")
        })
        cve_ids = sorted({cve for g in ghsa_ids for cve in ghsa_to_cves(g)})
        titles = [v.get("title") for v in via if isinstance(v, dict) and v.get("title")]

        id_str = ", ".join(cve_ids) if cve_ids else (", ".join(ghsa_ids) or "no advisory ID")
        lines.append(
            f"- {name} ({info.get('severity')}) [{id_str}]: "
            f"{'; '.join(titles) or 'see npm-audit.json'} [range: {info.get('range')}]"
        )

    (OUTPUT_DIR / "ghsa_cve_map.json").write_text(json.dumps(ghsa_cache, indent=2))
    return "\n".join(lines)


_EXPLOITDB_INDEX: dict[str, list[str]] | None = None
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


def _exploitdb_index() -> dict[str, list[str]]:
    """Lazily download and index Exploit-DB's public CSV (id, description,
    CVE codes) by CVE ID, once per process. This is a direct match against
    Exploit-DB's own data, not just whatever NVD happens to cross-reference."""
    global _EXPLOITDB_INDEX
    if _EXPLOITDB_INDEX is None:
        _EXPLOITDB_INDEX = {}
        try:
            r = requests.get(EXPLOITDB_CSV_URL, timeout=60)
            for row in csv.DictReader(io.StringIO(r.text)):
                for code in row.get("codes", "").split(";"):
                    code = code.strip()
                    if CVE_RE.match(code):
                        url = f"https://www.exploit-db.com/exploits/{row['id']}"
                        _EXPLOITDB_INDEX.setdefault(code, []).append(url)
        except requests.RequestException:
            pass  # leave the index empty rather than fail the whole lookup
    return _EXPLOITDB_INDEX


@tool
def lookup_cve(cve_id: str) -> str:
    """Look up a CVE ID in the NVD database and return its CVSS score and
    summary, plus any matching Exploit-DB entry -- checked both via NVD's
    own references and by a direct match against Exploit-DB's published
    CVE-to-exploit index. Pass a CVE ID like 'CVE-2021-23337'."""
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        return f"'{cve_id}' is not a valid CVE ID format (expected CVE-YYYY-NNNN)."

    # NVD's public API allows ~5 requests/30s without a key; a burst of
    # lookup_cve calls in one turn was hitting 429s, so throttle here.
    time.sleep(6)
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        timeout=30,
    )
    if resp.status_code != 200:
        return f"NVD lookup for {cve_id} failed with HTTP {resp.status_code}."

    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return f"{cve_id} not found in NVD."

    cve = vulns[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            score = metrics[key][0]["cvssData"]["baseScore"]
            break

    exploit_links = sorted(set(
        [r["url"] for r in cve.get("references", []) if "exploit-db.com" in r["url"]]
        + _exploitdb_index().get(cve_id, [])
    ))

    lines = [f"{cve_id}: CVSS={score}", f"Summary: {desc}"]
    lines.append(
        f"Exploit-DB reference(s): {', '.join(exploit_links)}"
        if exploit_links else "Exploit-DB reference(s): none found (checked NVD "
                              "references and Exploit-DB's own CVE index)."
    )
    return "\n".join(lines)


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
