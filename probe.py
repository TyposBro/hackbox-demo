"""Hackbox probe scanner. Runs INSIDE a Daytona sandbox. Python stdlib only, zero install.

Deterministic checks against an authorized target, mapped to OWASP categories:
  A03 Injection      - reflected XSS, SQL-ish concatenation echo
  A05 Misconfiguration - missing security headers
  A09 Logging        - server banner / version disclosure

Emits one JSON object per finding, one per line, so the orchestrator can stream them.
"""

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TARGET = sys.argv[1].rstrip("/")
TIMEOUT = 10
UA = "Hackbox/1.0 (authorized security test)"


def fetch(path, headers=None):
    request = urllib.request.Request(TARGET + path, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, dict(response.headers), response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode(errors="replace")
    except Exception as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


def finding(title, owasp, severity, cvss, endpoint, evidence, repro):
    return {
        "title": title,
        "owasp": owasp,
        "severity": severity,
        "cvss": cvss,
        "endpoint": endpoint,
        "evidence": evidence[:400],
        "repro": repro,
    }


results = []

# --- reachability gate ------------------------------------------------------------
# Without this an unreachable target produces a false "missing security headers" finding,
# because every header is absent when no response ever arrives.
status, _, body = fetch("/health")
if status != 200:
    print(f"SCAN_ERROR target unreachable at {TARGET}: status={status} body={body[:160]}")
    raise SystemExit(3)

# --- A03 Injection: reflected XSS -------------------------------------------------
payload = "<script>alert(1)</script>"
status, headers, body = fetch("/search?q=" + urllib.parse.quote(payload))
if status == 200 and payload in body:
    results.append(finding(
        "Reflected Cross-Site Scripting (XSS)",
        "A03:2021 Injection", "high", 7.4,
        "/search?q=",
        f"payload reflected unescaped into the HTML body: {payload}",
        f"curl '{TARGET}/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'",
    ))

# --- A03 Injection: naive SQL concatenation ---------------------------------------
sqli = "1 OR 1=1"
status, headers, body = fetch("/user?id=" + urllib.parse.quote(sqli))
if status == 200 and ("OR 1=1" in body or "select" in body.lower()):
    results.append(finding(
        "SQL Query Built By String Concatenation",
        "A03:2021 Injection", "high", 8.1,
        "/user?id=",
        f"user input reaches a query string unparameterised: {body[:200]}",
        f"curl '{TARGET}/user?id=1%20OR%201%3D1'",
    ))

# --- A05 Misconfiguration: security headers ---------------------------------------
status, headers, _ = fetch("/")
lower = {k.lower(): v for k, v in headers.items()}
missing = [h for h in (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
) if h not in lower]
if missing:
    results.append(finding(
        "Missing HTTP Security Headers",
        "A05:2021 Security Misconfiguration", "medium", 5.3,
        "/",
        "absent: " + ", ".join(missing),
        f"curl -sI '{TARGET}/'",
    ))

# --- A09 Logging: version disclosure ----------------------------------------------
status, headers, _ = fetch("/")
server = lower.get("server", "")
if re.search(r"\d+\.\d+", server):
    results.append(finding(
        "Server Version Disclosure",
        "A09:2021 Security Logging and Monitoring Failures", "low", 3.1,
        "/",
        f"Server header advertises a version: {server}",
        f"curl -sI '{TARGET}/'",
    ))

# --- Rate limiting ----------------------------------------------------------------
codes = []
for _ in range(25):
    status, _, _ = fetch("/")
    codes.append(status)
if codes and all(c == 200 for c in codes):
    results.append(finding(
        "No Rate Limiting On Request Path",
        "A04:2021 Insecure Design", "medium", 5.9,
        "/",
        f"{len(codes)} rapid requests all returned 200 with no throttling",
        f"for i in $(seq 25); do curl -s -o /dev/null -w '%{{http_code}} ' '{TARGET}/'; done",
    ))

for item in results:
    print("FINDING " + json.dumps(item))

print(f"SCAN_COMPLETE {len(results)} findings against {TARGET}")
