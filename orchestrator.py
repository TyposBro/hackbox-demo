"""Hackbox orchestrator — the whole pipeline, end to end.

    python orchestrator.py

1. Validates the run against scope.yaml (no authorization record, no run)
2. Starts the target inside a Daytona sandbox, exposed by signed preview URL
3. Runs the vulnerability scan inside a second Daytona sandbox
4. Runs the load test inside a third sandbox, with a live kill switch
5. Writes a hash-chained audit log
6. Renders the report and serves it from a sandbox as a public URL

Every run uses fresh sandboxes that are destroyed afterwards. Nothing is reused.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent


def _load_env() -> None:
    for candidate in (HERE / ".env", Path.home() / "Documents/hacksprint-daytona/.env"):
        if candidate.exists():
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
            return


_load_env()

import yaml  # noqa: E402

from daytona import (  # noqa: E402
    CreateSandboxFromSnapshotParams,
    Daytona,
    DaytonaConfig,
)

TTL = int(os.environ.get("SANDBOX_TTL_MINUTES", "45"))
AUDIT = HERE / "audit.jsonl"
RUN_ID = datetime.now(timezone.utc).strftime("run-%Y%m%d-%H%M%S")


# --------------------------------------------------------------------------- audit
def audit(event: str, **fields) -> dict:
    """Append-only, hash-chained. Each entry commits to the previous one."""
    previous = ""
    if AUDIT.exists():
        lines = AUDIT.read_text().strip().splitlines()
        if lines:
            previous = json.loads(lines[-1])["hash"]
    entry = {
        "run_id": RUN_ID,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        **fields,
        "prev": previous,
    }
    blob = json.dumps(entry, sort_keys=True)
    entry["hash"] = hashlib.sha256((previous + blob).encode()).hexdigest()[:16]
    with AUDIT.open("a") as handle:
        handle.write(json.dumps(entry) + "\n")
    print(f"  audit  {entry['event']:<22} {entry['hash']}")
    return entry


# --------------------------------------------------------------------------- helpers
def push(sandbox, local_path: Path, remote_path: str) -> None:
    payload = base64.b64encode(local_path.read_bytes()).decode()
    sandbox.process.code_run(
        "import base64, pathlib\n"
        f"p = pathlib.Path({remote_path!r})\n"
        "p.parent.mkdir(parents=True, exist_ok=True)\n"
        f"p.write_bytes(base64.b64decode({payload!r}))\n"
    )


def load_scope() -> dict:
    config = yaml.safe_load((HERE / "scope.yaml").read_text())
    run = config["runs"][0]
    if not run.get("authorized"):
        raise SystemExit("REFUSED: no authorization record for this target.")
    return run


# --------------------------------------------------------------------------- report
PAGE = """<!doctype html><meta charset="utf-8"><title>Hackbox report</title>
<style>
 :root{color-scheme:dark}
 body{background:#0b0d10;color:#e6e9ef;font:14px/1.55 ui-monospace,Menlo,monospace;margin:0;padding:32px}
 h1{font-size:20px;margin:0 0 2px} h2{font-size:14px;color:#8b93a1;text-transform:uppercase;
 letter-spacing:.08em;margin:28px 0 10px;font-weight:500}
 .sub{color:#8b93a1;margin-bottom:20px}
 .stats{display:flex;gap:26px;flex-wrap:wrap}
 .stat b{display:block;font-size:24px;font-weight:600} .stat span{color:#8b93a1;font-size:11px;
 text-transform:uppercase;letter-spacing:.06em}
 table{border-collapse:collapse;width:100%;margin-top:6px}
 th{text-align:left;color:#8b93a1;font-weight:500;font-size:11px;text-transform:uppercase;
 padding:6px 10px;border-bottom:1px solid #1e242e}
 td{padding:9px 10px;border-bottom:1px solid #141920;vertical-align:top}
 .high{color:#ff8f8f} .medium{color:#ffd479} .low{color:#8fd3ff}
 code{background:#151a21;padding:1px 5px;border-radius:3px;font-size:12px}
 .abort{color:#ff8f8f} .clean{color:#5ee89b}
 footer{margin-top:26px;color:#6b7280;font-size:12px}
</style>
<h1>Hackbox report</h1>
<div class="sub">__RUN__ &middot; target __TARGET__ &middot; generated __AT__</div>
<div class="stats">
 <div class="stat"><b>__NFIND__</b><span>findings</span></div>
 <div class="stat"><b>__RPS__</b><span>peak rps</span></div>
 <div class="stat"><b>__ERR__</b><span>error rate</span></div>
 <div class="stat"><b>__P95__</b><span>p95 ms</span></div>
 <div class="stat"><b class="__STATUSCLASS__">__STATUS__</b><span>run status</span></div>
</div>
<h2>Vulnerability findings</h2>
<table><tr><th>sev</th><th>cvss</th><th>finding</th><th>owasp</th><th>endpoint</th><th>reproduce</th></tr>
__ROWS__
</table>
<h2>Load test</h2>
<table><tr><th>metric</th><th>value</th></tr>
__LOADROWS__
</table>
<h2>Audit log</h2>
<table><tr><th>at</th><th>event</th><th>hash</th></tr>
__AUDITROWS__
</table>
<footer>Every phase ran in a fresh Daytona sandbox that was destroyed afterwards.
The audit log is hash-chained: each entry commits to the one before it.</footer>
"""


def render(run, findings, load, entries, status) -> str:
    rows = "".join(
        f"<tr><td class='{f['severity']}'>{f['severity']}</td><td>{f['cvss']}</td>"
        f"<td>{f['title']}</td><td>{f['owasp']}</td><td><code>{f['endpoint']}</code></td>"
        f"<td><code>{f['repro'][:90]}</code></td></tr>"
        for f in findings
    ) or "<tr><td colspan=6>no findings</td></tr>"
    load_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in load.items()
    ) or "<tr><td colspan=2>load test did not run</td></tr>"
    audit_rows = "".join(
        f"<tr><td>{e['at']}</td><td>{e['event']}</td><td><code>{e['hash']}</code></td></tr>"
        for e in entries
    )
    peak = load.get("peak_rps", 0)
    return (
        PAGE.replace("__RUN__", RUN_ID)
        .replace("__TARGET__", run["target"])
        .replace("__AT__", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"))
        .replace("__NFIND__", str(len(findings)))
        .replace("__RPS__", str(peak))
        .replace("__ERR__", f"{load.get('error_rate', 0) * 100:.1f}%")
        .replace("__P95__", str(load.get("p95_ms", 0)))
        .replace("__STATUS__", status)
        .replace("__STATUSCLASS__", "abort" if status != "completed" else "clean")
        .replace("__ROWS__", rows)
        .replace("__LOADROWS__", load_rows)
        .replace("__AUDITROWS__", audit_rows)
    )


# --------------------------------------------------------------------------- main
def main() -> int:
    run = load_scope()
    limits = run["limits"]
    stop = run["stop_conditions"]
    entries = []

    print(f"\nRUN {RUN_ID}")
    print(f"target      {run['target']}  ({run['description']})")
    print(f"authorized  {run['requester']}")
    print(f"limits      {limits['max_concurrency']} concurrent, "
          f"{limits['max_duration_seconds']}s, {limits['max_requests_per_second']} rps max")
    print(f"kill switch error rate > {stop['max_error_rate']:.0%} "
          f"or p95 > {stop['max_p95_ms']}ms\n")

    entries.append(audit("run.authorized", target=run["target"], requester=run["requester"]))

    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"],
                                    target=os.environ.get("DAYTONA_TARGET", "us")))
    victim = scanner = loader = None
    status = "completed"
    findings: list[dict] = []
    load: dict = {}

    try:
        # ---- target ------------------------------------------------------
        print("phase 1/4  starting target in a fresh sandbox")
        victim = daytona.create()
        victim.set_ttl(TTL)
        push(victim, HERE / "victim.js", "/home/daytona/victim.js")
        victim.process.exec("cd /home/daytona && nohup node victim.js >/tmp/victim.log 2>&1 &")
        time.sleep(1.5)
        health = victim.process.exec(
            "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/health").result.strip()
        target_url = victim.create_signed_preview_url(3000, expires_in_seconds=TTL * 60).url
        # The scanner and the load generators talk to the target over the internal link
        # network. The public URL exists only so a human can look at it in a browser.
        internal_url = f"http://{victim.name}:3000"
        entries.append(audit("target.started", sandbox=victim.id, health=health,
                             internal=internal_url))
        print(f"           sandbox {victim.id}  health {health}")
        print(f"           internal target  {internal_url}   (link network, not public)")
        print(f"           human view       {target_url}\n")

        # ---- scan --------------------------------------------------------
        print("phase 2/4  vulnerability scan in a fresh sandbox")
        # Linked sandbox: joins the parent's internal link network, reachable by DNS alias.
        # This is why the target never has to be exposed to the public internet.
        scanner = daytona.create(CreateSandboxFromSnapshotParams(
            linked_sandbox=victim.id, ephemeral=True, auto_delete_interval=0))
        push(scanner, HERE / "probe.py", "/home/daytona/probe.py")
        t0 = time.perf_counter()
        scan = scanner.process.exec(f"cd /home/daytona && python3 probe.py {internal_url}", timeout=180)
        scan_seconds = time.perf_counter() - t0
        for line in (scan.result or "").splitlines():
            if line.startswith("FINDING "):
                findings.append(json.loads(line[8:]))
        entries.append(audit("scan.completed", sandbox=scanner.id,
                             findings=len(findings), seconds=round(scan_seconds, 1)))
        print(f"           sandbox {scanner.id}  {len(findings)} findings in {scan_seconds:.1f}s")
        for f in findings:
            print(f"             [{f['severity']:<6}] {f['title']}")
        print()

        # ---- load --------------------------------------------------------
        print("phase 3/4  load test in a fresh sandbox, kill switch armed")
        loader = daytona.create(CreateSandboxFromSnapshotParams(
            linked_sandbox=victim.id, ephemeral=True, auto_delete_interval=0))
        push(loader, HERE / "loadgen.js", "/home/daytona/loadgen.js")
        loader.process.exec(
            f"cd /home/daytona && nohup node loadgen.js {internal_url} "
            f"{limits['max_concurrency']} 15 {limits['max_duration_seconds']} "
            ">/tmp/load.log 2>&1 &")
        time.sleep(2)

        peak_rps = 0.0
        aborted = False
        deadline = time.time() + limits["max_duration_seconds"]
        while time.time() < deadline:
            raw = loader.process.exec("curl -s -m 5 http://localhost:3001/stats", timeout=30)
            try:
                current = json.loads((raw.result or "{}").strip() or "{}")
            except json.JSONDecodeError:
                time.sleep(1)
                continue
            peak_rps = max(peak_rps, current.get("rps", 0))
            print(f"             rps {current.get('rps', 0):7.1f}   "
                  f"err {current.get('error_rate', 0) * 100:5.1f}%   "
                  f"p95 {current.get('p95_ms', 0):5.0f}ms   "
                  f"conc {current.get('peak_concurrency', 0)}", flush=True)

            if current.get("error_rate", 0) > stop["max_error_rate"]:
                loader.process.exec("curl -s http://localhost:3001/stop")
                entries.append(audit("killswitch.fired", reason="error_rate",
                                     value=round(current["error_rate"], 3),
                                     threshold=stop["max_error_rate"]))
                print("             KILL SWITCH: error rate crossed the agreed threshold")
                aborted = True
                status = "aborted"
                break
            if current.get("p95_ms", 0) > stop["max_p95_ms"]:
                loader.process.exec("curl -s http://localhost:3001/stop")
                entries.append(audit("killswitch.fired", reason="p95",
                                     value=current["p95_ms"], threshold=stop["max_p95_ms"]))
                print("             KILL SWITCH: p95 crossed the agreed threshold")
                aborted = True
                status = "aborted"
                break
            if current.get("stopped"):
                break
            time.sleep(1)

        final = json.loads((loader.process.exec(
            "curl -s -m 5 http://localhost:3001/stats").result or "{}").strip() or "{}")
        load = {
            "peak rps": round(peak_rps, 1),
            "total requests": final.get("sent", 0),
            "failed requests": final.get("failed", 0),
            "error rate": f"{final.get('error_rate', 0) * 100:.1f}%",
            "p50 latency": f"{final.get('p50_ms', 0)} ms",
            "p95 latency": f"{final.get('p95_ms', 0)} ms",
            "peak concurrency": final.get("peak_concurrency", 0),
            "kill switch": "FIRED" if aborted else "armed, not triggered",
        }
        entries.append(audit("load.completed", sandbox=loader.id, **{
            k.replace(" ", "_"): v for k, v in load.items()}))
        print()

        # ---- report ------------------------------------------------------
        print("phase 4/4  rendering report")
        html = render(run, findings, load, entries, status)
        (HERE / "report.html").write_text(html)
        push(scanner, HERE / "report.html", "/home/daytona/report.html")
        scanner.process.exec(
            "cd /home/daytona && nohup python3 -m http.server 3002 >/tmp/http.log 2>&1 &")
        time.sleep(1.5)
        report_url = scanner.create_signed_preview_url(3002, expires_in_seconds=TTL * 60).url
        entries.append(audit("report.published", url=report_url, status=status))

        print(f"\n{'=' * 68}")
        print(f"  REPORT   {report_url}")
        print(f"  TARGET   {target_url}   (human view)")
        print(f"  STATUS   {status}   findings {len(findings)}   peak {peak_rps:.0f} rps")
        print(f"{'=' * 68}\n")
        return 0

    except Exception as exc:
        status = "failed"
        entries.append(audit("run.failed", error=f"{type(exc).__name__}: {exc}"[:300]))
        print(f"\nRUN FAILED: {type(exc).__name__}: {exc}")
        return 1
    finally:
        # Sandboxes carry a TTL, but destroy them now so the demo leaves nothing running.
        # Linked children are ephemeral and cascade with the parent, so destroy the parent
        # first and treat a missing child as already gone.
        for name, sandbox in (("victim", victim), ("scanner", scanner), ("loader", loader)):
            if sandbox is None:
                continue
            try:
                sandbox.delete(60, True)
                print(f"destroyed {name} sandbox {sandbox.id}")
            except Exception as exc:
                if "not found" in str(exc).lower() or "ID or name" in str(exc):
                    print(f"{name} sandbox already gone (cascaded with the target)")
                else:
                    print(f"could not destroy {name}: {str(exc)[:80]}")


if __name__ == "__main__":
    raise SystemExit(main())
