"""Hackbox demo — the whole Daytona half, verified end to end.

Sandbox A: runs victim.js, exposes it with a signed preview URL that opens in any browser.
Sandbox B: installs Nuclei, scans that URL, prints findings as JSON.

    python demo.py

Prints everything you need to put on stage. Uses 2 of the 10 vCPUs the tier allows.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

HERE = Path(__file__).parent


def _load_env() -> None:
    for candidate in (HERE / ".env", Path.home() / "Documents/hacksprint-daytona/.env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
        return


_load_env()

from daytona import Daytona, DaytonaConfig  # noqa: E402

TTL = int(os.environ.get("SANDBOX_TTL_MINUTES", "45"))


def push(sandbox, local_path: Path, remote_path: str) -> None:
    """Write a local file into the sandbox without quoting hazards."""
    payload = base64.b64encode(local_path.read_bytes()).decode()
    sandbox.process.code_run(
        "import base64, pathlib\n"
        f"p = pathlib.Path({remote_path!r})\n"
        "p.parent.mkdir(parents=True, exist_ok=True)\n"
        f"p.write_bytes(base64.b64decode({payload!r}))\n"
        "print('wrote', p, p.stat().st_size, 'bytes')\n"
    )


def main() -> int:
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"],
                                    target=os.environ.get("DAYTONA_TARGET", "us")))
    victim_sb = scanner_sb = None
    try:
        # ---- Sandbox A: the victim app -------------------------------------
        print("creating victim sandbox...", flush=True)
        victim_sb = daytona.create()
        victim_sb.set_ttl(TTL)
        push(victim_sb, HERE / "victim.js", "/home/daytona/victim.js")
        victim_sb.process.exec("cd /home/daytona && nohup node victim.js >/tmp/victim.log 2>&1 &")
        time.sleep(1.5)

        probe = victim_sb.process.exec("curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/health")
        print(f"victim health probe: HTTP {probe.result.strip()}", flush=True)

        # get_preview_link() needs a header, so a browser gets 401. The signed form does not.
        signed = victim_sb.create_signed_preview_url(3000, expires_in_seconds=TTL * 60)
        target = signed.url
        print(f"\nTARGET (opens in any browser): {target}\n", flush=True)

        # ---- Sandbox B: the scanner ----------------------------------------
        print("creating scanner sandbox...", flush=True)
        scanner_sb = daytona.create()
        scanner_sb.set_ttl(TTL)
        install = scanner_sb.process.exec(
            "curl -sL -o /tmp/n.zip https://github.com/projectdiscovery/nuclei/releases/"
            "download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && "
            "(command -v unzip >/dev/null || sudo apt-get install -y -qq unzip >/dev/null 2>&1); "
            "unzip -o -q /tmp/n.zip -d /usr/local/bin && nuclei -version 2>&1 | head -1",
            timeout=300,
        )
        print(f"nuclei: {(install.result or '').strip()[:120]}", flush=True)

        push(scanner_sb, HERE / "xss-template.yaml", "/home/daytona/xss-template.yaml")

        print("\nscanning...", flush=True)
        t0 = time.perf_counter()
        scan = scanner_sb.process.exec(
            f"cd /home/daytona && nuclei -u {target} -t xss-template.yaml "
            "-jsonl -silent -no-color -timeout 10 -retries 1 2>&1 | head -20",
            timeout=240,
        )
        print(f"scan finished in {time.perf_counter() - t0:.1f}s\n", flush=True)

        findings = []
        for line in (scan.result or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if findings:
            for f in findings:
                info = f.get("info", {})
                print(f"  FINDING  [{info.get('severity', '?').upper()}] {info.get('name')}")
                print(f"           {f.get('matched-at') or f.get('host')}")
        else:
            print("  no findings parsed. raw output:")
            print("  " + (scan.result or "(empty)").strip()[:600])

        Path(HERE / "findings.json").write_text(json.dumps(findings, indent=2))
        print(f"\nwrote findings.json ({len(findings)} findings)")
        print(f"\nvictim sandbox:  {victim_sb.id}")
        print(f"scanner sandbox: {scanner_sb.id}")
        print(f"target URL:      {target}")
        print("\nBoth sandboxes have a TTL and will clean themselves up.")
        return 0
    finally:
        pass  # leave them running for the demo; TTL handles cleanup


if __name__ == "__main__":
    raise SystemExit(main())
