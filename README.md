# Hackbox — demo slice

A cut-down, runnable slice of [Hackbox](../hackbox): an internal security testing platform that runs
vulnerability scanning inside isolated [Daytona](https://www.daytona.io) sandboxes.

The full spec has seven phases. This is the part that runs, built and verified during the
HackSprint Seoul hackathon on 2026-09-19.

## What works, verified live

| Piece | Status |
|---|---|
| Victim app running inside a Daytona sandbox | Verified, HTTP 200 on `/health` |
| Public target URL via `create_signed_preview_url()` | Verified, opens in any browser with no headers |
| Probe scanner running inside a second sandbox | Verified, 0.7s, stdlib only, zero install |
| Nuclei install inside a sandbox | Verified, 4.1s |
| Sandbox teardown via TTL | Verified |

## The design decision that made this possible

The full spec's Phase 1 builds a tunnel manager, because Nosana workers and Daytona sandboxes cannot
reach `localhost`.

This slice removes that entirely. The victim app runs inside a Daytona sandbox and is exposed with
`create_signed_preview_url(port, expires_in_seconds=...)`. That URL is reachable from the public
internet with no auth headers, so both the scanner sandbox and any remote worker can hit it.

One less component, and the demo target is a machine we own end to end.

Note: `get_preview_link()` returns a token that must be sent as an `x-daytona-preview-token`
header, so its bare URL returns 401 in a browser. The signed form bakes the token into the
hostname. Use the signed form.

## Why a stdlib probe scanner instead of ZAP

Measured inside a real Daytona sandbox:

- No Docker, so the ZAP container image is not usable.
- No Java, so a native ZAP install needs a JVM first.
- Nuclei installs in 4.1s and runs, but its template matching did not fire reliably against a
  dynamically generated target within the time budget.

So the scanner is `probe.py`: Python stdlib, zero install, deterministic checks, 0.7s per run.
It covers reflected XSS, unparameterised SQL, missing security headers, version disclosure, and
missing rate limiting, each mapped to an OWASP category and a CVSS score.

Correctness beats brand here. The finding schema and CVSS mapping are what the report consumes.

## Files

| File | Purpose |
|---|---|
| `victim.js` | The target. Node stdlib, starts instantly. Contains three planted bugs. |
| `probe.py` | The scanner. Runs inside a sandbox. Emits one JSON finding per line. |
| `demo.py` | Creates both sandboxes, launches the victim, prints the public URL, runs the scan. |
| `xss-template.yaml` | Nuclei template, kept for the full-scan path. |

## Run it

```bash
python demo.py
```

Uses 2 of the 10 vCPUs the hackathon tier allows. Both sandboxes carry a TTL and clean themselves
up. Verified numbers from this tier: `create()` median 2.6s, a scan cell costs about 3.6s
end to end.

## Daytona integration, for the code-level review

| Call | Where | What it does |
|---|---|---|
| `Daytona(DaytonaConfig(...))` | `demo.py` | Client construction from env config |
| `daytona.create()` | `demo.py` | A fresh isolated machine per role, never reused |
| `sandbox.process.code_run()` | `demo.py` | Writes files into the sandbox without quoting hazards |
| `sandbox.process.exec()` | `demo.py` | Launches the target, runs the scanner |
| `sandbox.create_signed_preview_url(3000, ...)` | `demo.py` | Public, browser-openable URL for the target |
| `sandbox.set_ttl()` | `demo.py` | Guarantees teardown even if the orchestrator dies |

## Operational notes from this tier

- Total CPU limit is 10 vCPU and `daytona-small` is 1 vCPU, so 10 concurrent sandboxes is the cap.
  Exceeding it fails `create()` with HTTP 400.
- `delete()` is fire-and-forget and does not release the vCPU. Orphaned sandboxes accumulate until
  every later `create()` fails. Always pass `wait=True`.
- `asyncio.gather` without `return_exceptions=True` aborts on the first bad cell and orphans its
  siblings. That exhausted the quota once.

## Next

Nosana's load-testing phase, and the reporting and audit log from the full spec.
