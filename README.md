# Hackbox

Security testing that does not require trusting the tool with your laptop or your uptime.

Built at Daytona HackSprint Seoul, 2026-09-19.

## What it does

One command runs a vulnerability scan and a load test against a target you own:

```bash
python orchestrator.py
```

Four phases, each on a fresh Daytona sandbox:

1. The target application starts inside a sandbox.
2. A second sandbox scans it and reports findings with OWASP categories and CVSS scores.
3. A third sandbox generates load until the target degrades.
4. The report is rendered and published from a sandbox, and every step is written to a
   hash-chained audit log.

Then all of it is destroyed.

## Verified live

| Result | Value |
|---|---|
| Findings | 4, in under 1 second of scan time |
| Load ramp | 900 to 4,000 requests per second |
| Kill switch | Tripped automatically at the 15 percent error threshold |
| Sandbox create | About 2.6 seconds median |
| Sandboxes after the run | 0 |

## The design decision that matters most

The scanner and the load generators are **linked child sandboxes** on the same internal network as
the target:

```python
victim  = daytona.create()                              # the target
scanner = daytona.create(CreateSandboxFromSnapshotParams(
    linked_sandbox=victim.id, ephemeral=True, auto_delete_interval=0))
```

Linked sandboxes share a link network and are addressable by DNS alias, so the scanner reaches the
target at `http://<victim.name>:3000`.

This means **the target is never exposed to the public internet**. An earlier version published the
target through a public preview URL; it worked from a browser but was unreachable from inside
another sandbox, which silently broke the scan and the load test. Moving to linked sandboxes fixed
both and removed the public exposure entirely.

## Safeguards

| Safeguard | How it works |
|---|---|
| Authorization | `scope.yaml` holds target, requester, window, allowed test types and limits. No record, no run. |
| Traffic ceiling | Concurrency, duration and request rate come from the scope file, not the command line. |
| Kill switch | The orchestrator polls live error rate and p95, and aborts when either crosses the agreed stop condition. |
| Audit log | Append-only, each entry hashes the previous one, so a run cannot be edited afterwards. |
| Isolation | A fresh sandbox per phase, destroyed in a `finally` block. Nothing is reused. |
| No public exposure | The target is reachable only over the internal link network. |

## Findings it detects

All mapped to OWASP categories and CVSS scores:

- Reflected cross-site scripting (A03, CVSS 7.4)
- SQL query built by string concatenation (A03, CVSS 8.1)
- Missing HTTP security headers (A05, CVSS 5.3)
- No rate limiting on a request path (A04, CVSS 5.9)
- Server version disclosure (A09, CVSS 3.1)

## Files

| File | Purpose |
|---|---|
| `orchestrator.py` | The pipeline: scope validation, four phases, kill switch, audit, report |
| `probe.py` | The scanner. Runs inside a sandbox. Python stdlib, zero install |
| `loadgen.js` | The load generator. Runs inside a sandbox. Node stdlib |
| `victim.js` | Demo target with planted bugs and a soft capacity ceiling |
| `scope.yaml` | The authorization record |
| `PITCH.md` | The three-minute stage script |

## Why the scanner is not ZAP

Measured inside a real Daytona sandbox: no Docker (so the ZAP image is unusable) and no Java (so a
native install needs a JVM first). Nuclei installs in 4.1 seconds, but its template matching did
not fire reliably against a dynamically generated target.

So the scanner is a stdlib probe suite: deterministic, zero install, 0.4 seconds per run. The
finding schema and the CVSS mapping are what the report consumes, and a heavier scanner is a
configuration change.

## Not built yet

The Nosana distributed-worker path for the load test is specified but not wired up. The current
load generator runs in a single linked sandbox.

## Running it

```bash
# .env needs DAYTONA_API_KEY. The rest has defaults.
python orchestrator.py
```
