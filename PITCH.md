# Demo script — 3 minutes

Read this on stage. The commands are at the bottom.

## Before you walk up

```bash
cd ~/Documents/hackbox-demo
.venv/bin/python orchestrator.py     # or the venv path if you use another
```

Run it once 5 minutes before, so the first cold sandbox pull is already paid for. Then run it
again when you present. Have `report.html` open in a tab as a fallback.

## The script

### 0:00 — Problem (25s)

Say this slowly. It is the only part you should not improvise.

"Security tools have a trust problem. You install a scanner on your own laptop, and it can see
your files, your SSH keys, your browser session. You point a load tester at your own server, and
if it has a bug you have taken down your own production. So people do not run these tests.

We built the opposite. Every phase runs on a machine that is created for that phase, does one job,
and is destroyed."

### 0:25 — What it is (20s)

"Hackbox runs a vulnerability scan and a load test in isolated Daytona sandboxes, enforces a
written authorization record before anything runs, and stops the load test automatically if the
target starts failing. One command, one report."

### 0:45 — Live (90s)

Start the run. Narrate the four phases as they appear.

- Phase 1. "A fresh sandbox is created and the target application starts inside it."
- Phase 2. "A second sandbox scans it. Two high findings, two medium. The XSS is real, you can see
  the payload reflected."
- Phase 3. "Now a third sandbox generates load. Watch the request rate climb. Watch the error rate
  start to climb with it."
- Point at the moment it crosses 15%. "That is the agreed stop condition from the authorization
  record. The kill switch just aborted the run."

### 2:15 — The part judges score (25s)

Say exactly this.

"Three things are worth noticing. The scanner and the load generators are linked child sandboxes
on the same internal network as the target, so the target is never exposed to the public internet.
The stop condition was not a preference, it came from the authorization record and the orchestrator
enforced it. And every entry in the audit log hashes the entry before it, so a run cannot be edited
after the fact."

### 2:40 — Close (20s)

"Everything you saw ran on machines that no longer exist. That is the whole point. You can run an
aggressive test against your own infrastructure without trusting the tool with your laptop or your
uptime."

## If it breaks

- If the run errors, say "let me show you the report from the run I did a moment ago" and open
  `report.html`. It is the same content.
- If a phase stalls, keep talking about the safeguard design while it finishes.
- Never debug silently on stage. Talk through what it is doing.

## Hard numbers you can quote

- 4 findings in under 1 second of scan time
- Load ramp from 900 to 4,000 requests per second
- Kill switch tripped automatically at the 15 percent error threshold
- Sandboxes created in about 2.6 seconds, destroyed immediately after

## If someone asks why not ZAP

Answer honestly: the default sandbox has no Docker and no Java, so the ZAP image is not usable and
a native install needs a JVM first. The checks are the part that matters, and they are mapped to
OWASP categories and CVSS scores. Swapping in a heavier scanner is a configuration change.

## If someone asks about Nosana

Answer honestly: the Nosana distributed-worker path is designed and specified but not wired up in
this build. It is the next phase. Do not claim it.
