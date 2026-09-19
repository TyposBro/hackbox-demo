// Hackbox load generator. Runs INSIDE a Daytona sandbox, pointed at the authorized target.
// Node stdlib only. Ramps concurrency, exposes live stats on :3001, and stops on command so the
// orchestrator's kill switch has something real to pull.
//
//   node loadgen.js <target-url> <max-concurrency> <ramp-seconds> <max-duration-seconds> <delay-ms>
// delay-ms paces each worker so the offered rate climbs smoothly instead of saturating
// the target in the first second, which is what makes the degradation visible.
const http = require('http');

const TARGET = (process.argv[2] || '').replace(/\/$/, '');
const MAX_CONCURRENCY = Number(process.argv[3] || 20);
const RAMP_SECONDS = Number(process.argv[4] || 8);
const MAX_DURATION = Number(process.argv[5] || 90);
const DELAY_MS = Number(process.argv[6] || 5);
const STATS_PORT = 3001;

if (!TARGET) {
  console.error('usage: node loadgen.js <target-url> [max-concurrency] [ramp-s] [max-duration-s]');
  process.exit(2);
}

let sent = 0;
let ok = 0;
let failed = 0;
let inFlight = 0;
let peakConcurrency = 0;
let stopped = false;
let stopReason = null;
const latencies = [];
const startedAt = Date.now();
const marks = [];   // {at, sent} samples, used for a windowed rps instead of a lifetime average

function oneRequest() {
  return new Promise((resolve) => {
    const t0 = Date.now();
    inFlight += 1;
    if (inFlight > peakConcurrency) peakConcurrency = inFlight;

    const req = http.get(TARGET + '/', (res) => {
      res.resume();
      res.on('end', () => {
        latencies.push(Date.now() - t0);
        sent += 1;
        if (res.statusCode < 500) ok += 1; else failed += 1;
        inFlight -= 1;
        resolve();
      });
    });

    req.setTimeout(5000, () => req.destroy());
    req.on('error', () => {
      latencies.push(Date.now() - t0);
      sent += 1;
      failed += 1;
      inFlight -= 1;
      resolve();
    });
  });
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

function stats() {
  const now = Date.now();
  const elapsed = (now - startedAt) / 1000;
  const recent = latencies.slice(-500);

  marks.push({ at: now, sent });
  while (marks.length > 1 && now - marks[0].at > 2000) marks.shift();
  const oldest = marks[0];
  const windowSeconds = (now - oldest.at) / 1000;
  const windowRps = windowSeconds > 0 ? (sent - oldest.sent) / windowSeconds : 0;
  return {
    sent,
    ok,
    failed,
    error_rate: sent ? failed / sent : 0,
    rps: Math.round(windowRps * 10) / 10,
    avg_rps: elapsed > 0 ? Math.round((sent / elapsed) * 10) / 10 : 0,
    p50_ms: percentile(recent, 0.5),
    p95_ms: percentile(recent, 0.95),
    in_flight: inFlight,
    peak_concurrency: peakConcurrency,
    elapsed_s: Math.round(elapsed * 10) / 10,
    stopped,
    stop_reason: stopReason,
  };
}

http.createServer((req, res) => {
  if (req.url === '/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(stats()));
  }
  if (req.url === '/stop') {
    stopped = true;
    stopReason = 'kill switch pulled by orchestrator';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ stopped: true }));
  }
  res.writeHead(404);
  res.end();
}).listen(STATS_PORT, '0.0.0.0', () => console.log(`loadgen stats on ${STATS_PORT}`));

// Ramp concurrency up in steps, then hold. Hard stop at MAX_DURATION regardless.
let concurrency = 0;
const stepMs = (RAMP_SECONDS * 1000) / Math.max(MAX_CONCURRENCY, 1);
const ramp = setInterval(() => {
  if (concurrency >= MAX_CONCURRENCY) return clearInterval(ramp);
  concurrency += 1;
  (async () => {
    while (!stopped) {
      await oneRequest();
      if (DELAY_MS > 0) await new Promise((r) => setTimeout(r, DELAY_MS));
    }
  })();
}, stepMs);

setTimeout(() => {
  stopped = true;
  stopReason = stopReason || 'max duration reached';
}, MAX_DURATION * 1000);

console.log(`loadgen -> ${TARGET} max ${MAX_CONCURRENCY} over ${RAMP_SECONDS}s ramp`);
