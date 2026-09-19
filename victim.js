// Hackbox demo victim app. Node stdlib only, so it starts instantly with no install.
// Planted bugs, deliberately:
//   1. reflected XSS on /search  (unescaped query echoed into HTML)
//   2. naive SQL string concatenation on /user
//   3. no rate limiting anywhere, so a load test visibly degrades it
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
// Deliberately fixed capacity, standing in for an app with no autoscaling and no queue.
// Above this request rate it sheds load with 503. This is what gives the orchestrator's
// kill switch something real to detect, instead of a target that absorbs infinite traffic.
const MAX_RPS = Number(process.env.MAX_RPS || 6000);
const recent = [];
let served = 0;
let inFlight = 0;

const server = http.createServer((req, res) => {
  inFlight += 1;
  const release = () => { inFlight -= 1; };

  // Health checks bypass the pool so the orchestrator can always probe the target.
  if (req.url.startsWith('/health')) {
    release();
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }

  const now = Date.now();
  while (recent.length && now - recent[0] > 1000) recent.shift();
  // Soft ceiling: above capacity, shed a growing fraction instead of refusing everything.
  // Real overload looks like this, and it gives a visible degradation curve rather than a cliff.
  if (recent.length > MAX_RPS) {
    const shedProbability = 1 - (MAX_RPS / recent.length);
    if (Math.random() < shedProbability) {
      release();
      res.writeHead(503, { 'Content-Type': 'text/plain', 'Retry-After': '1' });
      return res.end('503 service unavailable: capacity exceeded');
    }
  }
  recent.push(now);

  served += 1;
  const u = new URL(req.url, 'http://localhost');

  if (u.pathname === '/stats') {
    release();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ served, in_flight: inFlight, max_rps: MAX_RPS,
      recent_rps: recent.length }));
  }

  if (u.pathname === '/search') {
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    release();
    // BUG 1: reflected without escaping
    return res.end(`<html><body><h1>Search</h1><p>Results for: ${q}</p></body></html>`);
  }

  if (u.pathname === '/user') {
    const id = u.searchParams.get('id') || '1';
    // BUG 2: naive concatenation, shown in the response so the finding is verifiable
    const query = `SELECT * FROM users WHERE id = ${id}`;
    release();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ query, note: 'simulated, no real database' }));
  }

  release();
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>Hackbox demo target</h1>'
    + '<p><a href="/search?q=hello">search</a> | <a href="/user?id=1">user</a></p>'
    + '</body></html>');
});

// BUG 3: no rate limiting, no connection cap
server.listen(PORT, '0.0.0.0', () => console.log(`victim listening on ${PORT}`));
