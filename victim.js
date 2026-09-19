// Hackbox demo victim app. Node stdlib only, so it starts instantly with no install.
// Planted bugs, deliberately:
//   1. reflected XSS on /search  (unescaped query echoed into HTML)
//   2. naive SQL string concatenation on /user
//   3. no rate limiting anywhere, so a load test visibly degrades it
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
let served = 0;

const server = http.createServer((req, res) => {
  served += 1;
  const u = new URL(req.url, 'http://localhost');

  if (u.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }

  if (u.pathname === '/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ served }));
  }

  if (u.pathname === '/search') {
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    // BUG 1: reflected without escaping
    return res.end(`<html><body><h1>Search</h1><p>Results for: ${q}</p></body></html>`);
  }

  if (u.pathname === '/user') {
    const id = u.searchParams.get('id') || '1';
    // BUG 2: naive concatenation, shown in the response so the finding is verifiable
    const query = `SELECT * FROM users WHERE id = ${id}`;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ query, note: 'simulated, no real database' }));
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>Hackbox demo target</h1>'
    + '<p><a href="/search?q=hello">search</a> | <a href="/user?id=1">user</a></p>'
    + '</body></html>');
});

// BUG 3: no rate limiting, no connection cap
server.listen(PORT, '0.0.0.0', () => console.log(`victim listening on ${PORT}`));
