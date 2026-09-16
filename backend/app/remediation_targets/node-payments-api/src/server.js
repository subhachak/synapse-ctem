'use strict';

// Minimal payments-config API for the CTEM live-remediation demo.
//
// It carries THREE intentional, independent vulnerabilities, each used by a
// different remediation strategy — one service, three exposure classes:
//
//   1. Dependency vuln (SCA) — pins lodash 4.17.4, whose `_.merge` in /merge is
//      the CVE-2019-10744 prototype-pollution sink. Fixed by the deterministic
//      dependency-bump strategy (bump to 4.17.21).
//   2. First-party code vuln (SAST) — runDiagnostic() in /diagnostics passes
//      untrusted input to a shell (`cp.exec`), i.e. OS command injection
//      (CWE-78). Fixed by the agentic code strategy (rewrite to `cp.execFile`).
//   3. Runtime web vuln (DAST) — renderGreeting() in /greeting reflects the
//      untrusted `name` query parameter into an HTML response without escaping,
//      i.e. reflected cross-site scripting (CWE-79). It is invisible to a pure
//      source signature but trivially found by a black-box HTTP probe; fixed by
//      the agentic code strategy (add output encoding).
//
// All three are behaviour-preserving to fix, so the functional test suite passes
// before and after; the scanners prove the vulnerabilities present -> absent.

const http = require('http');
const cp = require('child_process');
const _ = require('lodash');

const BASE_CONFIG = { currency: 'USD', retries: 3, features: { fraudCheck: true } };

function handleMerge(body, res) {
  let incoming;
  try {
    incoming = JSON.parse(body || '{}');
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid JSON' }));
    return;
  }
  const merged = _.merge({}, BASE_CONFIG, incoming);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ config: merged }));
}

// Resolve a host for an operator diagnostic. VULNERABLE (CWE-78): the untrusted
// `host` is concatenated into a shell command line.
function runDiagnostic(host) {
  return new Promise((resolve, reject) => {
    cp.exec('echo resolving ' + host, (err, stdout) => {
      if (err) return reject(err);
      resolve(String(stdout).trim());
    });
  });
}

// Render an operator greeting page. VULNERABLE (CWE-79, reflected XSS): the
// untrusted `name` is interpolated into the HTML response without escaping, so
// a payload like ?name=<script>...</script> is reflected and executed.
function renderGreeting(name) {
  return `<!doctype html><html><body><h1>Hello, ${name}!</h1></body></html>`;
}

function handleGreeting(reqUrl, res) {
  const params = new URL(reqUrl, 'http://localhost').searchParams;
  const name = params.get('name') || 'guest';
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(renderGreeting(name));
}

function handleDiagnostics(body, res) {
  let host;
  try {
    host = String(JSON.parse(body || '{}').host || 'localhost');
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid JSON' }));
    return;
  }
  runDiagnostic(host)
    .then((result) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result }));
    })
    .catch(() => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'diagnostic failed' }));
    });
}

function createServer() {
  return http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/merge') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => handleMerge(body, res));
      return;
    }
    if (req.method === 'POST' && req.url === '/diagnostics') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => handleDiagnostics(body, res));
      return;
    }
    if (req.method === 'GET' && (req.url === '/greeting' || req.url.startsWith('/greeting?'))) {
      handleGreeting(req.url, res);
      return;
    }
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });
}

module.exports = { createServer, BASE_CONFIG, runDiagnostic, renderGreeting };

if (require.main === module) {
  const port = process.env.PORT || 3200;
  createServer().listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`node-payments-api listening on :${port}`);
  });
}
