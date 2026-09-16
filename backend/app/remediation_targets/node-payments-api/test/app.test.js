'use strict';

// Functional contract tests. These assert the /merge endpoint's legitimate
// behaviour, which is identical on lodash 4.17.4 and 4.17.21 — so they pass
// both before and after the remediation. That is the point: they are the
// "no regression" evidence for the dependency bump. The vulnerability being
// present vs. absent is proven separately by the scanner, not by these tests.

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { createServer, BASE_CONFIG, runDiagnostic, renderGreeting } = require('../src/server');

function request(server, method, path, payload) {
  return new Promise((resolve, reject) => {
    const { port } = server.address();
    const data = payload === undefined ? undefined : JSON.stringify(payload);
    const req = http.request(
      { host: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json' } },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }));
      }
    );
    req.on('error', reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}

test('healthz returns ok', async () => {
  const server = createServer().listen(0);
  try {
    const res = await request(server, 'GET', '/healthz');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'ok');
  } finally {
    server.close();
  }
});

test('merge overlays caller overrides onto the base config', async () => {
  const server = createServer().listen(0);
  try {
    const res = await request(server, 'POST', '/merge', { retries: 5, features: { threeDS: true } });
    assert.strictEqual(res.status, 200);
    // Overrides applied...
    assert.strictEqual(res.body.config.retries, 5);
    assert.strictEqual(res.body.config.features.threeDS, true);
    // ...while untouched base values survive the deep merge.
    assert.strictEqual(res.body.config.currency, 'USD');
    assert.strictEqual(res.body.config.features.fraudCheck, true);
  } finally {
    server.close();
  }
});

test('base config is not mutated across requests', async () => {
  const server = createServer().listen(0);
  try {
    await request(server, 'POST', '/merge', { retries: 9 });
    assert.strictEqual(BASE_CONFIG.retries, 3);
  } finally {
    server.close();
  }
});

// Functional contract for the diagnostic path — identical output whether it uses
// the shell (`exec`) or the safe `execFile`, so it passes before and after the
// agentic fix. The command-injection vulnerability itself is proven present ->
// absent by the SAST scan + runtime exploit probe, not by this test.
test('runDiagnostic resolves a legitimate host', async () => {
  const out = await runDiagnostic('localhost');
  assert.strictEqual(out, 'resolving localhost');
});

// Functional contract for the greeting page — a legitimate name renders
// identically whether or not output encoding is applied (alphanumerics are not
// escaped), so this passes before and after the agentic DAST fix. The reflected
// XSS itself is proven present -> absent by the black-box HTTP probe, not here.
test('greeting renders a legitimate name', async () => {
  const server = createServer().listen(0);
  try {
    const res = await new Promise((resolve, reject) => {
      const { port } = server.address();
      http.get({ host: '127.0.0.1', port, path: '/greeting?name=Alice' }, (r) => {
        let body = '';
        r.on('data', (c) => { body += c; });
        r.on('end', () => resolve({ status: r.statusCode, body }));
      }).on('error', reject);
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.body, /Hello, Alice!/);
  } finally {
    server.close();
  }
});

test('renderGreeting is exported and includes the provided name', () => {
  assert.match(renderGreeting('Bob'), /Hello, Bob!/);
});
