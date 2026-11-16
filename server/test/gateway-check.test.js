// Real mode: the shared gateway hop (POST /api/gateway-check) against a stub MCP gateway on loopback. Every trace built from it is source 'real',
// holds only observed or inferred decisions (never 'checked'), passes assertTrace, and holds no key text. The key is built at run time.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { assertTrace } from '../src/gatewayTrace.js';
import { post, get, withServer } from './helpers.js';

const KEY = ['fake', 'agent', 'key'].join('-') + 'Q'.repeat(24);

// A minimal Streamable-HTTP MCP door. tools/list answers 200 (its description echoes the key, to prove the scrub); tools/call is refused by policy (403).
function stubGateway({ listStatus = 200 } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = ''; req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      seen.push({ method: req.method, auth: req.headers.authorization });
      if (req.method !== 'POST') { res.writeHead(200).end(); return; }
      const m = JSON.parse(raw || '{}');
      const send = (status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(body)); };
      if (m.method === 'initialize') return send(200, { jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'stub-door', version: '1' } } }, { 'mcp-session-id': 'sess-1234567890abcdef' });
      if (m.method === 'notifications/initialized') { res.writeHead(202).end(); return; }
      if (m.method === 'tools/list') {
        if (listStatus !== 200) return send(listStatus, { error: 'refused' });
        return send(200, { jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'lookup', description: `echoes ${KEY}` }, { name: 'search', description: 'search' }] } });
      }
      if (m.method === 'tools/call') return send(403, { error: 'refused by policy' });
      return send(404, {});
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, origin: `http://127.0.0.1:${server.address().port}` })));
}

async function withEnv(vars, fn) {
  const old = {};
  for (const [k, v] of Object.entries(vars)) { old[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally { for (const [k, v] of Object.entries(old)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
const noFile = { STANDALONE_ENV: '/nonexistent/standalone.env' };

test('Real with no gateway settings: 409 with a message, nothing is called', async () => {
  await withEnv({ ...noFile, FID_GW_URL: undefined, FID_GW_APPS: undefined, FID_GW_KEY_LAB: undefined }, () => withServer(async (url) => {
    await post(url, '/api/mode', { source: 'real' });
    const r = await post(url, '/api/gateway-check', {});
    assert.equal(r.status, 409);
    const b = await r.json();
    assert.equal(b.error, 'real_not_available');
    assert.match(b.message, /FID_GW_URL/);
  }));
});

test('Mock never calls the gateway: the check is refused 409 and the stub sees no request', async () => {
  const gw = await stubGateway();
  try {
    await withEnv({ ...noFile, FID_GW_URL: gw.origin, FID_GW_APPS: 'door-a', FID_GW_KEY_LAB: KEY }, () => withServer(async (url) => {
      await post(url, '/api/mode', { source: 'mock' });
      const r = await post(url, '/api/gateway-check', {});
      assert.equal(r.status, 409);
      assert.equal((await r.json()).error, 'mock_mode');
      assert.equal(gw.seen.length, 0);
    }));
  } finally { await new Promise((res) => gw.server.close(res)); }
});

test('Real: the check returns a real trace for tools/list and for the refusal probe, never "checked", assertTrace clean, no key anywhere', async () => {
  const gw = await stubGateway();
  try {
    await withEnv({ ...noFile, FID_GW_URL: gw.origin, FID_GW_APPS: 'door-a', FID_GW_KEY_LAB: KEY }, () => withServer(async (url) => {
      await post(url, '/api/mode', { source: 'real' });
      const r = await post(url, '/api/gateway-check', {});
      assert.equal(r.status, 200);
      const text = await r.text();
      assert.ok(!text.includes(KEY), 'the agent key is nowhere in the answer');
      const b = JSON.parse(text);
      assert.equal(b.listing.ok, true);
      assert.equal(b.listing.wire, undefined, 'the raw capture is not sent beside the trace');
      assert.equal(b.refusal.ok, false);
      assert.equal(b.refusal.refusal.status, 403);
      for (const [name, rpcMethod] of [['listing', 'tools/list'], ['refusal', 'tools/call']]) {
        const t = b.trace[name];
        assert.deepEqual(assertTrace(t), [], `${name} trace honours the contract`);
        assert.equal(t.source, 'real');
        assert.equal(t.request.body.method, rpcMethod);
        assert.equal(t.request.url, `${gw.origin}/door-a/mcp`);
        assert.ok(t.decisions.length > 0 && t.decisions.every((d) => d.basis === 'observed' || d.basis === 'inferred'), 'a real decision is never "checked"');
        assert.match(t.request.headers.authorization || t.request.headers.Authorization, /^Bearer <agent key, \d+ characters, kept on the server>$/);
      }
      assert.equal(b.trace.listing.response.status, 200);
      assert.equal(b.trace.refusal.response.status, 403);
      assert.deepEqual(b.trace.refusal.decisions.map((d) => [d.id, d.outcome]), [['authenticated', 'pass'], ['grant', 'fail']]);
      assert.ok(gw.seen.every((s) => s.method === 'DELETE' || s.auth === `Bearer ${KEY}`), 'the key reached the gateway itself');
    }));
  } finally { await new Promise((res) => gw.server.close(res)); }
});

test('Real: a gateway that refuses tools/list gives one real trace (401 is fail/inferred, the grant not reached) and no refusal probe', async () => {
  const gw = await stubGateway({ listStatus: 401 });
  try {
    await withEnv({ ...noFile, FID_GW_URL: gw.origin, FID_GW_APPS: 'door-a', FID_GW_KEY_LAB: KEY }, () => withServer(async (url) => {
      await post(url, '/api/mode', { source: 'real' });
      const b = await (await post(url, '/api/gateway-check', {})).json();
      assert.equal(b.listing.ok, false);
      assert.equal(b.refusal, undefined);
      assert.equal(b.trace.refusal, undefined);
      const t = b.trace.listing;
      assert.deepEqual(assertTrace(t), []);
      assert.deepEqual(t.decisions.map((d) => [d.id, d.outcome, d.basis]), [['authenticated', 'fail', 'inferred'], ['grant', 'skipped', 'inferred']]);
      assert.ok(!JSON.stringify(b).includes(KEY));
    }));
  } finally { await new Promise((res) => gw.server.close(res)); }
});

test('the check takes only { app, caller } and only a configured door', async () => {
  const gw = await stubGateway();
  try {
    await withEnv({ ...noFile, FID_GW_URL: gw.origin, FID_GW_APPS: 'door-a', FID_GW_KEY_LAB: KEY }, () => withServer(async (url) => {
      await post(url, '/api/mode', { source: 'real' });
      assert.equal((await post(url, '/api/gateway-check', { url: 'https://other.invalid' })).status, 400);
      assert.equal((await post(url, '/api/gateway-check', { app: 'door-z' })).status, 400);
      assert.equal(gw.seen.length, 0);
      assert.equal((await get(url, '/api/gateway-check')).status === 200, false, 'a GET is not an action');
    }));
  } finally { await new Promise((res) => gw.server.close(res)); }
});
