import test from 'node:test';
import assert from 'node:assert/strict';
import { C, GW, K8S_SUB, api, get, json, live, post, put, rawHttp, withServer, W } from './helpers.js';
import { installNetguard } from '../src/netguard.js';
import { mockState } from '../src/service.js';
import { MOCK_TABLE } from '../src/mockTable.js';

const guard = installNetguard();
const mint = (url, ws, body = {}) => api(url, 'POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW }, ...body } }, ws);

test('health, info and story answer; the story fills every token for every vertical and names the slides', async () => {
  await withServer(async (url) => {
    const h = await json(await get(url, '/api/health'));
    assert.equal(h.schema, 'demo-health/1'); assert.equal(h.demo.id, 'federated-identity-lab');
    const info = await json(await get(url, '/api/info'));
    assert.deepEqual([info.simulated, info.unverified, info.release], [true, true, '2026-11-02']);
    for (const v of ['finance', 'health', 'retail']) {
      const s = await json(await get(url, `/api/story?vertical=${v}`));
      assert.ok(!/\{\{/.test(JSON.stringify(s)), v);
      assert.equal(s.vertical, v); assert.equal(s.steps.length, 15); assert.equal(s.deploymentModels.length, 5); assert.equal(s.presets.length, 27);
    }
    assert.equal((await json(await get(url, '/api/story?vertical=__proto__'))).vertical, 'finance');
  });
});

test('the state: Mock gives a generated scenario, Live gives the workspace engine, both the same shape', async () => {
  await withServer(async (url) => {
    const m = await json(await get(url, '/api/state?mode=mock&vertical=finance&scenario=fork-pr'));
    const l = await json(await get(url, '/api/state?mode=live&vertical=finance'));
    assert.equal(m.scenario.id, 'fork-pr'); assert.equal(m.scenarios.length, 13);
    assert.deepEqual(Object.keys(m.state).sort(), Object.keys(l.state).sort(), 'one shape for both');
    assert.equal(l.state.identities.length, 5);
    assert.equal((await json(await get(url, '/api/state?mode=mock&scenario=nope'))).scenario.id, 'one-credential');
    assert.equal((await get(url, '/api/state?mode=prod')).status, 400);
    assert.equal((await get(url, '/api/state')).status, 400);
    assert.equal((await get(url, '/api/state?mode=live', W('Bad Id'))).status, 400);
    assert.equal((await get(url, '/api/state?mode=live', W('deadbeef'.repeat(4)))).status, 400, 'a hex-looking workspace id is refused, not echoed');
    assert.equal(mockState(MOCK_TABLE, 'finance', 'sensor').scenario.id, 'sensor');
  });
});

const WRITES = [
  ['post', '/api/tokens/mint', { mint: {} }], ['post', '/api/verify', { verify: {} }], ['post', '/api/clock', { clock: {} }], ['post', '/api/issuers/kube/actions', { action: {} }], ['post', '/api/identities', { identity: {} }],
  ['put', '/api/identities/fid-001', { identity: {} }], ['post', '/api/identities/fid-001/remove', { remove: {} }], ['post', '/api/identities/fid-001/refresh', { refresh: {} }], ['post', '/api/keys', { key: {} }],
  ['put', '/api/keys/key-0001', { key: {} }], ['post', '/api/keys/key-0001/remove', { remove: {} }], ['post', '/api/keys/key-0006/stored-call', { call: {} }], ['put', `/api/people/${C.castOwner}`, { person: {} }],
  ['post', '/api/sensors', { sensor: {} }], ['post', '/api/sensors/fid-006/reports', { report: {} }], ['put', '/api/sensors/fid-006/policy', { policy: {} }],
];

test('Mock is read-only: every write is refused with 409 and changes nothing', async () => {
  await withServer(async (url) => {
    for (const [m, p, b] of WRITES) { const r = await (m === 'put' ? put : post)(url, p, { mode: 'mock', vertical: 'finance', ...b }); assert.equal(r.status, 409, p); assert.equal((await r.json()).error, 'mock_is_read_only'); }
    const l = await json(await get(url, '/api/state?mode=live'));
    assert.deepEqual([l.state.audit.length, l.state.findings.length, l.state.clock.advancedMin], [1, 0, 0]);
  });
});

test('writes need a mode, an object body and only known top-level keys; the refusal never names the field', async () => {
  await withServer(async (url) => {
    assert.equal((await post(url, '/api/clock', { vertical: 'finance' })).status, 400);
    assert.equal((await post(url, '/api/clock', { mode: 'prod' })).status, 400);
    const r = await post(url, '/api/clock', live({ clock: { minutes: 1 }, oops: 1 })); assert.equal(r.status, 400); assert.ok(!(await r.text()).includes('oops'));
    assert.equal((await post(url, '/api/clock', [1])).status, 400);
    assert.equal((await rawHttp(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: '{bad json' })).status, 400);
    assert.equal((await rawHttp(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: JSON.stringify({ mode: 'live', pad: 'x'.repeat(40000) }) })).status, 413);
  });
});

test('a verify over HTTP: 200 allowed with the steps and the masked backend credential; refusals keep honest statuses (401, 403, 404, 400) and carry the step list', async () => {
  await withServer(async (url) => {
    const m = await mint(url, 'a1');
    assert.equal(m.status, 200); assert.match(m.body.result.mintedToken, /^eyJ/);
    const token = m.body.result.mintedToken;
    const ok = await api(url, 'POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'mcp' } }, 'a1');
    assert.equal(ok.status, 200); assert.equal(ok.body.ok, true); assert.equal(ok.body.result.steps.length, 15);
    assert.match(ok.body.result.forwarded.request.headers.authorization, /^\[masked: /);
    assert.ok(!JSON.stringify(ok.body).includes(token), 'the token is not echoed by the verify answer');
    assert.ok(ok.body.hops.length >= 3 && ok.body.hops.every((h) => /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/.test(h.request.headers.traceparent)), 'a W3C traceparent on every hop');
    const llm = await api(url, 'POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'llm' } }, 'a1');
    assert.equal(llm.status, 403); assert.equal(llm.body.error, 'scope_not_on_key'); assert.equal(llm.body.result.steps.at(-1).status, 'fail');
    const bad = await api(url, 'POST', '/api/verify', { verify: { token: `${token}x`, identityId: 'fid-001', service: 'mcp' } }, 'a1');
    assert.equal(bad.status, 401); assert.equal(bad.body.error, 'bad_signature');
    assert.equal((await api(url, 'POST', '/api/verify', { verify: { token, identityId: 'nope', service: 'mcp' } }, 'a1')).status, 404);
    assert.equal((await api(url, 'POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'xx' } }, 'a1')).status, 400);
    assert.equal((await api(url, 'POST', '/api/verify', { verify: { token: 5, service: 'mcp' } }, 'a1')).status, 400);
    assert.equal(ok.body.state.audit.filter((a) => a.kind === 'verify').length, 1);
  });
});

test('revocation over HTTP: the very next request is refused', async () => {
  await withServer(async (url) => {
    const token = (await mint(url, 'r1')).body.result.mintedToken;
    const v = () => api(url, 'POST', '/api/verify', { verify: { token, service: 'mcp' } }, 'r1');
    assert.equal((await v()).status, 200);
    assert.equal((await api(url, 'PUT', '/api/identities/fid-001', { identity: { enabled: false } }, 'r1')).status, 200);
    const r = await v(); assert.equal(r.status, 401); assert.equal(r.body.error, 'identity_disabled');
  });
});

test('the unauthenticated lookup, the sensor flow and the policy over HTTP', async () => {
  await withServer(async (url) => {
    const e = await api(url, 'POST', '/api/sensors', { sensor: { name: 's' } }, 's1'); assert.equal(e.status, 200);
    const id = e.body.result.identityId;
    const pol = await api(url, 'PUT', `/api/sensors/${id}/policy`, { policy: { mode: 'audit', scope: { namespaces: [C.castNs] }, actions: { 'ai-agent': 'allow', 'mcp-server': 'warn', 'model-server': 'deny' } } }, 's1'); assert.equal(pol.status, 200);
    const rep = await api(url, 'POST', `/api/sensors/${id}/reports`, { report: { node: C.castNode1, body: { node: C.castNode3, findings: [{ kind: 'model-server', name: 'vllm', namespace: C.castNs, pod: 'p-0' }] } } }, 's1');
    assert.equal(rep.status, 200); assert.equal(rep.body.result.report.node, C.castNode1); assert.equal(rep.body.result.findings[0].effect, 'would-have-blocked');
    const aud = await api(url, 'POST', `/api/sensors/${id}/reports`, { report: { node: C.castNode1, tokenFrom: 'gateway-audience', body: { findings: [{ kind: 'ai-agent', name: 'a', namespace: C.castNs, pod: 'p-0' }] } } }, 's1');
    assert.equal(aud.status, 401); assert.equal(aud.body.error, 'aud_mismatch');
    assert.equal((await api(url, 'POST', '/api/sensors/fid-001/reports', { report: { node: C.castNode1, body: { findings: [] } } }, 's1')).status, 404);
  });
});

test('Reset clears this workspace only', async () => {
  await withServer(async (url) => {
    await api(url, 'POST', '/api/clock', { clock: { minutes: 5 } }, 'x1'); await api(url, 'POST', '/api/clock', { clock: { minutes: 7 } }, 'x2');
    assert.equal((await post(url, '/api/reset', {}, W('x1'))).status, 200);
    const c = async (ws) => (await json(await get(url, '/api/state?mode=live', W(ws)))).state.clock.advancedMin;
    assert.deepEqual([await c('x1'), await c('x2')], [0, 7]);
  });
});

test('failures are short JSON, never a stack trace or the path: unknown routes, bad JSON, wrong methods, hostile paths', async () => {
  await withServer(async (url) => {
    for (const p of ['/api/nope', '/api/../etc/passwd', '/nope/x', '/api/identities/%00', '/api/identities/<script>']) {
      const r = await rawHttp(`${url}${p}`); assert.ok([200, 400, 404].includes(r.status), `${p}: ${r.status}`);
      assert.ok(!/Cannot (GET|POST)|at .*\.js|<pre>|node_modules/.test(r.text), p);
    }
    const r = await rawHttp(`${url}/api/zzz-not-here`, { method: 'POST', headers: { origin: url } }); assert.ok(!/zzz-not-here/.test(r.text));
    assert.equal((await rawHttp(`${url}/api/health`, { method: 'POST', headers: { origin: url } })).status, 405);
    assert.equal((await rawHttp(`${url}/api/state?mode=live`, { headers: { host: 'evil.example.invalid' } })).status, 403);
    assert.equal((await post(url, '/api/clock', live({ clock: { minutes: 1 } }), { origin: 'http://evil.example.invalid' })).status, 403);
  });
});

test('parallel identical writes are serialised: one wins, the others are refused (no double create, no cap overrun)', async () => {
  await withServer(async (url) => {
    const mk = () => api(url, 'POST', '/api/sensors', { sensor: {} }, 'par1');
    const rs = await Promise.all(Array.from({ length: 9 }, mk));
    assert.equal(rs.filter((r) => r.status === 200).length, 5); assert.equal(rs.filter((r) => r.status === 409).length, 4);
    const s = (await json(await get(url, '/api/state?mode=live', W('par1')))).state;
    assert.equal(s.sensors.length, 5); assert.equal(new Set(s.identities.map((i) => i.id)).size, s.identities.length);
    const rev = await Promise.all([1, 2, 3].map(() => api(url, 'PUT', '/api/identities/fid-001', { identity: { enabled: false } }, 'par1')));
    assert.ok(rev.every((r) => r.status === 200));
    const dup = await Promise.all([1, 2, 3].map(() => api(url, 'POST', '/api/identities/fid-002/remove', { remove: {} }, 'par1')));
    assert.deepEqual(dup.map((r) => r.status).sort(), [200, 404, 404]);
  });
});

test('a workspace is refused at the cap rather than evicting another', async () => {
  const { createWorkspaces } = await import('../src/workspaces.js');
  await withServer(async (url) => {
    assert.equal((await get(url, '/api/state?mode=live', W('ws-a'))).status, 200);
    await api(url, 'POST', '/api/clock', { clock: { minutes: 1 } }, 'ws-a');
    assert.equal((await api(url, 'POST', '/api/clock', { clock: { minutes: 1 } }, 'ws-b')).status, 200);
    const refused = await api(url, 'POST', '/api/clock', { clock: { minutes: 1 } }, 'ws-c');
    assert.equal(refused.status, 503); assert.equal(refused.body.error, 'workspaces_full');
    assert.equal((await json(await get(url, '/api/state?mode=live', W('ws-a')))).state.clock.advancedMin, 1, 'the first workspace was not evicted');
  }, { workspaces: createWorkspaces({ max: 2 }) });
});

test('zero outbound network attempts were made while the whole API ran (netguard)', () => {
  assert.deepEqual(guard.attempts, []);
});

test('the issuer key set endpoint (for the in-browser check): public RSA halves only, intact under the response mask, Live only, 404 without echoing, 503 when the issuer is down, and it follows a rotation', async () => {
  const crypto = await import('node:crypto');
  await withServer(async (url) => {
    const g = async (id, mode = 'live', ws = 'jw1') => { const r = await get(url, `/api/issuers/${id}/jwks?mode=${mode}&vertical=finance`, W(ws)); return { status: r.status, text: await r.text() }; };
    const a = await g('kube'); assert.equal(a.status, 200);
    const j = JSON.parse(a.text); assert.equal(j.issuer, 'kube'); assert.deepEqual(j.keys.map((k) => k.kid), ['kube-key-1']);
    for (const k of j.keys) { assert.deepEqual(Object.keys(k).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']); assert.ok(crypto.createPublicKey({ key: { kty: k.kty, n: k.n, e: k.e }, format: 'jwk' }), 'a usable public key'); }
    assert.ok(!/"d":|"p":|"q":|"dp"|"dq"|"qi"|PRIVATE/.test(a.text), 'no private material');
    assert.equal((await g('kube', 'mock')).status, 409); assert.equal(JSON.parse((await g('kube', 'mock')).text).error, 'live_only');
    const bad = await g('AKIAIOSFODNN7EXAMPLE'); assert.equal(bad.status, 404); assert.ok(!bad.text.includes('AKIA'));
    assert.equal((await g('__proto__')).status, 404); assert.equal((await g('attacker')).status, 404);
    await api(url, 'POST', '/api/issuers/kube/actions', { action: { action: 'rotate' } }, 'jw1');
    assert.deepEqual(JSON.parse((await g('kube')).text).keys.map((k) => k.kid), ['kube-key-2'], 'the published set follows the rotation');
    assert.deepEqual(JSON.parse((await g('kube', 'live', 'jw2')).text).keys.map((k) => k.kid), ['kube-key-1'], 'another workspace is untouched');
    await api(url, 'POST', '/api/issuers/kube/actions', { action: { action: 'down' } }, 'jw1');
    const down = await g('kube'); assert.equal(down.status, 503); assert.equal(JSON.parse(down.text).error, 'issuer_down');
    assert.equal((await g('private')).status, 200, 'the private issuer still publishes (it is a different issuer)');
  });
});

test('only UTF-8 request bodies are read: any other declared charset is 415 before a parser can decode it', async () => {
  await withServer(async (url) => {
    const send = (ct, body) => rawHttp(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': ct, origin: url }, body });
    const ok = JSON.stringify({ mode: 'live', vertical: 'finance', clock: { minutes: 1 } });
    for (const cs of ['utf-16', 'utf-16le', 'iso-8859-1', 'latin1', 'windows-1252', 'utf-7', 'shift_jis', 'ascii', '"utf-32"']) assert.equal((await send(`application/json; charset=${cs}`, ok)).status, 415, cs);
    for (const cs of ['utf-8', 'UTF-8', '"utf-8"']) assert.equal((await send(`application/json; charset=${cs}`, ok)).status, 200, cs);
    assert.equal((await send('application/json', ok)).status, 200);
    const r = await send('application/json; charset=utf-16', ok); assert.ok(!/utf-16/.test(r.text), 'the charset is not echoed');
  });
});
