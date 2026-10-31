// Review patterns that broke sibling labs: a refused request must change nothing (caps are checked BEFORE any mutation), parsers are bounded while they expand,
// and audit summaries never store a raw value.
import test from 'node:test';
import assert from 'node:assert/strict';
import { b64u } from '../src/jwt.js';
import { LIMITS } from '../src/engine.js';
import { maskResponseText } from '../src/mask.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { SECRETS } from './masking.test.js';
import { C, GW, K8S_SUB, codeOf, k8sMint, newEngine } from './helpers.js';

const URI = 'https://kube-api.cluster-a.example/openid/v1/jwks';
const ident = (over = {}) => ({ name: 'x', scopes: ['mcp'], platform: 'kubernetes', ...over, federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW, ...(over.federation || {}) } });
const frozen = (e, fn) => { const before = JSON.stringify(e.snapshot()); const code = codeOf(fn); assert.ok(code, 'the request was refused'); assert.equal(JSON.stringify(e.snapshot()), before, `a refused request (${code}) changed the state`); return code; };

test('a refused request changes nothing: a long list of bad requests of every operation leaves the whole state byte-identical', () => {
  const e = newEngine();
  const bad = [
    () => e.createIdentity(ident({ name: 5 })), () => e.createIdentity(ident({ scopes: [] })), () => e.createIdentity(ident({ federation: { audience: '' } })), () => e.createIdentity(ident({ surprise: 1 })),
    () => e.updateIdentity({ identityId: 'fid-001', scopes: ['x'] }), () => e.updateIdentity({ identityId: 'nope' }), () => e.updateIdentity({ identityId: 'fid-001', federation: { maxTokenLifetimeSec: -5 } }),
    () => e.deleteIdentity({ identityId: 'nope' }), () => e.createKey({ name: 'k', owner: { kind: 'identity', ref: 'nope' }, scopes: ['mcp'] }), () => e.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], ownFederation: true }),
    () => e.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['shadowai:write'] }), () => e.updateKey({ keyId: 'key-0001', scopes: ['bogus'] }), () => e.deleteKey({ keyId: 'nope' }),
    () => e.setPerson({ person: 'nobody', active: false }), () => e.setPerson({ person: C.castOwner, active: 'x' }), () => e.advance({ minutes: 0 }), () => e.advance({ minutes: 100000 }),
    () => e.issuerAction({ issuer: 'nope', action: 'down' }), () => e.issuerAction({ issuer: 'kube', action: 'x' }), () => e.refreshKeys({ identityId: 'fid-005' }), () => e.refreshKeys({ identityId: 'nope' }),
    () => e.enrollSensor({ name: 5 }), () => e.setPolicy({ identityId: 'fid-001', mode: 'audit', scope: { all: true }, actions: {} }), () => e.sensorReport({ identityId: 'fid-001', node: C.castNode1, body: { findings: [] } }),
    () => e.mint({ issuer: 'nope' }), () => e.storedKeyCall({ keyId: 'nope', service: 'mcp' }), () => e.verify({ token: 5, service: 'mcp' }),
  ];
  for (const f of bad) frozen(e, f);
});

test('at every cap the whole request is refused and nothing was half-done: no identity without its key, no key, no sequence number consumed', () => {
  const e = newEngine();
  // identities at the cap: a sensor enrolment must not create a key (or anything) first
  while (e.snapshot().identities.length < LIMITS.identities) e.createIdentity(ident());
  assert.equal(frozen(e, () => e.enrollSensor({})), 'workspace_full');
  assert.equal(frozen(e, () => e.createIdentity(ident())), 'workspace_full');
  // keys at the cap, identities not: no identity is left behind without its key
  const f = newEngine();
  while (f.snapshot().keys.length < LIMITS.keys) f.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-002' }, scopes: ['mcp'] });
  assert.equal(frozen(f, () => f.enrollSensor({})), 'workspace_full');
  assert.equal(frozen(f, () => f.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-002' }, scopes: ['mcp'] })), 'workspace_full');
  // sensors at the cap
  const g = newEngine(); for (let i = 0; i < LIMITS.sensors; i++) g.enrollSensor({});
  assert.equal(frozen(g, () => g.enrollSensor({})), 'workspace_full');
  // findings at the cap: a report that would overrun is refused whole, not sliced
  const h = newEngine(); const id = h.enrollSensor({}).identityId;
  const ten = Array.from({ length: 10 }, () => ({ kind: 'ai-agent', name: 'a', namespace: C.castNs, pod: 'p-0' }));
  for (let i = 0; i < 20; i++) h.sensorReport({ identityId: id, node: C.castNode1, body: { findings: ten } });
  assert.equal(frozen(h, () => h.sensorReport({ identityId: id, node: C.castNode1, body: { findings: [ten[0]] } })), 'workspace_full');
  // the clock total
  const k = newEngine(); while (k.snapshot().clock.advancedMin + 180 <= LIMITS.clockTotalMin) k.advance({ minutes: 180 });
  assert.equal(frozen(k, () => k.advance({ minutes: 180 })), 'clock_limit');
  // rotation limit
  const r = newEngine(); for (let i = 0; i < 5; i++) r.issuerAction({ issuer: 'kube', action: 'rotate' });
  assert.equal(frozen(r, () => r.issuerAction({ issuer: 'kube', action: 'rotate' })), 'rotation_limit');
  // an enrolment while the Kubernetes issuer is down (its key set cannot be validated) leaves nothing behind
  const d = newEngine(); d.issuerAction({ issuer: 'kube', action: 'down' });
  assert.equal(frozen(d, () => d.enrollSensor({})), 'jwks_unreachable');
  d.issuerAction({ issuer: 'kube', action: 'up' });
  assert.equal(d.enrollSensor({}).identityId, 'fid-006', 'the failed enrolment consumed no identity number');
});

test('user-fed structures are bounded while they expand: huge lists and objects are refused by their size before any element is walked', () => {
  const e = newEngine(); const t0 = Date.now();
  const pub = e.publishedJwks('private')[0];
  assert.equal(codeOf(() => e.createIdentity(ident({ federation: { jwks: Array.from({ length: 50000 }, (_, i) => ({ ...pub, kid: `k${i}` })) } }))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(ident({ federation: { requiredClaims: Object.fromEntries(Array.from({ length: 30000 }, (_, i) => [`c${i}`, 'v'])) } }))), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { extra: Object.fromEntries(Array.from({ length: 30000 }, (_, i) => [`c${i}`, 'v'])) } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { aud: Array.from({ length: 30000 }, () => 'x') } })), 'bad_claims');
  assert.equal(codeOf(() => e.createIdentity(ident({ scopes: Array.from({ length: 30000 }, () => 'mcp') }))), 'bad_scopes');
  assert.equal(codeOf(() => e.setPolicy({ identityId: 'fid-001', mode: 'audit', scope: { namespaces: Array.from({ length: 30000 }, (_, i) => `n${i}`) }, actions: {} })), 'unknown_sensor');
  const s = e.enrollSensor({}).identityId;
  assert.equal(codeOf(() => e.setPolicy({ identityId: s, mode: 'audit', scope: { namespaces: Array.from({ length: 30000 }, (_, i) => `n${i}`) }, actions: { 'ai-agent': 'allow', 'mcp-server': 'allow', 'model-server': 'allow' } })), 'bad_scope');
  assert.equal(codeOf(() => e.sensorReport({ identityId: s, node: C.castNode1, body: { findings: Array.from({ length: 30000 }, () => ({ kind: 'ai-agent', name: 'a', namespace: 'n', pod: 'p' })) } })), 'bad_findings');
  assert.ok(Date.now() - t0 < 5000, `${Date.now() - t0} ms`);
});

test('a token whose payload is a deep or wide JSON structure is parsed, shown bounded and never throws', () => {
  const e = newEngine(); const t0 = Date.now();
  const mk = (payloadText) => `${b64u(JSON.stringify({ alg: 'RS256', kid: 'kube-key-1' }))}.${b64u(payloadText)}.${b64u('sig')}`;
  const deep = mk('['.repeat(1500) + ']'.repeat(1500)); assert.ok(deep.length <= 4096);
  const wide = mk(`{${Array.from({ length: 280 }, (_, i) => `"k${i}":1`).join(',')}}`); assert.ok(wide.length <= 4096);
  const nested = mk(`{"a":${'{"a":'.repeat(500)}1${'}'.repeat(500)}}`);
  for (const t of [deep, wide, nested]) {
    const r = e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
    assert.equal(r.ok, false); assert.ok(JSON.stringify(r).length < 20000, 'the shown claims are bounded');
  }
  assert.ok(Date.now() - t0 < 3000);
});

test('audit summaries store no raw value: only known keys, short masked strings; a secret typed as a claim (plain, percent-encoded, woven with zero-width characters) is not in any entry', () => {
  const pct = (t) => [...Buffer.from(t)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
  const ALLOWED = new Set(['n', 'at', 'kind', 'outcome', 'code', 'identityId', 'keyId', 'principal', 'deployment', 'claimed', 'service', 'scope', 'status', 'issuer', 'kid', 'note', 'minutes', 'platform', 'node']);
  for (const sc of MOCK_TABLE.verticals.finance.scenarios) for (const a of sc.state.audit) {
    for (const [k, v] of Object.entries(a)) { assert.ok(ALLOWED.has(k), `audit key ${k}`); if (typeof v === 'string') { assert.equal(maskResponseText(v), v, `${k} is already masked`); assert.ok(v.length <= 220, `${k} is short`); } }
  }
  const e = newEngine();
  for (const [name, v] of Object.entries(SECRETS)) {
    const probe = name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' || name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v;
    for (const typed of [v, pct(v), pct(pct(v)), v.split('').join(String.fromCharCode(0x200b))]) {
      const m = e.mint({ issuer: 'kube', claims: { sub: typed, aud: GW, extra: { node: typed, pod: typed } } });
      e.verify({ token: m.mintedToken, service: 'mcp' }); e.verify({ token: m.mintedToken, identityId: 'fid-001', service: 'mcp' });
    }
    const text = JSON.stringify(e.snapshot().audit);
    for (const p of [probe, pct(probe)]) assert.ok(!text.includes(p), `${name} is not in the audit log`);
  }
  assert.ok(e.snapshot().audit.every((a) => !a.claimed || a.claimed.length <= 160));
  assert.ok(k8sMint(e) && K8S_SUB);
});
