// Regression tests for the leaks found in the review of the first adoption: each one types a credential-shaped text in one of the spellings that used to get through, into the
// places that used to echo it, and asserts it is absent from every answer, from hops[0].request.body, from the state afterwards and from stdout / stderr.
// The secret is assembled from parts at run time so no whole credential shape sits in the repository.
import test from 'node:test';
import assert from 'node:assert/strict';
import { get, json, post, put, withServer } from './helpers.js';
import { live, sweepAll } from './sweep.js';

const H = ['hunter', '2xyz'].join('');
const pct = (t) => [...Buffer.from(t)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
const pctN = (t, n) => { let s = t; for (let i = 0; i < n; i++) s = pct(s); return s; };
// the spellings: [label, text typed]
const FORMS = [
  ['the key is x', `the key is ${H}`],
  ['pass<TAB>word: x', `pass\tword: ${H}`],
  ['pass<U+2028>word: x', `pass word: ${H}`],
  ['U+1680 inside a keyword', `pass word: ${H}`],
  ['U+1680 inside a keyword (second spelling)', `pa ssword: ${H}`],
  ['password: x percent-encoded four times', pctN(`password: ${H}`, 4)],
];
const E = encodeURIComponent;
const R = (x) => ({ issuer: x, aud: x, sub: x });
// The 16 write endpoints. The text goes into issuer, aud and sub of the body (every one of them is echoed in hops[0].request.body) and into the path id wherever the route has one.
const WRITES = (x) => [
  ['POST', '/api/tokens/mint', { mint: { issuer: x, claims: { iss: x, ...R(x) } } }],
  ['POST', '/api/verify', { verify: { token: x, service: 'mcp', ...R(x) } }],
  ['POST', '/api/clock', { clock: { minutes: x, ...R(x) } }],
  ['POST', `/api/issuers/${E(x)}/actions`, { action: { action: 'rotate', ...R(x) } }],
  ['POST', '/api/identities', { identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: x, subject: x, audience: x }, ...R(x) } }],
  ['PUT', `/api/identities/${E(x)}`, { identity: { name: 'n', federation: { issuer: x, subject: x, audience: x }, ...R(x) } }],
  ['POST', `/api/identities/${E(x)}/remove`, { remove: R(x) }],
  ['POST', `/api/identities/${E(x)}/refresh`, { refresh: R(x) }],
  ['POST', '/api/keys', { key: { name: 'k', owner: { kind: 'identity', ref: x }, scopes: ['mcp'], ...R(x) } }],
  ['PUT', `/api/keys/${E(x)}`, { key: { enabled: true, ...R(x) } }],
  ['POST', `/api/keys/${E(x)}/remove`, { remove: R(x) }],
  ['POST', `/api/keys/${E(x)}/stored-call`, { call: { service: 'mcp', ...R(x) } }],
  ['PUT', `/api/people/${E(x)}`, { person: { active: true, ...R(x) } }],
  ['POST', '/api/sensors', { sensor: { name: 's', ...R(x) } }],
  ['POST', `/api/sensors/${E(x)}/reports`, { report: { node: 'n', body: { findings: [] }, ...R(x) } }],
  ['PUT', `/api/sensors/${E(x)}/policy`, { policy: { mode: 'audit', ...R(x) } }],
];
const strip = (s) => s.normalize('NFKC');

test('hops[0].request.body (and the rest of the answer and the state) never echo issuer, aud or sub on any of the 16 write endpoints, in six spellings, nor a path id', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  await withServer(async (url) => {
    process.stdout.write = (c, ...a) => { out.push(String(c)); return realOut(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return realErr(c, ...a); };
    try {
      let answered = 0; let withHops = 0;
      for (const [label, x] of FORMS) {
        assert.equal(WRITES(x).length, 16);
        for (const [m, p, b] of WRITES(x)) {
          const r = await (m === 'PUT' ? put : post)(url, p, live(b), { 'x-workspace': 'w-known' }); const t = await r.text(); answered += 1;
          assert.ok(!t.includes(H), `${label}: ${m} ${p.slice(0, 40)} ${r.status}: ${t.split(H)[0].slice(-60)}`);
          const body = JSON.parse(t);
          if (body.hops) { withHops += 1; const req = body.hops[0].request.body; assert.ok(req && typeof req === 'object', `${label}: hops[0].request.body is present on ${p.slice(0, 30)}`); assert.ok(!JSON.stringify(req).includes(H)); }
        }
        const state = await (await get(url, '/api/state?mode=live', { 'x-workspace': 'w-known' })).text();
        assert.ok(!state.includes(H), `${label}: absent from the state`);
      }
      assert.equal(answered, 96);
      assert.equal(withHops, 96, 'every one of the 16 write endpoints answers with hops, in every spelling');
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
  });
  assert.ok(!out.join('').includes(H), 'nothing was logged');
});

test('the same six spellings typed into every field, key, query, path segment and header of every endpoint (the whole sweep) are absent from every answer and from the state', async () => {
  await withServer(async (url) => {
    for (const [label, x] of FORMS) {
      const text = await sweepAll(url, x);
      assert.ok(!text.includes(H), `${label}: ${text.split('\n').filter((l) => l.includes(H)).map((l) => l.slice(0, 200)).join(' | ')}`);
      const state = JSON.stringify(await (await get(url, '/api/state?mode=live')).json());
      assert.ok(!state.includes(H), `${label}: absent from the state afterwards`);
    }
  });
});

test('clock minutes and a mint issuer typed as a four times percent-encoded keyword assignment are refused or masked, never echoed', async () => {
  const x = pctN(`password: ${H}`, 4);
  await withServer(async (url) => {
    const c = await post(url, '/api/clock', live({ clock: { minutes: x } }), { 'x-workspace': 'w-known4' }); const ct = await c.text();
    assert.equal(c.status, 400); assert.ok(!ct.includes(H) && !ct.includes(pctN(H, 4)) && !ct.includes(x), ct.slice(0, 300));
    const m = await post(url, '/api/tokens/mint', live({ mint: { issuer: x } }), { 'x-workspace': 'w-known4' }); const mt = await m.text();
    assert.equal(m.status, 400); assert.ok(!mt.includes(H) && !mt.includes(x), mt.slice(0, 300));
    const s = await (await get(url, '/api/state?mode=live', { 'x-workspace': 'w-known4' })).text();
    assert.ok(!s.includes(H) && !s.includes(x));
    assert.equal(strip(JSON.stringify(await json(await get(url, '/api/info')))).includes(H), false);
  });
});
