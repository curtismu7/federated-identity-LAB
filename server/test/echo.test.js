// A credential the visitor types must come back in NO response field, hop pane, audit entry, log line or error: tested by typing every credential shape into every
// field, query, path, header and unknown key of every endpoint, and searching every answer, the state afterwards and the process output for it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { C, GW, K8S_SUB, get, post, put, withServer } from './helpers.js';
import { SECRETS } from './masking.test.js';

const probeOf = (k, v) => (k === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : k === 'bearer' ? 'tokenvalue' : k === 'assignment' || k === 'plain' ? 'hunter2hunter2' : k === 'pw' ? 'correcthorse' : k === 'userinfo' ? 's3cr3tpassw0rd' : k === 'authz' ? 'abcdef123456' : v);
const NEEDLES = Object.fromEntries(Object.entries(SECRETS).map(([k, v]) => [k, { raw: v, probe: probeOf(k, v) }]));
const live = (extra = {}) => ({ mode: 'live', vertical: 'finance', ...extra });
const e = encodeURIComponent;
const URI = 'https://kube-api.cluster-a.example/openid/v1/jwks';

// Types the text v into every field, query, path and header of every endpoint and returns everything that came back.
async function sweepAll(url, v) {
  const fed = (x) => ({ issuer: x, subject: x, audience: x, jwksUri: x, jwks: [{ kty: x, kid: x, n: x, e: x, d: x }], pinFromIssuer: x, maxTokenLifetimeSec: x, requiredClaims: { [x]: x, a: x }, allowAnySubject: x, [x]: x });
  const ident = (x) => ({ name: x, description: x, platform: x, scopes: [x], notAfter: x, enabled: x, federation: fed(x), [x]: x });
  const bodies = [
    ['POST', '/api/tokens/mint', live({ mint: { issuer: v, alg: v, generation: v, kid: v, claims: { iss: v, sub: v, aud: v, extra: { [v]: v, a: v } }, times: { iat: v, exp: v, nbf: v }, [v]: v } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'kube', kid: v } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'kube', claims: { iss: v, sub: v, aud: [v, v], extra: { token: v, note: `x ${v}` } } } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'attacker', alg: 'HS256', claims: { sub: v, aud: v } } })],
    ['POST', '/api/verify', live({ verify: { token: v, identityId: v, service: v, keyId: v, [v]: v } })],
    ['POST', '/api/verify', live({ verify: { token: v, identityId: 'fid-001', service: 'mcp' } })],
    ['POST', '/api/verify', live({ verify: { token: v, service: 'mcp' } })],
    ['POST', '/api/verify', live({ verify: { token: [v, v, v].join(" "), service: 'mcp' } })],
    ['POST', '/api/clock', live({ clock: { minutes: v, [v]: v } })],
    ['POST', `/api/issuers/${e(v)}/actions`, live({ action: { action: v, retireOld: v, [v]: v } })],
    ['POST', '/api/issuers/kube/actions', live({ action: { action: v, retireOld: v } })],
    ['POST', '/api/identities', live({ identity: ident(v) })],
    ['POST', '/api/identities', live({ identity: { name: `n ${v}`, description: `d ${v}`, scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: v, audience: GW } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: v } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW, requiredClaims: { repo: v } } } })],
    ['PUT', `/api/identities/${e(v)}`, live({ identity: ident(v) })],
    ['PUT', '/api/identities/fid-001', live({ identity: ident(v) })],
    ['PUT', '/api/identities/fid-001', live({ identity: { name: `r ${v}`, federation: { subject: v } } })],
    ['POST', `/api/identities/${e(v)}/remove`, live({ remove: { [v]: v } })],
    ['POST', `/api/identities/${e(v)}/refresh`, live({ refresh: { [v]: v } })],
    ['POST', '/api/keys', live({ key: { name: v, owner: { kind: v, ref: v, [v]: v }, scopes: [v], ownFederation: v, userRef: v, [v]: v } })],
    ['POST', '/api/keys', live({ key: { name: `k ${v}`, owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] } })],
    ['PUT', `/api/keys/${e(v)}`, live({ key: { enabled: v, scopes: [v], [v]: v } })],
    ['POST', `/api/keys/${e(v)}/remove`, live({ remove: {} })],
    ['POST', `/api/keys/${e(v)}/stored-call`, live({ call: { service: v, [v]: v } })],
    ['PUT', `/api/people/${e(v)}`, live({ person: { active: v, [v]: v } })],
    ['POST', '/api/sensors', live({ sensor: { name: v, [v]: v } })],
    ['POST', '/api/sensors', live({ sensor: { name: `s ${v}` } })],
    ['POST', `/api/sensors/${e(v)}/reports`, live({ report: { node: v, tokenFrom: v, token: v, body: { node: v, findings: [{ kind: v, name: v, namespace: v, pod: v, [v]: v }], [v]: v }, [v]: v } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, body: { node: v, findings: [{ kind: 'ai-agent', name: `n ${v}`, namespace: C.castNs, pod: 'p-0' }] } } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, token: v, body: { findings: [{ kind: 'ai-agent', name: 'n', namespace: C.castNs, pod: 'p-0' }] } } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, body: { findings: [{ kind: 'ai-agent', name: 'n', namespace: v, pod: v }] } } })],
    ['PUT', `/api/sensors/${e(v)}/policy`, live({ policy: { mode: v, scope: { all: v, namespaces: [v], [v]: v }, actions: { [v]: v, 'ai-agent': v }, [v]: v } })],
    ['PUT', '/api/sensors/fid-006/policy', live({ policy: { mode: 'audit', scope: { namespaces: [v] }, actions: { 'ai-agent': 'allow', 'mcp-server': 'allow', 'model-server': 'allow' } } })],
    ['POST', '/api/reset', { [v]: v }],
  ];
  const gets = [`/api/state?mode=${e(v)}`, `/api/state?mode=live&vertical=${e(v)}&scenario=${e(v)}`, `/api/state?mode=mock&scenario=${e(v)}`, `/api/story?vertical=${e(v)}`, `/api/diagram?name=${e(v)}&vertical=${e(v)}`, `/api/${e(v)}`, `/api/health?x=${e(v)}`, `/${e(v)}`];
  const texts = [];
  for (const [m, p, b] of bodies) { const r = await (m === 'PUT' ? put : post)(url, p, b); texts.push(`${m} #${texts.length} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  for (const g of gets) { const r = await get(url, g); texts.push(`GET ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  for (const hv of [v, `a ${v}`]) { const r = await get(url, '/api/state?mode=live', { 'x-workspace': hv.slice(0, 40).replace(/[^\x20-\x7e]/g, '?') }); texts.push(`H ${r.status} ${await r.text()}`); }
  { const r = await post(url, '/api/clock', live({ clock: { minutes: 1 } }), { traceparent: v.replace(/[^\x20-\x7e]/g, '?') }); texts.push(`T ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  return texts.join('\n');
}

test('typing every credential shape into every field of every endpoint never echoes it', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  await withServer(async (url) => {
    await post(url, '/api/sensors', live({ sensor: { name: 'real' } }));
    const sweep = (v) => sweepAll(url, v);
    process.stdout.write = (c, ...a) => { out.push(String(c)); return realOut(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return realErr(c, ...a); };
    try {
      const pct = (t) => [...Buffer.from(t)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
      for (const [name, n] of Object.entries(NEEDLES)) {
        for (const [form, typed] of [['plain', n.raw], ['once-encoded', pct(n.raw)], ['twice-encoded', pct(pct(n.raw))]]) {
          const text = await sweep(typed);
          for (const probe of [n.probe, pct(n.probe), pct(pct(n.probe))]) assert.ok(!text.includes(probe), `${name}/${form}: the value is absent from every answer: ${text.split('\n').filter((l) => l.includes(probe)).map((l) => l.slice(0, 200)).join(' | ')}`);
          const state = JSON.stringify(await (await get(url, '/api/state?mode=live')).json());
          for (const probe of [n.probe, pct(n.probe)]) assert.ok(!state.includes(probe), `${name}/${form}: absent from the state afterwards`);
        }
      }
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
  });
  for (const n of Object.values(NEEDLES)) assert.ok(!out.join('').includes(n.probe), 'nothing was logged');
});

test('a credential in a real, accepted action is masked in the response, the hops, the audit trail and the state', async () => {
  await withServer(async (url) => {
    for (const [name, n] of Object.entries(NEEDLES)) {
      const W = { 'x-workspace': `echo-${name.toLowerCase()}`.slice(0, 30).replace(/[^a-z0-9-]/g, '-') };
      const refused = await post(url, '/api/tokens/mint', live({ mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW, extra: { pod: `x ${n.raw}`, note: n.raw } } } }), W); const rt = await refused.text();
      assert.equal(refused.status, 400, `${name}: a credential typed as a claim is refused, not signed`); assert.ok(!rt.includes(n.probe), `${name}: not in the refusal`); assert.match(rt, /credential_shaped/);
      const m = await post(url, '/api/tokens/mint', live({ mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW, extra: { pod: 'p-0' } } } }), W);
      const mb = await m.json(); assert.equal(m.status, 200);
      const v = await post(url, '/api/verify', live({ verify: { token: mb.result.mintedToken, identityId: 'fid-001', service: 'mcp' } }), W); const t = await v.text();
      assert.equal(v.status, 200); assert.ok(!t.includes(n.probe), `${name}: not in the verify answer`); assert.ok(t.includes('"audit"') && t.includes('"hops"'));
      const ident = await post(url, '/api/identities', live({ identity: { name: `n ${n.raw}`, description: n.raw, scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW } } }), W);
      assert.ok(!(await ident.text()).includes(n.probe), `${name}: not in an identity answer`);
    }
  });
});

test('field names are not echoed either: an unknown key that is itself a credential never comes back', async () => {
  await withServer(async (url) => {
    for (const n of Object.values(NEEDLES)) {
      for (const [m, p, b] of [['POST', '/api/tokens/mint', { mint: { issuer: 'kube', [n.raw]: 1 } }], ['POST', '/api/verify', { verify: { token: 'a.b.c', service: 'mcp', [n.raw]: 1 } }], ['POST', '/api/clock', { clock: { minutes: 1, [n.raw]: 1 } }], ['POST', '/api/identities', { identity: { name: 'x', [n.raw]: 1 } }], ['PUT', '/api/sensors/fid-006/policy', { policy: { [n.raw]: 1 } }]]) {
        const r = await (m === 'PUT' ? put : post)(url, p, live(b)); const t = await r.text();
        assert.ok([400, 404].includes(r.status), p); assert.ok(!t.includes(n.probe));
      }
      const r = await post(url, '/api/clock', live({ clock: { minutes: 1 }, [n.raw]: 1 })); assert.ok(!(await r.text()).includes(n.probe));
    }
  });
});

test('a credential-shaped KEY at every depth of every endpoint body (plain, once- and twice-encoded) never comes back, in any answer or in the state afterwards', async () => {
  const pct = (t) => [...Buffer.from(t)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
  const fedBase = { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW };
  const templates = [
    ['POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW, extra: { pod: 'p' } }, times: { iat: 0, exp: 3600 } } }],
    ['POST', '/api/verify', { verify: { token: 'a.b.c', service: 'mcp' } }], ['POST', '/api/clock', { clock: { minutes: 1 } }], ['POST', '/api/issuers/kube/actions', { action: { action: 'rotate' } }],
    ['POST', '/api/identities', { identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { ...fedBase, requiredClaims: { a: 'b' } } } }],
    ['PUT', '/api/identities/fid-002', { identity: { federation: { requiredClaims: { repository: 'x' } } } }], ['POST', '/api/keys', { key: { name: 'k', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] } }],
    ['PUT', '/api/keys/key-0001', { key: { enabled: true, scopes: ['mcp'] } }], ['PUT', `/api/people/${C.castOwner}`, { person: { active: true } }], ['POST', '/api/sensors', { sensor: { name: 's' } }],
    ['PUT', '/api/sensors/fid-006/policy', { policy: { mode: 'audit', scope: { namespaces: [C.castNs] }, actions: { 'ai-agent': 'allow', 'mcp-server': 'warn', 'model-server': 'deny' } } }],
    ['POST', '/api/sensors/fid-006/reports', { report: { node: C.castNode1, body: { findings: [{ kind: 'ai-agent', name: 'a', namespace: C.castNs, pod: 'p-0' }] } } }],
  ];
  // every object node of a body, as a path of keys; a variant is the body with one extra secret-shaped key at that node
  const nodes = (o, path = []) => (o !== null && typeof o === 'object' && !Array.isArray(o) ? [path, ...Object.keys(o).flatMap((k) => nodes(o[k], [...path, k]))] : o !== null && typeof o === 'object' ? o.flatMap((x, i) => nodes(x, [...path, i])) : []);
  const inject = (body, path, key) => { const c = JSON.parse(JSON.stringify(body)); let at = c; for (const p of path) at = at[p]; at[key] = 'x'; return c; };
  await withServer(async (url) => {
    await post(url, '/api/sensors', live({ sensor: { name: 'real' } }));
    let sent = 0;
    for (const [name, n] of Object.entries(NEEDLES)) {
      for (const typed of [n.raw, pct(n.raw), pct(pct(n.raw))]) {
        const texts = [];
        for (const [m, p, tpl] of templates) for (const path of nodes(tpl)) {
          const r = await (m === 'PUT' ? put : post)(url, p, live(inject(tpl, path, typed))); texts.push(await r.text()); sent++;
        }
        const r = await post(url, '/api/clock', live({ clock: { minutes: 1 }, [typed]: 1 })); texts.push(await r.text());
        texts.push(JSON.stringify(await (await get(url, '/api/state?mode=live')).json()));
        const all = texts.join('\n');
        for (const probe of [n.probe, pct(n.probe), pct(pct(n.probe))]) assert.ok(!all.includes(probe), `${name}: a key shaped like this never comes back (${probe.slice(0, 12)})`);
      }
    }
    assert.ok(sent > 1000, `${sent} requests`);
  });
});

// ---- control characters woven through a keyword (C0, DEL, C1): the folded text is matched, so the secret is masked in every field of every endpoint ----------------------------
const CONTROLS = [0x00, 0x01, 0x1f, 0x7f, 0x85, 0x9f].map((c) => String.fromCharCode(c));
const weave = (word, ch) => [...word].join(ch);
const CONTROL_FORMS = (ch) => [
  ['password', `${weave('password', ch)}: CANARYpwd77hunter`, 'CANARYpwd77hunter'],
  ['pw', `${weave('pw', ch)}: CANARYpw88xyz99`, 'CANARYpw88xyz99'],
  ['token', `${weave('token', ch)}= CANARYtok66abcd`, 'CANARYtok66abcd'],
  ['Bearer', `${weave('Bearer', ch)} CANARYbrr55abcdef`, 'CANARYbrr55abcdef'],
  ['sk-', `${weave('sk-', ch)}CANARYsk44abcdefgh`, 'CANARYsk44abcdefgh'],
];

test('a keyword split by a C0, DEL or C1 control character (password, pw, token, Bearer, sk-) is masked in every field of every endpoint, in the state afterwards and in the log', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  await withServer(async (url) => {
    process.stdout.write = (c, ...a) => { out.push(String(c)); return realOut(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return realErr(c, ...a); };
    try {
      let forms = 0;
      for (const ch of CONTROLS) for (const [word, typed, probe] of CONTROL_FORMS(ch)) {
        const text = await sweepAll(url, typed); forms++;
        assert.ok(!text.includes(probe), `U+${ch.charCodeAt(0).toString(16)} in ${word}: the value is absent from every answer: ${text.split('\n').filter((l) => l.includes(probe)).map((l) => l.slice(0, 200)).join(' | ')}`);
        const state = JSON.stringify(await (await get(url, '/api/state?mode=live')).json());
        assert.ok(!state.includes(probe), `U+${ch.charCodeAt(0).toString(16)} in ${word}: absent from the state afterwards`);
      }
      assert.equal(forms, 30);
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
  });
  for (const ch of CONTROLS) for (const [, , probe] of CONTROL_FORMS(ch)) assert.ok(!out.join('').includes(probe), 'nothing was logged');
});

test('a split keyword in a name is masked in the stored state, the audit trail and hop 1; as a mint claim it is refused; a control character that hides nothing is shown written out', async () => {
  await withServer(async (url) => {
    for (const ch of CONTROLS) for (const [word, typed, probe] of CONTROL_FORMS(ch)) {
      const W = { 'x-workspace': `ctl-${ch.charCodeAt(0)}-${word.toLowerCase().replace(/[^a-z]/g, '')}` };
      const put1 = await put(url, '/api/identities/fid-001', live({ identity: { name: typed } }), W); const t = await put1.text();
      assert.equal(put1.status, 200, word); assert.ok(!t.includes(probe), `${word}: not in the update answer, its hops or its state`);
      const st = await (await get(url, '/api/state?mode=live&vertical=finance', W)).json();
      assert.match(st.state.identities[0].name, /\[masked:/, 'the stored name is masked'); assert.ok(!JSON.stringify(st).includes(probe));
      for (const claims of [{ sub: typed }, { iss: typed }, { aud: typed }, { aud: [typed] }, { extra: { note: typed } }]) {
        const r = await post(url, '/api/tokens/mint', live({ mint: { issuer: 'kube', claims } }), W);
        assert.equal(r.status, 400, `${word} ${JSON.stringify(Object.keys(claims))} is refused`); const body = await r.text();
        assert.match(body, /credential_shaped/); assert.ok(!body.includes(probe));
      }
    }
    // claim exactness: a control character that hides no credential is signed exactly and shown written out, with a notice
    const r = await post(url, '/api/tokens/mint', live({ mint: { issuer: 'kube', claims: { sub: 'a\u0001b\u0085c\u007fd', aud: 'x' } } }), { 'x-workspace': 'ctl-plain' });
    const b = await r.json(); assert.equal(r.status, 200);
    assert.equal(b.result.claims.sub, 'a\\u{1}b\\u{85}c\\u{7f}d', 'the hidden characters are written out'); assert.ok(b.result.notices.some((n) => /hidden characters/.test(n.text)));
    assert.equal(JSON.parse(Buffer.from(b.result.mintedToken.split('.')[1], 'base64url').toString()).sub, 'a\u0001b\u0085c\u007fd', 'and signed exactly as typed');
  });
});
