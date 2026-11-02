// Fixes from the independent review: claims are signed EXACTLY as typed (or refused), credential-shaped claim names are refused, object keys are masked, token parsing is
// strict (canonical base64url, UTF-8, no crit), unknown-kid refreshes have a cooldown, and a flood of noise cannot push the audit's important entries out.
import test from 'node:test';
import assert from 'node:assert/strict';
import { maskDeep } from '../src/mask.js';
import { credentialProblem } from '../src/clean.js';
import { b64u, parseToken } from '../src/jwt.js';
import { LIMITS } from '../src/engine.js';
import { SECRETS } from './masking.test.js';
import { C, GW, K8S_SUB, codeOf, k8sMint, k8sVerify, newEngine } from './helpers.js';

const ZW = String.fromCharCode(0x200b);
const payloadOf = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const frozen = (e, fn) => { const before = JSON.stringify(e.snapshot()); const code = codeOf(fn); assert.ok(code); assert.equal(JSON.stringify(e.snapshot()), before); return code; };
const pct = (t) => [...Buffer.from(t)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
const probeOf = (name, v) => (name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' || name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v);

// ---- 3: the editor signs exactly what is typed ------------------------------------------------------------------------------------------------------------------------------
test('a typed claim is signed byte for byte: percent-encoding, a zero-width space, a fullwidth letter, a trailing space and a trailing slash are NOT normalised away', () => {
  const e = newEngine();
  const cases = { percent: `system:serviceaccount:${C.castNs}:agent%2Drunner`, zeroWidth: `system:serviceaccount:${C.castNs}:agent${ZW}-runner`, fullwidth: `${String.fromCharCode(0xff53)}ystem:serviceaccount:${C.castNs}:${C.castAgent}`, trailingSpace: `${K8S_SUB} `, leadingSpace: ` ${K8S_SUB}`, soft: `${K8S_SUB.slice(0, 8)}${String.fromCharCode(0xad)}${K8S_SUB.slice(8)}`, tab: `${K8S_SUB}\t` };
  for (const [name, sub] of Object.entries(cases)) {
    const m = e.mint({ issuer: 'kube', claims: { sub, aud: GW } });
    assert.equal(payloadOf(m.mintedToken).sub, sub, `${name}: signed exactly as typed`);
    const r = e.verify({ token: m.mintedToken, identityId: 'fid-001', service: 'mcp' });
    assert.equal(r.code, 'subject_mismatch', name);
    assert.ok(m.notices.some((n) => n.claim === 'sub'), `${name}: the mint says the value is not plain`);
    assert.ok(!/[\u0000-\u0008\u000b-\u001f​­ｓ]/.test(JSON.stringify(m.claims)) || name === 'fullwidth', `${name}: hidden characters are written out in the answer`);
  }
  const aud = e.mint({ issuer: 'kube', claims: { sub: K8S_SUB, aud: `${GW}%2F` } }); assert.equal(payloadOf(aud.mintedToken).aud, `${GW}%2F`, 'not decoded');
  assert.equal(k8sVerify(e, { claims: { sub: K8S_SUB, aud: `${GW}/` } }).code, 'aud_mismatch');
  assert.equal(e.mint({ issuer: 'kube', claims: { sub: `system:serviceaccount:${C.castNs}:agent${ZW}-runner`, aud: GW } }).claims.sub, `system:serviceaccount:${C.castNs}:agent\\u{200b}-runner`, 'the answer shows the hidden character, not a clean string');
  const plain = e.mint({ issuer: 'kube', claims: { sub: K8S_SUB, aud: GW } }); assert.deepEqual(plain.notices, [], 'a plain value has no notice');
});

test('a claim is refused, never rewritten: too long (not cut), credential-shaped (not masked then signed), a long alphanumeric run (not signed as [masked:long-blob])', () => {
  const e = newEngine();
  assert.equal(frozen(e, () => e.mint({ issuer: 'kube', claims: { sub: `${'a b '.repeat(40)}x`, aud: GW } })), 'claim_too_long');
  assert.ok(e.mint({ issuer: 'kube', claims: { sub: 'a '.repeat(80).slice(0, 160), aud: GW } }).mintedToken, '160 characters is allowed');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { sub: `system:serviceaccount:${C.castNs}:${'a'.repeat(30)}`, aud: GW } })), 'credential_shaped');
  for (const [name, v] of Object.entries(SECRETS)) for (const typed of [v, pct(v), v.split('').join(ZW)]) assert.ok(['credential_shaped', 'claim_too_long'].includes(codeOf(() => e.mint({ issuer: 'kube', claims: { sub: typed, aud: GW } }))), `${name} is never signed`);
  const m = e.mint({ issuer: 'kube', claims: { sub: K8S_SUB, aud: GW } }); assert.ok(!JSON.stringify(payloadOf(m.mintedToken)).includes('[masked'), 'no masked marker is ever inside a signed token');
});

test('the mint hop shows the claim with hidden characters written out, not the cleaned value', () => {
  const e = newEngine(); e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) };
  const sub = `${K8S_SUB}${ZW}`;
  e.mint({ issuer: 'kube', claims: { sub, aud: GW } });
  assert.equal(JSON.stringify(e.hops).includes(ZW), false);
});

// ---- 2: names and keys -------------------------------------------------------------------------------------------------------------------------------------------------------------
test('a credential-shaped pinned-claim NAME or extra-claim name is refused with fixed text and never echoed, stored or kept', () => {
  const e = newEngine();
  const URI = 'https://kube-api.cluster-a.example/openid/v1/jwks';
  const mk = (rc) => ({ name: 'x', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW, requiredClaims: rc } });
  for (const [name, v] of Object.entries(SECRETS)) {
    const key = v.slice(0, 40).replace(/[^A-Za-z0-9_.:/-]/g, '_');
    for (const bad of [key, `password:correcthorsebattery1`, ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('')].filter((k) => k.length <= 40 && credentialProblem(k))) {
      frozen(e, () => e.createIdentity(mk({ [bad]: 'x' })));
      frozen(e, () => e.updateIdentity({ identityId: 'fid-002', federation: { requiredClaims: { [bad]: 'x' } } }));
      frozen(e, () => e.mint({ issuer: 'kube', claims: { extra: { [bad]: 'x' } } }));
    }
    if (credentialProblem(key)) { let msg = ''; try { e.createIdentity(mk({ [key]: 'x' })); } catch (err) { msg = `${err.code} ${err.message}`; } assert.ok(msg && !msg.includes(key) && !msg.includes(probeOf(name, v)), `${name}: refused and the name is not echoed`); }
  }
  assert.ok(e.createIdentity(mk({ repository: 'x', environment: 'y' })).identityId, 'ordinary names are fine');
  assert.ok(!JSON.stringify(e.snapshot()).includes('correcthorsebattery1'));
});

test('maskDeep masks object KEYS at every depth, keeps shape, de-duplicates collisions and leaves ordinary keys, ids and public key members alone', () => {
  const g = ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join(''); const g2 = ['gh', 'p_', 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2'].join('');
  const out = maskDeep({ [g]: 1, [g2]: 2, ok: { deep: { [g]: ['x', { [`password:correcthorse${'1'}`]: 3 }] } }, 'fid-001': 4, n: 'AQAB', e: 'AQAB', __proto__x: 1 });
  const text = JSON.stringify(out);
  assert.ok(!text.includes(g) && !text.includes(g2) && !text.includes('correcthorse'));
  assert.deepEqual(Object.keys(out).filter((k) => k.startsWith('[masked')), ['[masked:prefix-token]', '[masked:prefix-token]#2'], 'two keys that mask alike are kept apart');
  assert.equal(out['fid-001'], 4); assert.equal(out.n, 'AQAB'); assert.equal(out.e, 'AQAB');
  assert.equal(Object.keys(out.ok.deep).length, 1);
  const proto = JSON.parse('{"__proto__":{"polluted":1}}'); const m = maskDeep(proto);
  assert.equal(Object.getPrototypeOf(m), Object.prototype); assert.equal({}.polluted, undefined);
});

// ---- 4: strict parsing ------------------------------------------------------------------------------------------------------------------------------------------------------------
test('the server parser is strict like the browser: no trimmed whitespace, no BOM, no invalid UTF-8, canonical base64url only, and a crit header is rejected (RFC 7515)', () => {
  const e = newEngine();
  const good = k8sMint(e).mintedToken; const [h, p, s] = good.split('.');
  const code = (t) => e.verify({ token: t, identityId: 'fid-001', service: 'mcp' }).code;
  assert.equal(code(good), 'allowed');
  for (const t of [`${good}  `, ` ${good}`, `${good}\n`, `${good}\t`]) assert.equal(code(t), 'malformed_token');
  const bom = (text) => b64u(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]));
  const hj = Buffer.from(h, 'base64url').toString(); const pj = Buffer.from(p, 'base64url').toString();
  assert.equal(code(`${bom(hj)}.${p}.${s}`), 'malformed_token', 'a BOM before the header JSON'); assert.equal(code(`${h}.${bom(pj)}.${s}`), 'malformed_token', 'a BOM before the payload JSON');
  assert.equal(code(`${b64u(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]))}.${p}.${s}`), 'malformed_token', 'invalid UTF-8 is refused, not repaired');
  // non-canonical encodings: the last character of the signature has unused bits, so several texts decode to the same bytes
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'; const last = ALPHA.indexOf(s.at(-1));
  const variants = [...ALPHA].filter((c, i) => i !== last && (i & ~15) === (last & ~15));
  assert.ok(variants.length >= 1);
  for (const c of variants) assert.equal(code(`${h}.${p}.${s.slice(0, -1)}${c}`), 'malformed_token', `the signature ending in ${c} decodes to the same bytes but is not canonical`);
  const crit = (c) => b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'kube-key-1', crit: c }));
  for (const c of [['exp'], [], 'x', ['b64'], ['unknown-extension'], null]) assert.equal(code(`${crit(c)}.${p}.${s}`), 'crit_unsupported', `crit ${JSON.stringify(c)}`);
  assert.equal(e.verify({ token: `${crit(['x'])}.${p}.${s}`, identityId: 'fid-001', service: 'mcp' }).steps[0].status, 'fail');
  assert.equal(parseToken(good).ok, true); assert.equal(parseToken(`${h}.${p}.${s}x`).ok, false);
});

// ---- M05: AllowAnySubject in the gateway's own lookup --------------------------------------------------------------------------------------------------------------------------
test('without a named identity the gateway matches on issuer alone only for an identity that opted in to AllowAnySubject', () => {
  const e = newEngine();
  const t = e.mint({ issuer: 'kube', claims: { sub: 'someone-else', aud: GW } }).mintedToken;
  assert.equal(e.verify({ token: t, service: 'mcp' }).code, 'no_matching_identity');
  e.updateIdentity({ identityId: 'fid-001', federation: { allowAnySubject: true } });
  const r = e.verify({ token: t, service: 'mcp' }); assert.equal(r.ok, true); assert.equal(r.identityId, 'fid-001');
  e.updateIdentity({ identityId: 'fid-001', federation: { allowAnySubject: false } });
  assert.equal(e.verify({ token: t, service: 'mcp' }).code, 'no_matching_identity');
});

// ---- 5: cooldown and the audit under flood -------------------------------------------------------------------------------------------------------------------------------------
test('700 verifies with distinct unknown kids: one audit entry each, at most one refresh per cooldown, and no change or allowed request is evicted', () => {
  const e = newEngine();
  const good = k8sMint(e).mintedToken; e.verify({ token: good, identityId: 'fid-001', service: 'mcp' });
  e.updateIdentity({ identityId: 'fid-001', description: 'must survive' });
  const before = e.snapshot();
  const keep = (s) => s.audit.filter((a) => a.outcome !== 'refused').map((a) => a.n);
  const nBefore = before.audit.at(-1).n; const refreshesBefore = before.identities[0].keyset.log.length;
  for (let i = 0; i < 700; i++) e.verify({ token: k8sMint(e, { kid: `unknown-${i}` }).mintedToken, identityId: 'fid-001', service: 'mcp' });
  const after = e.snapshot();
  assert.deepEqual(keep(after).filter((n) => n <= nBefore), keep(before), 'every earlier change and allowed request is still there');
  assert.equal(after.audit.filter((a) => a.outcome === 'refused').length, LIMITS.auditRefusals);
  assert.equal(after.auditDropped.refusals, 700 - LIMITS.auditRefusals); assert.equal(after.auditDropped.changes, 0); assert.equal(after.auditDropped.requests, 0);
  assert.equal(after.audit.at(-1).n - nBefore, 700, 'exactly one audit entry per verify');
  assert.equal(after.identities[0].keyset.log.length - refreshesBefore, 1, 'one refresh in the cooldown window, not seven hundred');
  assert.equal(after.audit.filter((a) => a.kind === 'jwks.refresh').length, 0, 'no separate refresh entry');
  assert.ok(after.audit.filter((a) => a.outcome === 'refused').some((a) => /cooled down/.test(a.note || '')));
  assert.match(after.identities[0].keyset.cooldownUntil, /^2026-/);
  e.advance({ minutes: 1 });
  const r = e.verify({ token: k8sMint(e, { kid: 'unknown-after' }).mintedToken, identityId: 'fid-001', service: 'mcp' });
  assert.equal(r.refresh.attempted, true, 'after the cooldown a refresh is tried again');
});

test('the cooldown is per identity and does not apply to a known kid, a pinned identity (nothing to refresh) or a different identity', () => {
  const e = newEngine();
  const unk = (iss, over = {}) => e.mint({ issuer: iss, kid: 'nope-key-9', claims: { sub: K8S_SUB, aud: GW }, ...over }).mintedToken;
  assert.equal(e.verify({ token: unk('kube'), identityId: 'fid-001', service: 'mcp' }).refresh.attempted, true);
  assert.equal(e.verify({ token: unk('kube'), identityId: 'fid-001', service: 'mcp' }).refresh.cooledDown, true);
  assert.equal(e.verify({ token: k8sMint(e).mintedToken, identityId: 'fid-001', service: 'mcp' }).ok, true, 'a known kid never needs a refresh');
  const gh = e.mint({ issuer: 'github', kid: 'nope-key-9', claims: { sub: `repo:${C.castOrg}/${C.castRepo}:ref:refs/heads/main`, aud: GW } }).mintedToken;
  assert.equal(e.verify({ token: gh, identityId: 'fid-002', service: 'mcp' }).refresh.attempted, true, 'another identity has its own cooldown');
  const pinned = e.mint({ issuer: 'private', kid: 'nope-key-9', claims: { sub: `agent:${C.castAgent}`, aud: GW } }).mintedToken;
  assert.equal(e.verify({ token: pinned, identityId: 'fid-005', service: 'mcp' }).refresh, null);
});
