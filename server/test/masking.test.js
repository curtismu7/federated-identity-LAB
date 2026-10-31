import test from 'node:test';
import assert from 'node:assert/strict';
import { DETECTORS, MAX_FREE, cleanFree, findCredentials, maskText } from '../src/credentials.js';
import { cleanValue } from '../src/clean.js';
import { maskDeep } from '../src/mask.js';
import { C, GW, newEngine } from './helpers.js';

// Credential-shaped test values are assembled at run time, so no such string sits in the repository.
export const SECRETS = {
  github: ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join(''),
  githubPat: ['github', '_pat_', '11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJ'].join(''),
  gitlab: ['glpat', '-', 'AbCdEfGhIjKlMnOpQrSt'].join(''),
  slack: ['xox', 'b-', '123456789012-abcdefghijklmnopqrstuvwx'].join(''),
  aws: ['AKI', 'AIOSFODNN7EXAMPLE'].join(''),
  openai: ['sk', '-proj-', 'Zy9Xw8Vv7Uu6Tt5Ss4Rr3Qq2Pp1'].join(''),
  jwt: ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJhYmNkZWYifQ', 'abcdefghij1234567890XYZ'].join('.'),
  pem: ['-----BEGIN ', 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdefghijklmnop\n-----END ', 'PRIVATE KEY-----'].join(''),
  bearer: ['Bear', 'er ', 'abcdEFGH1234567890.tokenvalue'].join(''),
  assignment: ['pass', 'word=', 'hunter2hunter2'].join(''),
  blob: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5',
  hex: 'deadbeef'.repeat(6),
  plain: ['my pass', 'word is hunter2hunter2'].join(''),
  pw: ['p', 'w: correcthorsebattery'].join(''),
  userinfo: ['https://', 'user:s3cr3tpassw0rd@host.example/x'].join(''),
  authz: ['Authoriz', 'ation: token abcdef123456'].join(''),
  shortPrefixed: ['sk', '-abcdefghijkl'].join(''),
};

test('every credential shape is found and masked', () => {
  for (const [name, v] of Object.entries(SECRETS)) {
    assert.ok(findCredentials(`please use ${v} for this`).length > 0, name);
    const out = maskText(`please use ${v} for this`);
    assert.ok(!out.includes(v), `${name} is masked`);
    assert.match(out, /\[masked:/);
  }
  assert.ok(DETECTORS.length >= 10);
});

test('cleanFree: masks, strips control and bidi characters, collapses space, caps, and never throws', () => {
  const v = SECRETS.github;
  assert.ok(!cleanFree(`token ${v}`).includes(v));
  assert.equal(cleanFree('a\u0000b‮c  d'), 'a bc d', 'a control character becomes a space; a bidi format character is deleted');
  assert.equal(cleanFree('x'.repeat(5000)).length <= MAX_FREE, true);
  assert.equal(cleanFree(undefined), ''); assert.equal(cleanFree(null), ''); assert.equal(cleanFree({}), '[object Object]');
  assert.equal(cleanFree('I need read access to review the change for the release'), 'I need read access to review the change for the release', 'ordinary text is left alone');
});

test('a secret split across the 400 character cap is still masked (masking happens before the cut)', () => {
  const v = SECRETS.github;
  const text = `${'a '.repeat(190)}${v}`;
  assert.ok(!cleanFree(text, 400).includes(v.slice(0, 20)) || cleanFree(text, 400).length <= 400);
  const out = cleanFree(`${'a '.repeat(195)}${v}`, 400);
  assert.ok(!out.includes(v));
  assert.ok(!out.includes(v.slice(0, 12)), 'not even a prefix of the token survives');
});

test('detectors are linear: a hostile input of 20000 characters is scanned quickly', () => {
  const t0 = Date.now();
  for (const bad of ['a'.repeat(32000), 'password' + ' '.repeat(32000), '-----BEGIN PRIVATE KEY-----' + 'x'.repeat(32000), 'sk-' + '-'.repeat(32000), 'Bearer ' + 'a'.repeat(32000), 'eyJ' + 'a.'.repeat(16000), ('a=').repeat(16000), 'https://' + 'a:'.repeat(16000)]) cleanFree(bad);
  assert.ok(Date.now() - t0 < 3000, `${Date.now() - t0} ms`);
});

test('maskDeep masks nested values, keeps ids, hashes and trace ids, does not mutate, and survives a deep structure', () => {
  const v = SECRETS.github;
  const input = { a: [{ b: `x ${v}` }], hash: 'f'.repeat(64), traceparent: `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`, id: 'req-0001', n: 5, nil: null };
  const out = maskDeep(input);
  assert.ok(!JSON.stringify(out).includes(v));
  assert.equal(out.hash, input.hash); assert.equal(out.traceparent, input.traceparent); assert.equal(out.id, 'req-0001'); assert.equal(out.n, 5);
  assert.ok(input.a[0].b.includes(v), 'the input is not mutated');
  let deep = { v: `y ${v}` }; for (let i = 0; i < 50000; i++) deep = { d: deep };
  assert.doesNotThrow(() => maskDeep(deep));
});


const ZW = String.fromCharCode(0x200b);
test('zero-width characters interleaved, fullwidth forms and a secret placed after 19,990 filler characters are all still masked (invisible characters are deleted and the text is folded BEFORE matching, and masking comes before truncation)', () => {
  const v = SECRETS.github;
  const woven = v.split('').join(ZW);
  assert.ok(!cleanFree(`use ${woven} now`).includes(v.slice(0, 12)));
  assert.ok(!cleanValue(`use ${woven} now`).includes(v.slice(0, 12)));
  const full = [...v].map((c) => (c.charCodeAt(0) < 127 && c !== ' ' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c)).join('');
  assert.ok(!cleanFree(`use ${full} now`).includes(v.slice(0, 10)), 'fullwidth forms are folded');
  for (const fn of [cleanFree, cleanValue]) {
    const out = fn(`${'a '.repeat(9995)}${v}`, 40000);
    assert.ok(!out.includes(v.slice(0, 8)), 'not even the first characters of a secret straddling the old 20,000 character cut survive');
    assert.ok(!fn(`${'b '.repeat(14000)}${SECRETS.pem}`, 40000).includes('MIIEvQ'));
  }
});

test('cleanValue keeps a SPIFFE ID and a Kubernetes subject, masks every shape in SECRETS, and masks a 24-character blob', () => {
  assert.equal(cleanValue('spiffe://trust.example/ns/payments/sa/agent-runner'), 'spiffe://trust.example/ns/payments/sa/agent-runner');
  assert.equal(cleanValue('system:serviceaccount:payments:agent-runner'), 'system:serviceaccount:payments:agent-runner');
  for (const [name, v] of Object.entries(SECRETS)) {
    const out = cleanValue(`please use ${v} for this`);
    const probe = name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' ? 'hunter2hunter2' : name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v;
    assert.ok(!out.includes(probe), name);
  }
});

test('a credential typed into a name, description, claim, extra claim, key name or sensor name is masked everywhere the engine keeps or shows it', () => {
  const probeOf = (name, v) => (name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' || name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v);
  for (const [name, v] of Object.entries(SECRETS)) {
    const e = newEngine(); e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) };
    const id = e.createIdentity({ name: `n ${v}`, description: `d ${v}`, scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', subject: 'a:b', audience: GW } }).identityId;
    e.updateIdentity({ identityId: id, name: `renamed ${v}` });
    const m = e.mint({ issuer: 'kube', claims: { iss: v, sub: v, aud: [v, v], extra: { [`c`]: v, token: v } }, kid: undefined });
    const out = e.verify({ token: m.mintedToken, identityId: id, service: 'mcp' });
    e.createKey({ name: `k ${v}`, owner: { kind: 'identity', ref: id }, scopes: ['mcp'] });
    e.enrollSensor({ name: `s ${v}` });
    const all = JSON.stringify([m.header, m.claims, out, e.snapshot(), e.hops]);
    assert.ok(!all.includes(probeOf(name, v)), `${name} is nowhere in the answers, the state or the hops`);
    assert.ok(!Buffer.from(m.mintedToken.split('.')[1], 'base64url').toString().includes(probeOf(name, v)), `${name} is not inside the minted token either`);
  }
});
