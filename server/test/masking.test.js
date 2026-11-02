import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_FREE, cleanFree, maskText } from '../src/credentials.js';
import { DETECTOR_IDS } from '../src/shared/mask.js';
import { credentialProblem, reveal } from '../src/clean.js';
import { maskDeep, maskResponseText } from '../src/mask.js';
import { C, GW, findCredentials, newEngine } from './helpers.js';

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
  assert.ok(DETECTOR_IDS.length >= 10);
});

test('a long hex run (a hash, a commit id) is ordinary text in a name or a note, but a claim or a stored value of 24 or more letters and digits is refused', () => {
  const hex = 'deadbeef'.repeat(6);
  assert.equal(cleanFree(`commit ${hex}`), `commit ${hex}`);
  assert.equal(credentialProblem(hex), true);
  assert.equal(credentialProblem('deadbeef'.repeat(3)), true); assert.equal(credentialProblem(`${'deadbeef'.repeat(2)}deadbee`), false, '23 characters');
});

test('cleanFree: masks, strips control and bidi characters, collapses space, caps, and never throws', () => {
  const v = SECRETS.github;
  assert.ok(!cleanFree(`token ${v}`).includes(v));
  assert.equal(cleanFree('a\u0000b‮c  d'), 'abc d', 'a control character and a bidi format character are deleted (never turned into a space: a keyword split by one must still be found)');
  assert.equal(cleanFree('a\tb\nc\rd'), 'a b c d', 'tab, line feed and carriage return are separators');
  assert.equal(cleanFree('x'.repeat(5000)).length <= MAX_FREE, true);
  assert.equal(cleanFree(undefined), ''); assert.equal(cleanFree(null), ''); assert.equal(cleanFree({}), '[masked:non-string]');
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
  assert.ok(Date.now() - t0 < 60000, `${Date.now() - t0} ms (only a catastrophic pattern can exceed this)`);
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
  assert.ok(!reveal(`use ${woven} now`).includes(v.slice(0, 12)));
  const full = [...v].map((c) => (c.charCodeAt(0) < 127 && c !== ' ' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c)).join('');
  assert.ok(!cleanFree(`use ${full} now`).includes(v.slice(0, 10)), 'fullwidth forms are folded');
  for (const fn of [cleanFree, reveal]) {
    const out = fn(`${'a '.repeat(9995)}${v}`, 40000);
    assert.ok(!out.includes(v.slice(0, 8)), 'not even the first characters of a secret straddling the old 20,000 character cut survive');
    assert.ok(!fn(`${'b '.repeat(14000)}${SECRETS.pem}`, 40000).includes('MIIEvQ'));
  }
});

test('reveal keeps a SPIFFE ID and a Kubernetes subject, masks every shape in SECRETS, and masks a 24-character blob', () => {
  assert.equal(reveal('spiffe://trust.example/ns/payments/sa/agent-runner'), 'spiffe://trust.example/ns/payments/sa/agent-runner');
  assert.equal(reveal('system:serviceaccount:payments:agent-runner'), 'system:serviceaccount:payments:agent-runner');
  for (const [name, v] of Object.entries(SECRETS)) {
    const out = reveal(`please use ${v} for this`);
    const probe = name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' ? 'hunter2hunter2' : name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v;
    assert.ok(!out.includes(probe), name);
  }
});

test('a credential typed into a name, description, key name or sensor name is masked everywhere the engine keeps or shows it; typed as a claim it is REFUSED (never signed, never shown)', () => {
  const probeOf = (name, v) => (name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' || name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v);
  for (const [name, v] of Object.entries(SECRETS)) {
    const e = newEngine(); e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) };
    const id = e.createIdentity({ name: `n ${v}`, description: `d ${v}`, scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', subject: 'a:b', audience: GW } }).identityId;
    e.updateIdentity({ identityId: id, name: `renamed ${v}` });
    e.createKey({ name: `k ${v}`, owner: { kind: 'identity', ref: id }, scopes: ['mcp'] });
    e.enrollSensor({ name: `s ${v}` });
    for (const claims of [{ sub: v }, { aud: v }, { iss: v }, { aud: [v] }, { extra: { note: v } }, { extra: { token: v } }]) {
      const code = (() => { try { e.mint({ issuer: 'kube', claims }); return null; } catch (err) { return err.code; } })();
      assert.equal(code, 'credential_shaped', `${name} ${JSON.stringify(Object.keys(claims))} is refused`);
    }
    const all = JSON.stringify([e.snapshot(), e.hops]);
    assert.ok(!all.includes(probeOf(name, v)), `${name} is nowhere in the state or the hops`);
  }
});

// ---- review patterns: invisible characters, percent-encoding, JSON-key and glued secrets, expansion bombs --------------------------------------------------------------
const IGNORABLE = [0x3164, 0xffa0, 0x115f, 0x1160, 0x034f, 0x180e, 0xfe00, 0xfe0f, 0xe0001, 0xe0020, 0xe007f, 0x061c, 0x206a, 0x206f, 0x17b4, 0x17b5, 0xfffd, 0x200b, 0x200d, 0x2060, 0xad, 0xfeff, 0x202e, 0x2066];
const ALL = [['cleanFree', (x) => cleanFree(x, 2000)], ['reveal', (x) => reveal(x, 2000)], ['maskResponseText', (x) => maskResponseText(x)]];
const pct = (text) => [...Buffer.from(text)].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('');
const probeFor = (name, v) => (name === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : name === 'bearer' ? 'tokenvalue' : name === 'assignment' || name === 'plain' ? 'hunter2hunter2' : name === 'pw' ? 'correcthorse' : name === 'userinfo' ? 's3cr3tpassw0rd' : name === 'authz' ? 'abcdef123456' : v);

test('every Default_Ignorable, Cf and U+FFFD character woven through a secret still lets it be masked, by all three cleaners', () => {
  const v = SECRETS.github;
  for (const cp of IGNORABLE) {
    const ch = String.fromCodePoint(cp); const woven = v.split('').join(ch);
    for (const [name, fn] of ALL) { const out = fn(`use ${woven} now`); assert.ok(!out.includes(v.slice(0, 8)), `U+${cp.toString(16)} in ${name}`); assert.ok(!out.includes(ch) || name === 'x', `U+${cp.toString(16)} is gone from ${name}`); }
  }
  const range = Array.from({ length: 16 }, (_, i) => String.fromCodePoint(0xfe00 + i)).join('');
  assert.ok(!cleanFree(`${v.slice(0, 6)}${range}${v.slice(6)}`).includes(v.slice(0, 8)), 'a run of variation selectors');
  const tags = Array.from({ length: 20 }, (_, i) => String.fromCodePoint(0xe0020 + i)).join('');
  assert.ok(!reveal(`${v.slice(0, 6)}${tags}${v.slice(6)}`).includes(v.slice(0, 8)), 'a run of tag characters');
});

test('percent-encoded secrets (once, twice, three times, and fullwidth percent signs) are decoded before masking, in every cleaner and the response mask', () => {
  for (const [name, v] of Object.entries(SECRETS)) {
    const probe = probeFor(name, v);
    const forms = { plain: v, once: pct(v), twice: pct(pct(v)), thrice: pct(pct(pct(v))), fullwidth: pct(v).replace(/%/g, String.fromCharCode(0xff05)) };
    for (const [form, text] of Object.entries(forms)) for (const [fname, fn] of ALL) {
      if (fname === 'maskResponseText' && (name === 'blob' || name === 'hex')) continue; // the response mask leaves long ids and hashes alone by design; the cleaners mask them on the way in
      const out = fn(`note ${text} end`);
      assert.ok(!out.includes(probe), `${name}/${form} through ${fname}`);
      assert.ok(!out.includes(pct(probe)), `${name}/${form}: the encoded form is not left either (${fname})`);
    }
  }
  assert.equal(cleanFree('100% sure %zz and %'), '100% sure %zz and %', 'text that merely contains a percent sign is left alone');
  assert.ok(cleanFree(`${'%25'.repeat(5000)}41`).length < 2000, 'a percent bomb is bounded');
});

test('keyword plus JSON-key secrets and glued assignments are masked, whatever the quoting', () => {
  const cases = [['{"password":"x"}', 'x"'], ['{"token":"abc"}', 'abc'], ["{'secret':'hunter22'}", 'hunter22'], ['a","b":"password: zq81xkzq', 'zq81xkzq'], ['xpassword=zq81xkzq', 'zq81xkzq'], ['{"api_key":"k"}', ':"k'], ['{"client-secret": "s3cr3tvalue"}', 's3cr3tvalue'], ['pw:zq81xkzq', 'zq81xkzq'], ['"credential":"c"', ':"c'], ['{"password":"x" }', ':"x'], ['{ "secret" : "q" , "n": 1 }', ':"q'], ["{'token':'z' }", ":'z"], ['{"passphrase" : "correct horse"}', 'correct']];
  for (const [text, probe] of cases) for (const [name, fn] of ALL) assert.ok(!fn(text).includes(probe), `${text} through ${name}`);
  assert.equal(cleanFree('the password policy is documented'), 'the password policy is documented', 'a word on its own is not a secret');
});

test('an NFKC expansion bomb (30,000 characters that each become eighteen) is bounded in time and output', () => {
  const bomb = String.fromCharCode(0xfdfa).repeat(30000); const t0 = Date.now();
  for (const [name, fn] of ALL) assert.ok(name === 'maskResponseText' || fn(bomb).length <= 2000);
  assert.ok(maskResponseText(bomb).length <= 200000);
  assert.ok(Date.now() - t0 < 60000, `${Date.now() - t0} ms (only a catastrophic pattern can exceed this)`);
});

test('the response mask changes nothing it does not have to: ordinary text, ids and hashes pass through unchanged', () => {
  for (const t of ['The token stops at the gateway.', 'payments/agent-runner pod agent-runner-7d9f', `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`, 'https://gateway.fabrikam.example', '100% done']) assert.equal(maskResponseText(t), t);
});
