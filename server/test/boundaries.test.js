// Literal boundaries of the editable thresholds: N accepted, N+1 refused (S6), and the exactness of the comparisons the gateway makes. Each assertion names the number.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { b64u, jwkProblem, parseToken, signRS256, signingInput, MAX_TOKEN } from '../src/jwt.js';
import { ISSUER } from '../src/catalog.js';
import { GENERATIONS, keyAt } from '../src/keys.js';
import { createWorkspaces } from '../src/workspaces.js';
import { VERTICALS } from '../src/cast.js';
import { GW, K8S_SUB, codeOf, k8sMint, k8sVerify, newEngine } from './helpers.js';

const KID = 'kube-key-1';
// A token with the claims exactly as given, really signed by the Kubernetes issuer's first key (the mint would refuse or rewrite some of them).
const signed = (payload, header = { alg: 'RS256', typ: 'JWT', kid: KID }) => {
  const input = signingInput(header, payload);
  return `${input}.${signRS256(input, keyAt(ISSUER.kube.slot * GENERATIONS).privateKey)}`;
};
const claims = (e, over = {}) => ({ iss: ISSUER.kube.url, sub: K8S_SUB, aud: GW, iat: e.s.now, exp: e.s.now + 3600, ...over });
const verifyRaw = (e, payload) => e.verify({ token: signed(payload), identityId: 'fid-001', service: 'mcp' });

test('identity.notAfter: a token is refused AT the expiry second and accepted one second before it (S6)', () => {
  const e = newEngine();
  e.updateIdentity({ identityId: 'fid-001', notAfter: '2026-11-02T09:01:00Z' }); // the lab clock starts at 09:00:00
  assert.equal(k8sVerify(e).ok, true, 'at 09:00:00 the identity is valid until 09:01:00');
  e.advance({ minutes: 1 }); // 09:01:00 exactly: now equals notAfter
  const r = k8sVerify(e);
  assert.equal(r.code, 'identity_expired', 'now == notAfter is expired'); assert.match(r.detail, /expired at 2026-11-02T09:01:00Z/);
  const e2 = newEngine();
  e2.updateIdentity({ identityId: 'fid-001', notAfter: '2026-11-02T09:02:00Z' });
  e2.advance({ minutes: 1 });
  assert.equal(k8sVerify(e2).ok, true, 'one minute before notAfter it still works');
  e2.advance({ minutes: 1 });
  assert.equal(k8sVerify(e2).code, 'identity_expired');
});

test('maxTokenLifetimeSec: 86400 is accepted, 86401 is refused, 0 is accepted (the default), -1 is refused (S6)', () => {
  const e = newEngine();
  const set = (v) => e.updateIdentity({ identityId: 'fid-001', federation: { maxTokenLifetimeSec: v } });
  assert.deepEqual(set(86400), { identityId: 'fid-001', enabled: true });
  assert.equal(codeOf(() => set(86401)), 'bad_lifetime');
  assert.equal(codeOf(() => set(-1)), 'bad_lifetime');
  assert.equal(codeOf(() => set(1.5)), 'bad_lifetime');
  assert.equal(codeOf(() => set('3600')), 'bad_lifetime');
  assert.ok(set(0)); assert.equal(e.snapshot().identities[0].federation.effectiveCapSec, 3600, '0 means the default of 3600');
  // and the cap is enforced exactly: a token that lives 86400 s passes under a cap of 86400, one that lives 86401 s does not
  set(86400);
  assert.equal(verifyRaw(e, claims(e, { exp: e.s.now + 86400 })).ok, true);
  assert.equal(verifyRaw(e, claims(e, { exp: e.s.now + 86401 })).code, 'lifetime_exceeds_cap');
  set(0);
  assert.equal(verifyRaw(e, claims(e, { exp: e.s.now + 3600 })).ok, true, 'the default cap is 3600: a token that lives 3600 s passes');
  assert.equal(verifyRaw(e, claims(e, { exp: e.s.now + 3601 })).code, 'lifetime_exceeds_cap', 'and 3601 s does not');
});

test('the audience must be exact: an array with a non-string element, a padded string and a number are refused (S6)', () => {
  const e = newEngine();
  assert.equal(verifyRaw(e, claims(e)).ok, true);
  assert.equal(verifyRaw(e, claims(e, { aud: [GW] })).ok, true);
  assert.equal(verifyRaw(e, claims(e, { aud: ['other', GW] })).ok, true, 'a list that holds the audience is accepted');
  for (const aud of [[GW, 1], [1, GW], [GW, null], [GW, {}], [GW, [GW]], [GW, true], `${GW} `, ` ${GW}`, `${GW}\n`, `\t${GW}`, 7, null, { a: GW }, [], [`${GW} `]]) {
    const r = verifyRaw(e, claims(e, { aud }));
    assert.equal(r.code, 'aud_mismatch', JSON.stringify(aud)); assert.equal(r.status, 401);
  }
});

test('the subject must be exact: an array holding the subject, a number and a padded subject are refused; allowAnySubject opts out', () => {
  const e = newEngine();
  for (const sub of [[K8S_SUB], { toString: 1 }, 5, true, `${K8S_SUB} `, ` ${K8S_SUB}`, K8S_SUB.toUpperCase()]) assert.equal(verifyRaw(e, claims(e, { sub })).code, 'subject_mismatch', JSON.stringify(sub));
  assert.equal(verifyRaw(e, claims(e, { sub: undefined })).code, 'sub_missing');
  assert.equal(verifyRaw(e, claims(e)).ok, true);
});

test('a pinned claim is compared strictly: the number 1 is not the string "1", true is not "true"', () => {
  const e = newEngine();
  e.updateIdentity({ identityId: 'fid-001', federation: { requiredClaims: { pod: 'p-0', n: 1, flag: true } } });
  const ok = claims(e, { pod: 'p-0', n: 1, flag: true });
  assert.equal(verifyRaw(e, ok).ok, true);
  for (const over of [{ n: '1' }, { n: [1] }, { flag: 'true' }, { flag: 1 }, { pod: ['p-0'] }]) assert.equal(verifyRaw(e, { ...ok, ...over }).code, 'required_claim_mismatch', JSON.stringify(over));
});

// A token of exactly `n` characters whose parts are valid, canonical base64url, built by padding the payload and picking a signature length.
function tokenOfLength(n) {
  const header = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: KID }));
  for (let pad = 0; pad < 6000; pad++) {
    const payload = b64u(JSON.stringify({ iss: ISSUER.kube.url, pad: 'x'.repeat(pad) }));
    for (const sigBytes of [1, 2, 3, 4, 5, 6]) {
      const sig = b64u(Buffer.alloc(sigBytes, 7));
      const t = `${header}.${payload}.${sig}`;
      if (t.length === n) return t;
    }
  }
  throw new Error(`cannot build a token of ${n} characters`);
}
test('MAX_TOKEN is 4096: a 4096 character token is parsed, a 4097 character token is malformed (S6)', () => {
  assert.equal(MAX_TOKEN, 4096);
  const ok = tokenOfLength(4096); const big = tokenOfLength(4097);
  assert.equal(ok.length, 4096); assert.equal(big.length, 4097);
  assert.equal(parseToken(ok).ok, true);
  const refused = parseToken(big); assert.equal(refused.ok, false); assert.equal(refused.code, 'malformed_token'); assert.match(refused.detail, /longer than 4096/);
  const e = newEngine();
  assert.notEqual(e.verify({ token: ok, identityId: 'fid-001', service: 'mcp' }).code, 'malformed_token', 'it gets past the parse step (and fails later)');
  assert.equal(e.verify({ token: big, identityId: 'fid-001', service: 'mcp' }).code, 'malformed_token');
  assert.equal(e.verify({ token: big, identityId: 'fid-001', service: 'mcp' }).steps[0].status, 'fail');
});

test('mint time offsets: 31,536,000 seconds either way is accepted, one more is refused; null leaves the claim out (S6)', () => {
  const e = newEngine();
  const mint = (times) => e.mint({ issuer: 'kube', claims: { sub: K8S_SUB, aud: GW }, times });
  for (const key of ['exp', 'iat', 'nbf']) {
    assert.ok(mint({ [key]: 31_536_000 }).mintedToken, `${key} +31536000`);
    assert.ok(mint({ [key]: -31_536_000 }).mintedToken, `${key} -31536000`);
    assert.equal(codeOf(() => mint({ [key]: 31_536_001 })), 'bad_times', `${key} +31536001`);
    assert.equal(codeOf(() => mint({ [key]: -31_536_001 })), 'bad_times', `${key} -31536001`);
  }
  assert.equal(codeOf(() => mint({ exp: 1.5 })), 'bad_times'); assert.equal(codeOf(() => mint({ exp: '5' })), 'bad_times');
  const p = parseToken(mint({ exp: null, nbf: null }).mintedToken).payload; assert.equal(Object.hasOwn(p, 'exp'), false);
});

test('a claim is at most 160 characters and is never cut; 24 or more letters in a stored value or a claim is credential-shaped (S6)', () => {
  const e = newEngine();
  const mintSub = (sub) => e.mint({ issuer: 'kube', claims: { sub, aud: GW } });
  assert.equal(mintSub(`a:${'b '.repeat(79)}`.slice(0, 160)).claims.sub.length, 160);
  assert.equal(codeOf(() => mintSub(`a:${'b '.repeat(80)}`.slice(0, 161))), 'claim_too_long');
  assert.ok(mintSub(`${'a'.repeat(23)}:${'b'.repeat(23)}`), '23 letters in a row, then a separator');
  assert.equal(codeOf(() => mintSub('a'.repeat(24))), 'credential_shaped');
  assert.equal(codeOf(() => mintSub(`x ${'a'.repeat(24)}`)), 'credential_shaped');
  // a stored value (a federation audience): 23 letters accepted, 24 refused without being echoed
  const e2 = newEngine();
  const aud = (v) => e2.updateIdentity({ identityId: 'fid-001', federation: { audience: v } });
  assert.ok(aud('a'.repeat(23))); assert.equal(codeOf(() => aud('a'.repeat(24))), 'audience_required');
  assert.ok(aud(`${'a'.repeat(23)}-${'b'.repeat(23)}`), 'a separator ends the run');
});

test('pinned and published key limits: kid 60 / 61 characters, n 700 / 701, e 16 / 17, and every private member is refused, `oth` included (S6)', () => {
  const pub = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  const good = { kty: 'RSA', kid: 'k', n: pub.n, e: pub.e };
  assert.equal(jwkProblem(good), null);
  assert.equal(jwkProblem({ ...good, kid: 'k'.repeat(60) }), null); assert.match(jwkProblem({ ...good, kid: 'k'.repeat(61) }), /short kid/);
  assert.match(jwkProblem({ ...good, kid: '' }), /kid/); assert.match(jwkProblem({ ...good, kid: 'bad kid' }), /kid/);
  assert.equal(jwkProblem({ ...good, n: 'w'.repeat(700) }), null); assert.match(jwkProblem({ ...good, n: 'w'.repeat(701) }), /short base64url/);
  assert.equal(jwkProblem({ ...good, e: '_'.repeat(16) }), null); assert.match(jwkProblem({ ...good, e: '_'.repeat(17) }), /short base64url/);
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']) assert.match(jwkProblem({ ...good, [k]: k === 'oth' ? [] : 'AQAB' }), /private key material/, k);
  assert.match(jwkProblem({ ...good, kty: 'EC' }), /only RSA/); assert.match(jwkProblem(null), /object/);
  // the same limit through the API: a pinned key set with `oth` is refused as private material
  const e = newEngine();
  const pin = (k) => e.createIdentity({ name: 'p', scopes: ['mcp'], platform: 'oidc', federation: { issuer: ISSUER.private.url, subject: 's', audience: 'a', jwks: [k] } });
  assert.equal(codeOf(() => pin({ ...good, oth: [] })), 'jwks_private_material');
  assert.ok(pin(good).identityId);
});

test('the default workspace store holds 500 visitors and forgets one after 60 idle minutes (S6)', () => {
  let t = 1_000_000;
  const w = createWorkspaces({ now: () => t });
  const cast = VERTICALS.finance;
  for (let i = 0; i < 500; i++) w.engine(`v${i}`, 'finance', cast);
  assert.equal(w.size(), 500, 'the 500th visitor is accepted');
  assert.equal(codeOf(() => w.engine('v500', 'finance', cast)), 'workspaces_full', 'the 501st is refused');
  t += 60 * 60 * 1000; // exactly 60 minutes idle: still kept
  assert.ok(w.peek('v0', 'finance'), 'idle for exactly 60 minutes: kept');
  t += 1; // 60 minutes and 1 ms
  assert.equal(w.peek('v0', 'finance'), null, 'idle for 60 minutes and a millisecond: forgotten');
  assert.equal(w.size(), 0);
  assert.ok(w.engine('late', 'finance', cast));
});

test('a disabled or expired identity still counts toward ambiguous_identity when the token does not name one (N2, documented)', () => {
  const e = newEngine();
  const twin = (over = {}) => e.createIdentity({ name: 'twin', scopes: ['mcp'], platform: 'kubernetes', ...over, federation: { issuer: ISSUER.kube.url, jwksUri: ISSUER.kube.jwksUri, subject: K8S_SUB, audience: GW } });
  const noName = () => e.verify({ token: k8sMint(e).mintedToken, service: 'mcp' });
  assert.equal(noName().ok, true, 'one identity matches');
  const a = twin({ enabled: false });
  assert.equal(noName().code, 'ambiguous_identity', 'a disabled twin still makes the match ambiguous');
  assert.equal(e.verify({ token: k8sMint(e).mintedToken, identityId: 'fid-001', service: 'mcp' }).ok, true, 'naming the identity resolves it');
  e.deleteIdentity({ identityId: a.identityId });
  twin({ notAfter: '2026-11-02T09:00:00Z' }); // already expired at the lab's start
  assert.equal(noName().code, 'ambiguous_identity', 'and so does an expired one');
});
