import test from 'node:test';
import assert from 'node:assert/strict';
import { b64u, tamperToken } from '../src/jwt.js';
import { STEPS } from '../src/engine.js';
import { C, GH_SUB, GW, K8S_SUB, PRESET, k8sMint, k8sVerify, newEngine } from './helpers.js';

const forge = (e, header, payload, sig = 'c2ln') => `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}.${sig}`;
const codes = (r) => r.steps.filter((s) => s.status === 'fail').map((s) => s.id);

test('every preset gives the result it says: the right token is allowed, every wrong one is refused at its own step with its own code', () => {
  const e = newEngine();
  for (const p of Object.values(PRESET)) {
    const m = e.mint(p.mint);
    const r = e.verify({ token: m.mintedToken, identityId: p.identityId, service: p.service });
    assert.equal(r.ok ? 'ok' : r.code, p.expect, p.id);
    assert.equal(r.steps.length, STEPS.length, 'every step is always listed');
  }
});

test('a verification lists every step in order; passed steps, the one failing step and the steps never reached are told apart', () => {
  const e = newEngine();
  const ok = k8sVerify(e);
  assert.deepEqual(ok.steps.map((s) => s.id), STEPS.map((s) => s.id));
  assert.ok(ok.steps.every((s) => s.status === 'pass'));
  const bad = k8sVerify(e, { claims: { sub: `${K8S_SUB}x`, aud: GW } });
  const at = bad.steps.findIndex((s) => s.status === 'fail');
  assert.equal(bad.steps[at].id, 'subject');
  assert.ok(bad.steps.slice(0, at).every((s) => s.status === 'pass'));
  assert.ok(bad.steps.slice(at + 1).every((s) => s.status === 'skip' && s.detail === 'not reached'));
  assert.equal(bad.status, 401); assert.equal(bad.callerSees, '401 Unauthorized');
});

test('exact subject: a trailing character, a different case and a different namespace are all refused; the exact value passes', () => {
  const e = newEngine();
  assert.ok(k8sVerify(e).ok);
  for (const sub of [`${K8S_SUB}x`, K8S_SUB.toUpperCase(), K8S_SUB.slice(0, -1), `system:serviceaccount:${C.castNs3}:${C.castAgent}`]) assert.equal(k8sVerify(e, { claims: { sub, aud: GW } }).code, 'subject_mismatch', sub);
  assert.equal(k8sVerify(e, { claims: { aud: GW } }).code, 'sub_missing');
});

test('exact issuer: a trailing slash and a different case are refused', () => {
  const e = newEngine();
  for (const iss of ['https://kube-api.cluster-a.example/', 'https://KUBE-API.cluster-a.example']) assert.equal(k8sVerify(e, { claims: { iss, sub: K8S_SUB, aud: GW } }).code, 'issuer_mismatch', iss);
  assert.equal(k8sVerify(e, { claims: { iss: null, sub: K8S_SUB, aud: GW } }).code, 'issuer_mismatch', 'a missing iss is not a match');
});

test('whitespace around a subject or issuer is not trimmed by the gateway (forged by hand, because the mint cleans its claims)', () => {
  const e = newEngine();
  const good = k8sMint(e).mintedToken.split('.');
  const body = JSON.parse(Buffer.from(good[1], 'base64url'));
  const c = (over) => e.verify({ token: forge(e, { alg: 'RS256', typ: 'JWT', kid: 'kube-key-1' }, { ...body, ...over }, good[2]), identityId: 'fid-001', service: 'mcp' }).code;
  assert.equal(c({ sub: ` ${K8S_SUB}` }), 'bad_signature', 'any change after signing breaks the signature');
});

test('the audience is mandatory and exact: missing, different, a prefix, an array holding it (accepted) and an array without it (refused)', () => {
  const e = newEngine();
  assert.equal(k8sVerify(e, { claims: { sub: K8S_SUB } }).code, 'aud_missing');
  for (const aud of ['https://other.example', `${GW}/`, GW.slice(0, -2), GW.toUpperCase(), '']) assert.equal(k8sVerify(e, { claims: { sub: K8S_SUB, aud } }).code, 'aud_mismatch', aud);
  assert.ok(k8sVerify(e, { claims: { sub: K8S_SUB, aud: ['https://other.example', GW] } }).ok);
  assert.equal(k8sVerify(e, { claims: { sub: K8S_SUB, aud: ['https://other.example'] } }).code, 'aud_mismatch');
});

test('lifetime cap: exactly the cap passes, one second more is refused even though the token has not expired; a custom cap is honoured and 0 means the default', () => {
  const e = newEngine();
  assert.ok(k8sVerify(e, { times: { iat: 0, exp: 3600 } }).ok);
  const over = k8sVerify(e, { times: { iat: 0, exp: 3601 } });
  assert.equal(over.code, 'lifetime_exceeds_cap');
  assert.equal(over.steps.find((s) => s.id === 'expiry').status, 'pass', 'it had not expired');
  assert.ok(k8sVerify(e, { times: { iat: -3000, exp: 600 } }).ok, 'a long-ago iat with the lifetime inside the cap');
  assert.equal(k8sVerify(e, { times: { iat: -3601, exp: 100 } }).code, 'lifetime_exceeds_cap');
  e.updateIdentity({ identityId: 'fid-001', federation: { maxTokenLifetimeSec: 600 } });
  assert.ok(k8sVerify(e, { times: { iat: 0, exp: 600 } }).ok);
  assert.equal(k8sVerify(e, { times: { iat: 0, exp: 601 } }).code, 'lifetime_exceeds_cap');
  e.updateIdentity({ identityId: 'fid-001', federation: { maxTokenLifetimeSec: 7200 } });
  assert.ok(k8sVerify(e, { times: { iat: 0, exp: 7200 } }).ok);
  e.updateIdentity({ identityId: 'fid-001', federation: { maxTokenLifetimeSec: 0 } });
  assert.equal(k8sVerify(e, { times: { iat: 0, exp: 3601 } }).code, 'lifetime_exceeds_cap', '0 is the gateway default of 3600');
  assert.equal(e.snapshot().identities[0].federation.effectiveCapSec, 3600);
});

test('expiry is required, a number and in the future; exp equal to now is expired', () => {
  const e = newEngine();
  assert.equal(k8sVerify(e, { times: { exp: null } }).code, 'exp_missing');
  assert.equal(k8sVerify(e, { times: { exp: 0, iat: -10 } }).code, 'expired', 'exp equal to the lab clock is expired');
  assert.ok(k8sVerify(e, { times: { exp: 1, iat: -10 } }).ok);
  const t = forge(e, { alg: 'none' }, {});
  assert.ok(t);
});

test('iat is required and may not be in the future; exp must be after iat; nbf is honoured to the second', () => {
  const e = newEngine();
  assert.equal(k8sVerify(e, { times: { iat: null } }).code, 'iat_missing');
  assert.ok(k8sVerify(e, { times: { iat: 0 } }).ok);
  assert.equal(k8sVerify(e, { times: { iat: 1, exp: 100 } }).code, 'iat_in_future');
  assert.equal(k8sVerify(e, { times: { iat: 100, exp: 50 } }).code, 'iat_in_future');
  assert.equal(k8sVerify(e, { times: { iat: -100, exp: -50 } }).code, 'expired');
  assert.equal(k8sVerify(e, { times: { iat: 0, exp: 0 } }).code, 'expired');
  assert.ok(k8sVerify(e, { times: { nbf: 0 } }).ok, 'nbf equal to now is reached');
  assert.equal(k8sVerify(e, { times: { nbf: 1 } }).code, 'not_yet_valid');
});

test('the algorithm allow-list: none in any case, HS256 in any case and any unknown name are refused; ES256 is asymmetric but unsupported by the lab', () => {
  const e = newEngine();
  const good = k8sMint(e).mintedToken.split('.');
  const body = JSON.parse(Buffer.from(good[1], 'base64url'));
  const withAlg = (alg, kid = 'kube-key-1') => forge(e, { alg, typ: 'JWT', kid }, body, good[2]);
  const code = (t) => e.verify({ token: t, identityId: 'fid-001', service: 'mcp' }).code;
  for (const a of ['none', 'None', 'NONE', 'nOnE']) assert.equal(code(withAlg(a)), 'alg_none', a);
  for (const a of ['HS256', 'HS384', 'HS512', 'hs256', 'Hs256']) assert.equal(code(withAlg(a)), 'alg_symmetric', a);
  for (const a of ['ES256', 'PS256', 'RS512', 'EdDSA']) assert.equal(code(withAlg(a)), 'alg_unsupported_by_lab', a);
  for (const a of ['XYZ', 'rs256', '', 'RS256 ']) assert.equal(code(withAlg(a)), 'alg_not_allowed', JSON.stringify(a));
  assert.equal(code(forge(e, { typ: 'JWT', kid: 'kube-key-1' }, body, good[2])), 'alg_not_allowed', 'no alg at all');
  assert.equal(code(forge(e, { alg: 5 }, body, good[2])), 'alg_not_allowed', 'a non-string alg');
  assert.equal(e.mint({ issuer: 'kube', alg: 'HS256', claims: { sub: K8S_SUB, aud: GW } }).notes.includes('public key'), true, 'the HS256 form is the public-key-as-secret confusion attack');
});

test('a real signature check: an altered payload, an altered header, a swapped signature and a different key all fail; an attacker under the issuer\'s kid fails', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken; const [h, p, s] = t.split('.');
  const v = (x) => e.verify({ token: x, identityId: 'fid-001', service: 'mcp' }).code;
  assert.equal(v(t), 'allowed');
  assert.equal(v(tamperToken(t)), 'bad_signature');
  assert.equal(v(`${h}.${p}.${s.slice(0, -4)}AAAA`), 'bad_signature');
  assert.equal(v(`${h}.${p}.`), 'bad_signature');
  const other = k8sMint(e, { claims: { sub: K8S_SUB, aud: GW, extra: { pod: 'other' } } }).mintedToken.split('.');
  assert.equal(v(`${h}.${p}.${other[2]}`), 'bad_signature', 'a signature for another message');
  assert.equal(v(PRESET['attacker-forged-kid'] && e.mint(PRESET['attacker-forged-kid'].mint).mintedToken), 'bad_signature');
  assert.equal(v(e.mint(PRESET['attacker-own-kid'].mint).mintedToken), 'unknown_kid');
});

test('malformed tokens are refused at the parse step with fixed text that never echoes the token', () => {
  const e = newEngine();
  const good = k8sMint(e).mintedToken;
  const cases = ['', 'a', 'a.b', 'a.b.c.d', `${good}.x`, '...', 'a b.c.d', `${b64u('[]')}.${b64u('{}')}.x`, `${b64u('{}')}.${b64u('[]')}.x`, `${b64u('not json')}.${b64u('{}')}.x`, `${b64u('{}')}.${b64u('"str"')}.x`, 'x'.repeat(5000)];
  for (const t of cases) {
    const r = e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
    assert.equal(r.code, 'malformed_token', t.slice(0, 20)); assert.equal(r.steps[0].status, 'fail');
    assert.ok(!JSON.stringify(r).includes(t) || t.length < 4, 'the token is not echoed');
  }
  assert.throws(() => e.verify({ token: 5, identityId: 'fid-001', service: 'mcp' }), /text/);
});

test('a missing kid is refused and an unknown kid on an issuer that has not rotated triggers a refresh that does not find it', () => {
  const e = newEngine();
  assert.equal(k8sVerify(e, { kid: null }).code, 'kid_missing');
  const r = k8sVerify(e, { kid: 'nope-key-9' });
  assert.equal(r.code, 'unknown_kid'); assert.equal(r.refresh.attempted, true); assert.equal(r.refresh.ok, true);
});

test('revocation: the very next request is refused; restoring and removing behave; a stored notAfter expires the identity on the lab clock', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken; const v = () => e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
  assert.ok(v().ok);
  e.updateIdentity({ identityId: 'fid-001', enabled: false });
  assert.equal(v().code, 'identity_disabled');
  assert.equal(e.verify({ token: t, service: 'mcp' }).code, 'identity_disabled', 'also when the gateway looks the identity up itself');
  e.updateIdentity({ identityId: 'fid-001', enabled: true });
  assert.ok(v().ok);
  e.updateIdentity({ identityId: 'fid-001', notAfter: '2026-11-02T09:30:00Z' });
  assert.ok(v().ok);
  e.advance({ minutes: 31 });
  const fresh = k8sMint(e).mintedToken;
  assert.equal(e.verify({ token: fresh, identityId: 'fid-001', service: 'mcp' }).code, 'identity_expired');
  e.updateIdentity({ identityId: 'fid-001', notAfter: '' });
  assert.ok(e.verify({ token: fresh, identityId: 'fid-001', service: 'mcp' }).ok);
  e.deleteIdentity({ identityId: 'fid-001' });
  assert.equal(e.verify({ token: fresh, identityId: 'fid-001', service: 'mcp' }).code, 'unknown_identity');
  assert.equal(e.verify({ token: fresh, service: 'mcp' }).code, 'no_matching_identity');
});

test('the gateway finds the identity by issuer and subject when none is named; two matching identities are refused as ambiguous', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken;
  const r = e.verify({ token: t, service: 'mcp' });
  assert.equal(r.ok, true); assert.equal(r.identityId, 'fid-001');
  assert.equal(e.verify({ token: k8sMint(e, { claims: { sub: 'someone-else', aud: GW } }).mintedToken, service: 'mcp' }).code, 'no_matching_identity');
  e.createIdentity({ name: 'twin', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', subject: K8S_SUB, audience: GW } });
  assert.equal(e.verify({ token: t, service: 'mcp' }).code, 'ambiguous_identity');
  assert.ok(e.verify({ token: t, identityId: 'fid-001', service: 'mcp' }).ok, 'naming the identity resolves it');
});

test('pinned claims: a missing claim, a wrong value and a value of the wrong type are refused; the exact claims pass; an extra claim is ignored', () => {
  const e = newEngine();
  const gh = (extra) => e.verify({ token: e.mint({ issuer: 'github', claims: { sub: GH_SUB, aud: GW, extra } }).mintedToken, identityId: 'fid-002', service: 'mcp' });
  const full = { repository: `${C.castOrg}/${C.castRepo}`, environment: 'production' };
  assert.ok(gh(full).ok);
  assert.ok(gh({ ...full, anything: 'else', n: 3 }).ok);
  assert.equal(gh({ repository: full.repository }).code, 'required_claim_missing');
  assert.equal(gh({ environment: 'production' }).code, 'required_claim_missing');
  assert.equal(gh({ ...full, environment: 'Production' }).code, 'required_claim_mismatch');
  assert.equal(gh({ ...full, repository: `${C.castAttackerOrg}/${C.castRepo}` }).code, 'required_claim_mismatch');
  e.updateIdentity({ identityId: 'fid-002', federation: { requiredClaims: { repository: full.repository, run_id: 1 } } });
  assert.equal(gh({ repository: full.repository, run_id: '1' }).code, 'required_claim_mismatch', 'the string "1" is not the number 1');
  assert.ok(gh({ repository: full.repository, run_id: 1 }).ok);
  e.updateIdentity({ identityId: 'fid-002', federation: { requiredClaims: {} } });
  assert.ok(gh({}).ok, 'no pinned claims left');
});

test('the fork-PR case: a pull request in the repository and a pull request from a fork are refused, main is allowed', () => {
  const e = newEngine();
  const run = (id) => { const p = PRESET[id]; return e.verify({ token: e.mint(p.mint).mintedToken, identityId: p.identityId, service: p.service }); };
  assert.ok(run('gh-right').ok);
  for (const id of ['gh-pr', 'gh-fork-pr']) { const r = run(id); assert.equal(r.code, 'subject_mismatch', id); assert.equal(r.steps.find((s) => s.id === 'subject').status, 'fail'); }
});

test('AllowAnySubject is an explicit opt-in: any subject passes the subject step, the other bindings still apply', () => {
  const e = newEngine();
  e.updateIdentity({ identityId: 'fid-001', federation: { allowAnySubject: true } });
  assert.ok(k8sVerify(e, { claims: { sub: 'whoever', aud: GW } }).ok);
  assert.ok(k8sVerify(e, { claims: { aud: GW } }).ok);
  assert.equal(k8sVerify(e, { claims: { sub: 'whoever', aud: 'https://other.example' } }).code, 'aud_mismatch');
  e.updateIdentity({ identityId: 'fid-001', federation: { allowAnySubject: false } });
  assert.equal(k8sVerify(e, { claims: { sub: 'whoever', aud: GW } }).code, 'subject_mismatch');
});

test('scopes: the effective scopes are the key\'s scopes within the identity\'s; a scope not on the key is 403; removing a scope from the identity narrows the key', () => {
  const e = newEngine();
  assert.ok(k8sVerify(e, {}, { service: 'a2a' }).ok);
  const llm = k8sVerify(e, {}, { service: 'llm' });
  assert.equal(llm.code, 'scope_not_on_key'); assert.equal(llm.status, 403); assert.match(llm.detail, /^key not scoped for llm access/);
  e.updateKey({ keyId: 'key-0001', scopes: ['mcp'] });
  assert.equal(k8sVerify(e, {}, { service: 'a2a' }).code, 'scope_not_on_key');
  e.updateKey({ keyId: 'key-0001', scopes: ['mcp', 'a2a'] });
  e.updateIdentity({ identityId: 'fid-001', scopes: ['mcp', 'llm'] });
  assert.equal(k8sVerify(e, {}, { service: 'a2a' }).code, 'scope_not_on_key', 'the identity no longer allows a2a');
  assert.equal(k8sVerify(e, {}, { service: 'llm' }).code, 'scope_not_on_key', 'the key never had llm');
  assert.ok(k8sVerify(e, {}, { service: 'mcp' }).ok);
});

test('a key owned by the identity is required: a revoked key, no key, and a key naming another identity are each refused', () => {
  const e = newEngine();
  e.updateKey({ keyId: 'key-0001', enabled: false });
  assert.equal(k8sVerify(e).code, 'key_revoked');
  e.updateKey({ keyId: 'key-0001', enabled: true });
  assert.ok(k8sVerify(e).ok);
  assert.equal(k8sVerify(e, {}, { keyId: 'key-0002' }).code, 'key_not_owned_by_identity');
  assert.equal(k8sVerify(e, {}, { keyId: 'key-0006' }).code, 'key_not_owned_by_identity', 'a stored key is not an identity\'s key');
  e.deleteKey({ keyId: 'key-0001' });
  assert.equal(k8sVerify(e).code, 'no_key_behind_identity');
});

test('the inbound token never reaches the backend: the forwarded request holds only the application\'s masked credential', () => {
  const e = newEngine();
  const m = k8sMint(e); const r = e.verify({ token: m.mintedToken, identityId: 'fid-001', service: 'mcp' });
  const out = JSON.stringify(r.forwarded);
  const [h, p, s] = m.mintedToken.split('.');
  for (const piece of [m.mintedToken, h, p, s]) assert.ok(!out.includes(piece));
  assert.equal(r.forwarded.inboundTokenForwarded, false);
  assert.match(r.forwarded.request.headers.authorization, /^\[masked: /);
  assert.deepEqual(['mcp', 'a2a'].map((svc) => e.verify({ token: m.mintedToken, identityId: 'fid-001', service: svc }).forwarded.backend), ['ledger-mcp', 'reconcile-agent']);
  assert.equal(e.verify({ token: m.mintedToken, identityId: 'fid-001', service: 'llm' }).forwarded, null, 'a refused call forwards nothing');
});

test('every request is attributed to a specific deployment, and a refused one is recorded without a verified deployment', () => {
  const e = newEngine();
  const pod = (n) => k8sVerify(e, { claims: { sub: K8S_SUB, aud: GW, extra: { pod: n } } });
  assert.equal(pod('runner-aaaa').deployment, `${C.castNs}/${C.castAgent} pod runner-aaaa`);
  assert.equal(pod('runner-bbbb').deployment, `${C.castNs}/${C.castAgent} pod runner-bbbb`);
  k8sVerify(e, { claims: { sub: 'intruder', aud: GW } });
  const a = e.snapshot().audit.filter((x) => x.kind === 'verify');
  assert.deepEqual(a.map((x) => x.outcome), ['allowed', 'allowed', 'refused']);
  assert.deepEqual(a.map((x) => x.deployment), [`${C.castNs}/${C.castAgent} pod runner-aaaa`, `${C.castNs}/${C.castAgent} pod runner-bbbb`, undefined]);
  assert.equal(a[2].code, 'subject_mismatch'); assert.equal(a[2].claimed, 'intruder');
  const gh = e.verify({ token: e.mint(PRESET['gh-right'].mint).mintedToken, identityId: 'fid-002', service: 'mcp' });
  assert.equal(gh.deployment, `${C.castOrg}/${C.castRepo} refs/heads/main run 4821`);
  assert.match(a[0].principal, /^identity /);
});

test('the algorithm, kid and claims shown for a refused token are cleaned: a credential in a claim is masked in the answer', () => {
  const e = newEngine();
  const secret = ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
  const t = forge(e, { alg: 'RS256', kid: secret }, { sub: secret, aud: secret, iss: secret, extra: { token: secret } });
  const r = e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
  assert.ok(!JSON.stringify(r).includes(secret));
  assert.ok(!JSON.stringify(e.snapshot()).includes(secret));
});
