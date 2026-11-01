import test from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/engine.js';
import { C, GW, K8S_SUB, PRESET, codeOf, k8sMint, k8sVerify, newEngine } from './helpers.js';

const snapId = (e, id) => e.snapshot().identities.find((i) => i.id === id);
const priv = (e, over = {}) => e.mint({ issuer: 'private', claims: { sub: `agent:${C.castAgent}`, aud: GW }, ...over }).mintedToken;
const vPriv = (e, t) => e.verify({ token: t, identityId: 'fid-005', service: 'mcp' });

test('an unknown signing key triggers a refresh, and then the token verifies (the issuer rotated)', () => {
  const e = newEngine();
  e.issuerAction({ issuer: 'kube', action: 'rotate' });
  const r = k8sVerify(e);
  assert.equal(r.ok, true); assert.equal(r.refresh.attempted, true); assert.equal(r.refresh.ok, true);
  assert.match(r.steps.find((s) => s.id === 'keyset').detail, /refreshed on sight of the unknown kid/);
  assert.deepEqual(snapId(e, 'fid-001').keyset.kids, ['kube-key-2']);
  assert.equal(k8sVerify(e).refresh, null, 'the second token finds its key: no refresh');
  assert.ok(e.snapshot().audit.some((a) => a.kind === 'verify' && /unknown kid: the key set was refreshed \(ok\)/.test(a.note || '')), 'one verify entry records the refresh; there is no second entry');
});

test('a token signed by a retired key is refused after the refresh: the key is no longer published', () => {
  const e = newEngine();
  const old = k8sMint(e).mintedToken;
  e.issuerAction({ issuer: 'kube', action: 'rotate' });
  assert.ok(e.verify({ token: old, identityId: 'fid-001', service: 'mcp' }).ok, 'until the gateway refreshes, its cached set still holds the old key');
  assert.ok(k8sVerify(e).ok, 'a token with the new key triggers the refresh');
  const r = e.verify({ token: old, identityId: 'fid-001', service: 'mcp' });
  assert.equal(r.code, 'unknown_kid'); assert.equal(r.refresh.attempted, false); assert.equal(r.refresh.cooledDown, true, 'the refresh a lab second ago is within the cooldown');
  e.advance({ minutes: 1 });
  const r2 = e.verify({ token: old, identityId: 'fid-001', service: 'mcp' });
  assert.equal(r2.code, 'unknown_kid'); assert.equal(r2.refresh.attempted, true, 'after the cooldown the gateway refreshes again and still does not find the retired key');
});

test('retireOld false keeps the old key published beside the new one: both verify', () => {
  const e = newEngine();
  const out = e.issuerAction({ issuer: 'kube', action: 'rotate', retireOld: false });
  assert.deepEqual(out.published, ['kube-key-1', 'kube-key-2']);
  assert.ok(e.verify({ token: k8sMint(e, { generation: 0 }).mintedToken, identityId: 'fid-001', service: 'mcp' }).ok);
  assert.ok(k8sVerify(e).ok);
});

test('issuer outage: a key the gateway already holds keeps working (last known good); an unknown kid cannot be resolved; recovery resolves it', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken; const v = (x = t) => e.verify({ token: x, identityId: 'fid-001', service: 'mcp' });
  e.issuerAction({ issuer: 'kube', action: 'down' });
  assert.ok(v().ok, 'verifies from the cached set while the issuer is down');
  e.issuerAction({ issuer: 'kube', action: 'rotate' });
  const fresh = k8sMint(e).mintedToken;
  const bad = v(fresh);
  assert.equal(bad.code, 'unknown_kid'); assert.equal(bad.refresh.ok, false);
  assert.match(bad.detail, /kept the last known good set/);
  assert.deepEqual(snapId(e, 'fid-001').keyset.kids, ['kube-key-1'], 'the last known good set is kept');
  assert.ok(v().ok, 'the old key still verifies');
  e.issuerAction({ issuer: 'kube', action: 'up' });
  assert.equal(v(fresh).code, 'unknown_kid', 'within the cooldown the gateway does not try again');
  e.advance({ minutes: 1 });
  assert.ok(v(fresh).ok); assert.deepEqual(snapId(e, 'fid-001').keyset.kids, ['kube-key-2']);
});

test('scheduled refresh: every fifteen lab minutes, not before; a refresh that fails keeps the set and tries again fifteen minutes later', () => {
  const e = newEngine();
  const n = () => snapId(e, 'fid-001').keyset.log.length;
  assert.equal(n(), 1, 'validated when created');
  e.advance({ minutes: 14 }); assert.equal(n(), 1);
  e.advance({ minutes: 1 }); assert.equal(n(), 2);
  assert.equal(snapId(e, 'fid-001').keyset.last.reason, 'scheduled (every 15 lab minutes)');
  e.issuerAction({ issuer: 'kube', action: 'down' });
  e.advance({ minutes: 15 });
  const last = snapId(e, 'fid-001').keyset.last;
  assert.equal(last.ok, false); assert.equal(last.kept, true); assert.equal(n(), 3);
  assert.equal(snapId(e, 'fid-001').keyset.nextRefreshAt, '2026-11-02T09:45:00.000Z');
  e.advance({ minutes: 14 }); assert.equal(n(), 3);
  e.issuerAction({ issuer: 'kube', action: 'up' });
  e.advance({ minutes: 1 }); assert.equal(snapId(e, 'fid-001').keyset.last.ok, true);
  e.issuerAction({ issuer: 'kube', action: 'rotate' });
  e.advance({ minutes: 15 });
  assert.deepEqual(snapId(e, 'fid-001').keyset.kids, ['kube-key-2'], 'the scheduled refresh picked up the rotation');
  assert.ok(k8sVerify(e).refresh === null, 'so a new token needs no refresh');
  const summary = e.snapshot().audit.filter((a) => a.kind === 'clock.advanced').at(-1);
  assert.match(summary.note, /fid-00\d: 1 ok, 0 failed/);
});

test('the refresh log keeps its newest twenty entries', () => {
  const e = newEngine();
  for (let i = 0; i < 4; i++) e.advance({ minutes: LIMITS.clockPerMoveMin });
  assert.equal(snapId(e, 'fid-001').keyset.log.length, LIMITS.refreshLog);
});

test('a pinned private issuer: nothing to refresh, an unknown kid cannot be resolved, re-pinning the issuer\'s current keys fixes it', () => {
  const e = newEngine();
  assert.ok(vPriv(e, priv(e)).ok);
  assert.equal(snapId(e, 'fid-005').keyset.source, 'pinned'); assert.equal(snapId(e, 'fid-005').keyset.nextRefreshAt, null);
  e.issuerAction({ issuer: 'private', action: 'rotate' });
  const t = priv(e);
  const r = vPriv(e, t);
  assert.equal(r.code, 'unknown_kid'); assert.equal(r.refresh, null, 'no address to refresh from'); assert.match(r.detail, /pins its keys/);
  e.advance({ minutes: 30 });
  assert.equal(snapId(e, 'fid-005').keyset.log.length, 1, 'a pinned set is never refreshed');
  assert.equal(codeOf(() => e.refreshKeys({ identityId: 'fid-005' })), 'nothing_to_refresh');
  e.updateIdentity({ identityId: 'fid-005', federation: { pinFromIssuer: 'private' } });
  assert.deepEqual(snapId(e, 'fid-005').keyset.kids, ['private-key-2']);
  assert.ok(vPriv(e, t).ok);
});

test('a pasted JWKS: public RSA keys are accepted; private material, a non-RSA key, a missing kid, junk and an oversize set are refused', () => {
  const e = newEngine();
  const pub = e.publishedJwks('private'); const make = (jwks) => ({ name: 'pasted', scopes: ['mcp'], platform: 'oidc', federation: { issuer: 'https://issuer.private.example', subject: 'agent:x', audience: GW, jwks } });
  assert.ok(e.createIdentity(make(pub)).identityId);
  assert.ok(e.createIdentity(make({ keys: pub })).identityId, 'a JWKS document with keys is accepted');
  assert.equal(codeOf(() => e.createIdentity(make([{ ...pub[0], d: 'AAAA' }]))), 'jwks_private_material');
  assert.equal(codeOf(() => e.createIdentity(make([{ ...pub[0], p: 'AAAA' }]))), 'jwks_private_material');
  assert.equal(codeOf(() => e.createIdentity(make([{ ...pub[0], kty: 'EC' }]))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(make([{ kty: 'RSA', n: pub[0].n, e: pub[0].e }]))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(make([{ ...pub[0], n: '!!!' }]))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(make([]))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(make(Array.from({ length: 5 }, (_, i) => ({ ...pub[0], kid: `k${i}` }))))), 'jwks_invalid');
  assert.equal(codeOf(() => e.createIdentity(make([pub[0], pub[0]]))), 'jwks_invalid', 'duplicate kids');
  assert.equal(codeOf(() => e.createIdentity(make('keys'))), 'jwks_invalid');
});

test('the key set is validated when the identity is created: an issuer that is down or an address the lab does not know refuses the creation and creates nothing', () => {
  const e = newEngine();
  const make = (federation) => ({ name: 'new', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', subject: 'a:b', audience: GW, ...federation } });
  const before = e.snapshot().identities.length;
  e.issuerAction({ issuer: 'kube', action: 'down' });
  assert.equal(codeOf(() => e.createIdentity(make({ jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks' }))), 'jwks_unreachable');
  e.issuerAction({ issuer: 'kube', action: 'up' });
  assert.equal(codeOf(() => e.createIdentity(make({ jwksUri: 'https://nowhere.example/jwks' }))), 'jwks_unreachable', 'the lab fetches nothing from the network');
  assert.equal(codeOf(() => e.createIdentity(make({}))), 'jwks_required');
  assert.equal(e.snapshot().identities.length, before, 'nothing was created');
  assert.ok(e.createIdentity(make({ jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks' })).identityId);
  // the pinned set is the fallback when the address is unreachable at creation
  e.issuerAction({ issuer: 'kube', action: 'down' });
  const made = e.createIdentity(make({ jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', pinFromIssuer: 'kube' }));
  assert.equal(snapId(e, made.identityId).keyset.source, 'pinned');
});

test('a change that needs a key set fails when it cannot be fetched and changes nothing; revoking needs no fetch, so it works during an outage', () => {
  const e = newEngine();
  e.issuerAction({ issuer: 'kube', action: 'down' });
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 'fid-001', federation: { jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', issuer: 'https://kube-api.cluster-a.example' } })), null, 'unchanged key-set settings need no fetch');
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 'fid-003', federation: { jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', issuer: 'https://kube-api.cluster-a.example' } })), 'jwks_unreachable');
  assert.equal(snapId(e, 'fid-003').federation.issuer, 'https://gitlab.ci.example', 'unchanged after the refusal');
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 'fid-001', enabled: false })), null);
});

test('the lab clock: forward only, whole minutes, capped per move and in total; a refused move changes nothing', () => {
  const e = newEngine();
  for (const m of [0, -5, 1.5, '10', null, undefined, NaN]) assert.ok(codeOf(() => e.advance({ minutes: m })), String(m));
  assert.equal(codeOf(() => e.advance({ minutes: -1 })), 'clock_forward_only');
  assert.equal(codeOf(() => e.advance({ minutes: LIMITS.clockPerMoveMin + 1 })), 'clock_move_too_big');
  assert.equal(codeOf(() => e.advance({ minutes: 5, extra: 1 })), 'unknown_field');
  assert.equal(e.snapshot().clock.advancedMin, 0);
  assert.equal(e.advance({ minutes: LIMITS.clockPerMoveMin }).advancedMin, LIMITS.clockPerMoveMin);
  while (e.snapshot().clock.advancedMin + LIMITS.clockPerMoveMin <= LIMITS.clockTotalMin) e.advance({ minutes: LIMITS.clockPerMoveMin });
  const before = e.snapshot().clock.now;
  assert.equal(codeOf(() => e.advance({ minutes: LIMITS.clockPerMoveMin })), 'clock_limit');
  assert.equal(e.snapshot().clock.now, before);
});

test('the clock moves a token to expiry: allowed at 59 minutes, expired at 60', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken; const v = () => e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
  e.advance({ minutes: 59 }); assert.ok(v().ok);
  e.advance({ minutes: 1 }); assert.equal(v().code, 'expired');
});

test('issuers: unknown issuer or action, a rotation limit, down and up flags', () => {
  const e = newEngine();
  assert.equal(codeOf(() => e.issuerAction({ issuer: 'nope', action: 'down' })), 'unknown_issuer');
  assert.equal(codeOf(() => e.issuerAction({ issuer: '__proto__', action: 'down' })), 'unknown_issuer');
  assert.equal(codeOf(() => e.issuerAction({ issuer: 'kube', action: 'explode' })), 'bad_action');
  assert.equal(codeOf(() => e.issuerAction({ issuer: 'kube', action: 'rotate', retireOld: 'yes' })), 'bad_retire');
  for (let i = 0; i < 5; i++) e.issuerAction({ issuer: 'kube', action: 'rotate' });
  assert.equal(codeOf(() => e.issuerAction({ issuer: 'kube', action: 'rotate' })), 'rotation_limit');
  e.issuerAction({ issuer: 'kube', action: 'down' });
  assert.equal(e.snapshot().issuers[0].up, false); assert.equal(e.snapshot().issuers[0].rotationsLeft, 0);
});

test('minting: only a generation the issuer has used; attacker keys; a kid override; no secret key material in any answer', () => {
  const e = newEngine();
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', generation: 1 })), 'bad_generation');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', generation: -1 })), 'bad_generation');
  assert.equal(codeOf(() => e.mint({ issuer: 'nope' })), 'bad_issuer');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', alg: 'RS512' })), 'bad_alg');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', times: { exp: 1e12 } })), 'bad_times');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', times: { exp: 1.5 } })), 'bad_times');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { extra: { iss: 'x' } } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { extra: { __proto__x: 'x', ['__proto__']: 'y' } } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { extra: Object.fromEntries(Array.from({ length: LIMITS.extraClaims + 1 }, (_, i) => [`c${i}`, 1])) } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { extra: { a: { nested: 1 } } } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { aud: Array.from({ length: 6 }, () => 'x') } })), 'bad_claims');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', kid: 'has space' })), 'bad_kid');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', oops: 1 })), 'unknown_field');
  assert.equal(codeOf(() => e.mint({ issuer: 'kube', claims: { sub: 'ab '.repeat(52).trim(), extra: Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`c${i}`, 'ab '.repeat(52).trim()])), aud: Array.from({ length: 5 }, () => 'ab '.repeat(52).trim()) } })), 'token_too_large');
  const m = e.mint({ issuer: 'attacker', kid: 'kube-key-1' });
  assert.equal(m.header.kid, 'kube-key-1'); assert.equal(m.claims.iss, 'https://attacker.invalid');
  const text = JSON.stringify([m, e.snapshot()]);
  assert.ok(!/"d":|"p":|"q":|BEGIN [A-Z ]*PRIVATE/.test(text));
  assert.ok(!/"n":"[A-Za-z0-9_-]{100,}"/.test(JSON.stringify(e.snapshot())), 'not even a public modulus is in the state');
});

test('time claims are relative to the lab clock and move with it', () => {
  const e = newEngine();
  const a = e.mint({ issuer: 'kube' }).claims; e.advance({ minutes: 10 }); const b = e.mint({ issuer: 'kube' }).claims;
  assert.equal(b.iat - a.iat, 600); assert.equal(b.exp - b.iat, 3600);
  assert.equal(e.mint({ issuer: 'kube', times: { nbf: -30 } }).claims.nbf, b.iat - 30);
  assert.ok(!('nbf' in b));
});
