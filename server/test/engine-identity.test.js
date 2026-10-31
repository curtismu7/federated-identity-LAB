import test from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/engine.js';
import { C, GW, K8S_SUB, codeOf, k8sMint, k8sVerify, newEngine, statusOf } from './helpers.js';

const PAT = ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
const URI = 'https://kube-api.cluster-a.example/openid/v1/jwks';
const plain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const base = (over = {}) => ({ name: 'new identity', scopes: ['mcp'], platform: 'kubernetes', federation: over.federation !== undefined && !plain(over.federation) ? over.federation : { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'system:serviceaccount:x:y', audience: GW, ...(over.federation || {}) }, ...Object.fromEntries(Object.entries(over).filter(([k]) => k !== 'federation')) });
const snap = (e, id) => e.snapshot().identities.find((i) => i.id === id);

test('creating an identity: audience and subject are mandatory (exact binding), and the identity gets the next id', () => {
  const e = newEngine();
  const n = e.snapshot().identities.length;
  assert.equal(codeOf(() => e.createIdentity(base({ federation: { audience: undefined } }))), 'audience_required');
  assert.equal(codeOf(() => e.createIdentity(base({ federation: { audience: '' } }))), 'audience_required');
  assert.equal(codeOf(() => e.createIdentity(base({ federation: { subject: undefined } }))), 'subject_required');
  assert.equal(codeOf(() => e.createIdentity(base({ federation: { subject: '' } }))), 'subject_required');
  assert.equal(e.snapshot().identities.length, n);
  const made = e.createIdentity(base());
  assert.equal(made.identityId, `fid-${String(n + 1).padStart(3, '0')}`);
  assert.equal(snap(e, made.identityId).enabled, true);
  assert.ok(e.createIdentity(base({ federation: { allowAnySubject: true, subject: undefined } })).identityId, 'any subject only by explicit opt-in');
});

test('every field of an identity is validated: type, form and length; nothing is created by a refused call', () => {
  const e = newEngine(); const n = e.snapshot().identities.length;
  const bad = {
    bad_name: [{ name: 5 }, { name: '' }, { name: '   ' }], bad_description: [{ description: 5 }], bad_platform: [{ platform: 'windows' }, { platform: '__proto__' }],
    bad_scopes: [{ scopes: [] }, { scopes: ['root'] }, { scopes: ['mcp', 'mcp'] }, { scopes: 'mcp' }, { scopes: ['mcp', 'a2a', 'llm', 'shadowai:write', 'policy:read', 'x'] }],
    bad_not_after: [{ notAfter: 'tomorrow' }, { notAfter: '2026-11-03' }, { notAfter: '2026-13-45T00:00:00Z' }, { notAfter: 5 }], bad_enabled: [{ enabled: 'yes' }],
    bad_issuer: [{ federation: { issuer: 'http://kube-api.cluster-a.example' } }, { federation: { issuer: 'https://real-host.com' } }, { federation: { issuer: 5 } }, { federation: { issuer: `https://a.example/${PAT}` } }],
    bad_jwks_uri: [{ federation: { jwksUri: 'http://x.example/jwks' } }, { federation: { jwksUri: 5 } }],
    bad_lifetime: [{ federation: { maxTokenLifetimeSec: -1 } }, { federation: { maxTokenLifetimeSec: 86401 } }, { federation: { maxTokenLifetimeSec: 1.5 } }, { federation: { maxTokenLifetimeSec: '3600' } }],
    bad_claims: [{ federation: { requiredClaims: { sub: 'x' } } }, { federation: { requiredClaims: { exp: 1 } } }, { federation: { requiredClaims: { ['__proto__']: 'x' } } }, { federation: { requiredClaims: { a: { n: 1 } } } }, { federation: { requiredClaims: { 'bad name': 'x' } } }, { federation: { requiredClaims: [] } },
      { federation: { requiredClaims: Object.fromEntries(Array.from({ length: LIMITS.requiredClaims + 1 }, (_, i) => [`c${i}`, 'v'])) } }],
    bad_federation: [{ federation: 'x' }, { federation: null }, { federation: [] }], unknown_field: [{ surprise: 1 }, { federation: { surprise: 1 } }, { kind: 'self-hosted-agent' }],
    bad_subject: [{ federation: { allowAnySubject: 'yes' } }], audience_required: [{ federation: { audience: 'has space' } }, { federation: { audience: 'x'.repeat(201) } }], subject_required: [{ federation: { subject: 'a b' } }, { federation: { subject: 5 } }],
  };
  for (const [code, list] of Object.entries(bad)) for (const over of list) assert.equal(codeOf(() => e.createIdentity(base(over))), code, `${code}: ${JSON.stringify(over).slice(0, 80)}`);
  assert.equal(e.snapshot().identities.length, n);
  assert.equal(codeOf(() => e.createIdentity(null)), 'unknown_field');
  assert.equal(codeOf(() => e.createIdentity({ __bad: 1 })), 'unknown_field');
});

test('a stored value that looks like a credential is refused, never echoed; a SPIFFE-length subject is fine', () => {
  const e = newEngine();
  const secret = ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
  for (const federation of [{ subject: secret }, { audience: secret }, { subject: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz' }, { subject: 'deadbeef'.repeat(6) }, { requiredClaims: { repository: secret } }]) {
    let msg = ''; try { e.createIdentity(base({ federation })); } catch (err) { msg = JSON.stringify([err.code, err.message]); }
    assert.ok(msg, 'refused'); assert.ok(!msg.includes(secret) && !msg.includes('QUJDRE') && !msg.includes('deadbeef'));
  }
  assert.ok(e.createIdentity(base({ federation: { subject: 'spiffe://trust.example/ns/payments/sa/agent-runner-with-a-long-name' } })).identityId);
});

test('every editable field of an identity is applied by an update, and an update is checked as a whole', () => {
  const e = newEngine();
  const up = (patch) => e.updateIdentity({ identityId: 'fid-001', ...patch });
  up({ name: 'renamed' }); assert.equal(snap(e, 'fid-001').name, 'renamed');
  up({ description: 'a new description' }); assert.equal(snap(e, 'fid-001').description, 'a new description');
  up({ platform: 'spiffe' }); assert.equal(snap(e, 'fid-001').platform, 'spiffe');
  up({ scopes: ['mcp'] }); assert.deepEqual(snap(e, 'fid-001').scopes, ['mcp']);
  up({ notAfter: '2026-11-02T09:05:00Z' }); assert.equal(snap(e, 'fid-001').notAfter, '2026-11-02T09:05:00Z');
  up({ notAfter: '' }); assert.equal(snap(e, 'fid-001').notAfter, '');
  up({ enabled: false }); assert.equal(snap(e, 'fid-001').enabled, false); up({ enabled: true });
  up({ federation: { subject: 'system:serviceaccount:x:y' } }); assert.equal(snap(e, 'fid-001').federation.subject, 'system:serviceaccount:x:y');
  assert.equal(k8sVerify(e).code, 'subject_mismatch', 'the new subject is enforced');
  up({ federation: { subject: K8S_SUB, audience: 'https://other.example' } });
  assert.equal(k8sVerify(e).code, 'aud_mismatch', 'the new audience is enforced');
  up({ federation: { audience: GW, issuer: 'https://gitlab.ci.example', jwksUri: 'https://gitlab.ci.example/oauth/discovery/keys' } });
  assert.equal(k8sVerify(e).code, 'issuer_mismatch', 'the new issuer is enforced');
  assert.deepEqual(snap(e, 'fid-001').keyset.kids, ['gitlab-key-1'], 'and its key set was fetched');
  up({ federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI } });
  assert.ok(k8sVerify(e).ok);
  assert.equal(codeOf(() => up({ scopes: ['bogus'] })), 'bad_scopes');
  assert.equal(codeOf(() => up({ federation: { audience: '' } })), 'audience_required');
  assert.equal(snap(e, 'fid-001').federation.audience, GW, 'a refused update changes nothing');
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 'nope', name: 'x' })), 'unknown_identity');
  assert.equal(statusOf(() => e.updateIdentity({ identityId: '__proto__', name: 'x' })), 404);
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 5, name: 'x' })), 'unknown_identity');
  assert.equal(codeOf(() => e.updateIdentity({ identityId: 'fid-001', federation: 'x' })), 'bad_federation');
});

test('an identity cap refuses the whole request; ids are never reused', () => {
  const e = newEngine();
  while (e.snapshot().identities.length < LIMITS.identities) e.createIdentity(base());
  assert.equal(codeOf(() => e.createIdentity(base())), 'workspace_full');
  e.deleteIdentity({ identityId: 'fid-002' });
  assert.equal(e.createIdentity(base()).identityId, `fid-${String(LIMITS.identities + 1).padStart(3, '0')}`);
});

test('keys: a key owned by an identity, the two measured refusals, narrowing only, unknown owners, and the person-owned form', () => {
  const e = newEngine();
  const ok = e.createKey({ name: 'narrow', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] });
  assert.equal(e.snapshot().keys.find((k) => k.id === ok.keyId).principalLabel.startsWith('identity '), true);
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], ownFederation: true })), 'mutually_exclusive');
  assert.equal(statusOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], ownFederation: true })), 409);
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], userRef: C.castOwner })), 'principal_conflict');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-002' }, scopes: ['a2a'] })), 'scope_not_on_identity');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'nope' }, scopes: ['mcp'] })), 'unknown_identity');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'human', ref: 'nobody' }, scopes: ['mcp'] })), 'unknown_person');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'human', ref: C.castOwner }, scopes: ['mcp'], ownFederation: true })), 'not_modelled');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'human', ref: C.castOwner }, scopes: ['mcp'], userRef: 'x' })), 'bad_owner');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'machine', ref: 'x' }, scopes: ['mcp'] })), 'bad_owner');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: 'fid-001', scopes: ['mcp'] })), 'bad_owner');
  assert.equal(codeOf(() => e.createKey({ name: '', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] })), 'bad_name');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-001' }, scopes: [] })), 'bad_scopes');
  assert.equal(codeOf(() => e.createKey({ name: 'x', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], extra: 1 })), 'unknown_field');
  assert.ok(e.createKey({ name: 'person', owner: { kind: 'human', ref: C.castOwner2 }, scopes: ['llm'] }).keyId);
});

test('every editable field of a key is applied: enabled, scopes (within the identity), and removal', () => {
  const e = newEngine();
  e.updateKey({ keyId: 'key-0001', enabled: false }); assert.equal(e.snapshot().keys[0].enabled, false); assert.equal(k8sVerify(e).code, 'key_revoked');
  e.updateKey({ keyId: 'key-0001', enabled: true, scopes: ['mcp'] }); assert.deepEqual(e.snapshot().keys[0].scopes, ['mcp']);
  e.updateKey({ keyId: 'key-0001', scopes: ['llm'] }); assert.ok(k8sVerify(e, {}, { service: 'llm' }).ok, 'a scope within the identity can be added to the key');
  e.updateKey({ keyId: 'key-0001', scopes: ['mcp', 'a2a', 'llm'] });
  assert.deepEqual(e.snapshot().keys[0].effectiveScopes, ['mcp', 'a2a', 'llm']);
  assert.equal(codeOf(() => e.updateKey({ keyId: 'key-0001', scopes: ['shadowai:write'] })), 'scope_not_on_identity');
  assert.equal(codeOf(() => e.updateKey({ keyId: 'nope' })), 'unknown_key');
  assert.equal(codeOf(() => e.updateKey({ keyId: 'key-0001', enabled: 'no' })), 'bad_enabled');
  e.deleteKey({ keyId: 'key-0001' }); assert.equal(e.snapshot().keys.some((k) => k.id === 'key-0001'), false);
  assert.equal(codeOf(() => e.deleteKey({ keyId: 'key-0001' })), 'unknown_key');
  while (e.snapshot().keys.length < LIMITS.keys) e.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-002' }, scopes: ['mcp'] });
  assert.equal(codeOf(() => e.createKey({ name: 'k', owner: { kind: 'identity', ref: 'fid-002' }, scopes: ['mcp'] })), 'workspace_full');
});

test('removing an identity leaves its keys naming nobody; they authenticate nothing', () => {
  const e = newEngine();
  e.deleteIdentity({ identityId: 'fid-001' });
  const k = e.snapshot().keys.find((x) => x.id === 'key-0001');
  assert.equal(k.ownerMissing, true); assert.equal(k.principalLabel, 'identity (removed)');
  assert.equal(codeOf(() => e.deleteIdentity({ identityId: 'fid-001' })), 'unknown_identity');
});

test('a key owned by a person stops when the person is inactive; a key owned by an identity does not; both are attributed to their own principal', () => {
  const e = newEngine();
  const call = (service = 'mcp') => e.storedKeyCall({ keyId: 'key-0006', service });
  const ok = call(); assert.equal(ok.ok, true); assert.equal(ok.principal, `person ${C.castOwner} (borrowed)`); assert.equal(ok.forwarded.backend, 'ledger-mcp');
  assert.equal(call('a2a').code, 'scope_not_on_key'); assert.equal(call('a2a').status, 403);
  assert.equal(call('llm').ok, true);
  e.setPerson({ person: C.castOwner, active: false });
  const r = call(); assert.equal(r.code, 'owner_inactive'); assert.equal(r.status, 401);
  assert.ok(k8sVerify(e).ok, 'the identity-owned key is unaffected');
  e.setPerson({ person: C.castOwner, active: true }); assert.equal(call().ok, true);
  e.updateKey({ keyId: 'key-0006', enabled: false }); assert.equal(call().code, 'key_revoked');
  assert.equal(codeOf(() => e.storedKeyCall({ keyId: 'key-0001', service: 'mcp' })), 'not_a_stored_key');
  assert.equal(codeOf(() => e.storedKeyCall({ keyId: 'key-0006', service: 'x' })), 'bad_service');
  assert.equal(codeOf(() => e.storedKeyCall({ keyId: 'nope', service: 'mcp' })), 'unknown_key');
  assert.equal(codeOf(() => e.setPerson({ person: 'nobody', active: true })), 'unknown_person');
  assert.equal(codeOf(() => e.setPerson({ person: C.castOwner, active: 'no' })), 'bad_active');
  const kinds = e.snapshot().audit.filter((a) => a.kind === 'stored-key').map((a) => `${a.outcome}:${a.principal}`);
  assert.ok(kinds.every((x) => x.includes(`person ${C.castOwner}`)));
});

test('the audit log is a ring of 500: the oldest entry is dropped and counted, never hidden', () => {
  const e = newEngine();
  const t = k8sMint(e).mintedToken;
  for (let i = 0; i < LIMITS.audit + 20; i++) e.verify({ token: t, identityId: 'fid-001', service: 'mcp' });
  const s = e.snapshot();
  assert.equal(s.audit.length, LIMITS.audit);
  assert.ok(s.auditDropped >= 20);
  assert.equal(s.audit[0].n, s.auditDropped + 1);
});

test('reset returns to the seeded world: the clock, issuers, identities, keys and audit', () => {
  const e = newEngine(); const fresh = JSON.stringify(e.snapshot());
  e.advance({ minutes: 30 }); e.issuerAction({ issuer: 'kube', action: 'rotate' }); e.updateIdentity({ identityId: 'fid-001', enabled: false }); e.enrollSensor({});
  assert.notEqual(JSON.stringify(e.snapshot()), fresh);
  e.reset();
  assert.equal(JSON.stringify(e.snapshot()), fresh);
});

test('two engines are independent, and the seeded world is the same for each', () => {
  const a = newEngine(); const b = newEngine();
  a.updateIdentity({ identityId: 'fid-001', enabled: false });
  assert.equal(b.snapshot().identities[0].enabled, true);
  assert.equal(JSON.stringify(newEngine().snapshot()), JSON.stringify(newEngine().snapshot()));
});
