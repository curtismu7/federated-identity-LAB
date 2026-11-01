// The Federated Identity engine: an in-process model of the gateway side of platform-issued tokens, with REAL crypto. Five mock issuers each hold an RSA key
// and publish a JWKS; a Federated Identity binds one issuer, one subject and one audience exactly; the gateway verifies the visitor's token (real RS256 on
// node:crypto) step by step and says exactly why it refused. Self-Hosted Agents: a Kubernetes sensor enrolled as its own principal whose reports are verified,
// with the reporting node taken from the token's claims, and an enforcement policy with modes and actions.
// One Engine per workspace and vertical. No I/O and no network. Time is a lab clock that only moves forward, by an explicit capped move; randomness (the
// audience Privilege generates at enrolment) comes from an injectable source, so the Mock tables are generated deterministically from this same engine.
// Every writer is synchronous, so a check and its change never interleave with another request.
import crypto from 'node:crypto';
import {
  ASYMMETRIC_ALGS, ATTACKER, ATTACKER_SLOT, BASE_SECONDS, DEFAULT_MAX_LIFETIME, FINDING_KINDS, HUMAN_ID_KEYS, ISSUER, ISSUERS, MINT_ALGS, PLATFORMS, POLICY_ACTIONS,
  POLICY_MODES, REFRESH_SECONDS, SCOPES, SERVICE_SCOPES, SYMMETRIC_ALGS, backends, seedIdentities,
} from './catalog.js';
import { GENERATIONS, keyAt } from './keys.js';
import { b64u, jwkProblem, parseToken, signHS256, signRS256, signingInput, verifyRS256 } from './jwt.js';
import { cleanFree, findCredentials } from './credentials.js';
import { cleanClaims, credentialProblem, oddities, show } from './clean.js';
import { formatTraceparent } from './trace.js';
import { refuse } from './errors.js';

export const LIMITS = {
  identities: 12, keys: 20, auditChanges: 300, auditRequests: 300, auditRefusals: 200, unknownKidCooldownSec: 60, findings: 200, reports: 50, sensors: 5, extraClaims: 12, claimText: 160, name: 60, description: 200, refreshLog: 20,
  hops: 40, requiredClaims: 6, scopes: 5, pinnedKeys: 4, clockPerMoveMin: 180, clockTotalMin: 10080, findingsPerReport: 10, namespaces: 5, audienceValues: 5,
};
export const STEPS = [
  { id: 'parse', title: 'Parse the token' },
  { id: 'identity', title: 'Find the Federated Identity; it is enabled and unexpired' },
  { id: 'alg', title: 'Algorithm is on the asymmetric allow-list (never none, never HS*)' },
  { id: 'issuer', title: 'Issuer matches exactly' },
  { id: 'keyset', title: 'Signing key is in the key set (refresh on an unknown kid)' },
  { id: 'signature', title: 'RS256 signature verifies' },
  { id: 'expiry', title: 'Expiry is present and has not passed' },
  { id: 'notbefore', title: 'Not-before has been reached' },
  { id: 'issued', title: 'Issued-at is present and not in the future' },
  { id: 'lifetime', title: 'Lifetime (exp minus iat) is within the cap' },
  { id: 'audience', title: 'Audience is present and exact' },
  { id: 'subject', title: 'Subject matches exactly' },
  { id: 'claims', title: 'Pinned claims match exactly' },
  { id: 'key', title: 'A key owned by this identity is usable' },
  { id: 'scope', title: 'The scope is on the key' },
];
const STATUS_TEXT = { 401: '401 Unauthorized', 403: '403 Forbidden', 404: '404 Not Found' };

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const pad = (n, w = 4) => String(n).padStart(w, '0');
const need = (cond, code, msg, status = 400) => { if (!cond) throw refuse(code, msg, status); };
const strictKeys = (o, allowed, what = 'the call') => { need(isObj(o) && Object.keys(o).every((k) => allowed.includes(k)), 'unknown_field', `${what} carries a field the lab does not take`); };
const iso = (sec) => new Date(sec * 1000).toISOString();
// A stored value is refused (never echoed) if it looks like a credential. The generic long-blob detector would reject a legitimate SPIFFE ID, so for stored values a
// "blob" is a run of 24 or more letters, digits, + _ = with no separator; this is a heuristic, and README says so.
const credentialShaped = (s) => findCredentials(s).some((x) => x.id !== 'long-blob') || /[A-Za-z0-9+_=]{24,}/.test(s);

// Strict forms for values the engine STORES and shows. A value outside the form, or credential-shaped, is refused without being echoed.
const SAFE_URL = /^https:\/\/[a-z0-9](?:[a-z0-9.-]{0,60}[a-z0-9])?\.(?:example|invalid)(?:\/[A-Za-z0-9._~/-]{0,100})?$/;
const SAFE_VALUE = /^[A-Za-z0-9:/._@=#+,-]{1,200}$/;
const SAFE_NAME = /^[A-Za-z0-9 ._:/-]{1,60}$/;
const K8S_NAME = /^[a-z0-9](?:[a-z0-9.-]{0,60}[a-z0-9])?$/;
const CLAIM_NAME = /^[A-Za-z0-9_.:/-]{1,40}$/;
const KID = /^[A-Za-z0-9._:-]{1,60}$/;
const RESERVED_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', '__proto__', 'constructor', 'prototype', 'mintedToken', 'traceparent', 'traceId']);
const RFC3339_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const strictValue = (v, re, code, msg) => need(typeof v === 'string' && re.test(v) && !credentialShaped(v), code, msg);
const uniqueStrings = (arr, allowed, max) => Array.isArray(arr) && arr.length >= 1 && arr.length <= max && new Set(arr).size === arr.length && arr.every((x) => typeof x === 'string' && allowed.includes(x));

export class Engine {
  constructor(cast, { rand = (n) => crypto.randomBytes(n) } = {}) {
    this.cast = cast; this.rand = rand;
    this.trace = null; this.hops = []; this.hopsTruncated = false;
    this.backendList = backends(cast);
    this.s = this.fresh();
    this.seed();
  }

  fresh() {
    return {
      now: BASE_SECONDS, advancedMin: 0,
      seq: { audit: 0, identity: 0, key: 0, report: 0, finding: 0 },
      issuers: new Map(ISSUERS.map((i) => [i.id, { g: 0, published: [0], up: true }])),
      identities: new Map(), keys: new Map(), humans: new Map(), audit: { changes: [], requests: [], refusals: [] }, auditDropped: { changes: 0, requests: 0, refusals: 0 },
      findings: [], reports: [], policies: new Map(), sensors: new Map(),
    };
  }
  reset() { this.s = this.fresh(); this.hops = []; this.seed(); }

  seed() {
    for (const k of HUMAN_ID_KEYS) { const id = this.cast[k]; this.s.humans.set(id, { id, active: true }); }
    for (const def of seedIdentities(this.cast)) {
      const ident = this.insertIdentity({ name: def.name, description: def.description, platform: def.platform, scopes: def.scopes, federation: def.federation, kind: 'agent', enabled: true });
      this.insertKey({ name: `key for ${def.name}`, owner: { kind: 'identity', ref: ident.id }, scopes: def.keyScopes });
    }
    this.insertKey({ name: `${this.cast.castOwner}'s stored key`, owner: { kind: 'human', ref: this.cast.castOwner }, scopes: ['mcp', 'llm'] });
    this.audit('lab.started', { note: 'five mock issuers, five Federated Identities, each with a key it owns, and one stored key owned by a person' });
  }

  // ---------- helpers -----------------------------------------------------------------------------------------------------------------------
  hop(label, request, response) {
    if (!this.trace) return null;
    if (this.hops.length >= LIMITS.hops) { this.hopsTruncated = true; return null; }
    const h = { n: this.hops.length + 1, label, request: { ...request, headers: { traceparent: formatTraceparent(this.trace.traceId, this.trace.span()), ...(request.headers || {}) } }, response };
    this.hops.push(h);
    return h;
  }
  audit(kind, data = {}) {
    const s = this.s; const a = { n: ++s.seq.audit, at: iso(s.now), kind, ...data };
    // Three rings, so noise cannot push out what matters: refusals (cheap for a caller to produce) never evict a change or an allowed request, and allowed requests never
    // evict a change (an identity created, revoked, a key rotated). Within a ring the oldest entry is dropped and counted, and the page says so.
    const ring = data.outcome === 'refused' ? 'refusals' : data.outcome === 'allowed' ? 'requests' : 'changes';
    const cap = ring === 'refusals' ? LIMITS.auditRefusals : ring === 'requests' ? LIMITS.auditRequests : LIMITS.auditChanges;
    s.audit[ring].push(a);
    if (s.audit[ring].length > cap) { s.audit[ring].shift(); s.auditDropped[ring] += 1; }
    return a;
  }
  identity(id) { return typeof id === 'string' && this.s.identities.has(id) ? this.s.identities.get(id) : null; }
  keyObj(id) { return typeof id === 'string' && this.s.keys.has(id) ? this.s.keys.get(id) : null; }
  issuerState(id) { return typeof id === 'string' && Object.hasOwn(ISSUER, id) ? this.s.issuers.get(id) : null; }
  kidOf(issuerId, g) { return `${issuerId}-key-${g + 1}`; }
  slotIndex(issuerId, g) { return ISSUER[issuerId].slot * GENERATIONS + g; }
  // The public JWKS the issuer publishes now (current key, and an older one while it has not been retired).
  publishedJwks(issuerId) { return this.s.issuers.get(issuerId).published.map((g) => ({ ...keyAt(this.slotIndex(issuerId, g)).publicJwk, kid: this.kidOf(issuerId, g), use: 'sig', alg: 'RS256' })); }
  effectiveScopes(ident, key) { return key.scopes.filter((x) => ident.scopes.includes(x)); }
  keysOf(identityId) { return [...this.s.keys.values()].filter((k) => k.owner.kind === 'identity' && k.owner.ref === identityId); }

  // ---------- the lab clock: forward only, capped per move and in total -----------------------------------------------------------------------
  advance(input = {}) {
    strictKeys(input, ['minutes'], 'the clock move');
    const m = input.minutes;
    need(Number.isInteger(m), 'bad_minutes', 'minutes must be a whole number');
    need(m >= 1, 'clock_forward_only', 'the lab clock only moves forward');
    need(m <= LIMITS.clockPerMoveMin, 'clock_move_too_big', `one move is at most ${LIMITS.clockPerMoveMin} minutes`);
    need(this.s.advancedMin + m <= LIMITS.clockTotalMin, 'clock_limit', `the lab clock moves at most ${LIMITS.clockTotalMin} minutes in total: Reset`, 409);
    const refreshed = new Map();
    for (let i = 0; i < m; i++) {
      this.s.now += 60;
      for (const ident of this.s.identities.values()) {
        if (ident.federation.jwksUri && this.s.now >= ident.cache.nextRefreshAt) {
          const r = this.refreshKeyset(ident, 'scheduled (every 15 lab minutes)', { quiet: true });
          const cur = refreshed.get(ident.id) || { ok: 0, failed: 0 }; cur[r.ok ? 'ok' : 'failed'] += 1; refreshed.set(ident.id, cur);
        }
      }
    }
    this.s.advancedMin += m;
    const summary = [...refreshed.entries()].map(([id, v]) => `${id}: ${v.ok} ok, ${v.failed} failed`);
    this.audit('clock.advanced', { minutes: m, note: summary.length ? `scheduled key-set refreshes: ${summary.join('; ')}` : 'no key-set refresh was due' });
    return { now: this.s.now, at: iso(this.s.now), advancedMin: this.s.advancedMin, refreshes: Object.fromEntries(refreshed) };
  }

  // ---------- issuers: rotate a key, take the issuer down, bring it back --------------------------------------------------------------------------
  issuerAction(input = {}) {
    strictKeys(input, ['issuer', 'action', 'retireOld'], 'the issuer action');
    const st = this.issuerState(input.issuer);
    need(st, 'unknown_issuer', 'no such issuer', 404);
    need(['rotate', 'down', 'up'].includes(input.action), 'bad_action', 'action must be rotate, down or up');
    need(input.retireOld === undefined || typeof input.retireOld === 'boolean', 'bad_retire', 'retireOld must be true or false');
    const meta = ISSUER[input.issuer];
    if (input.action === 'rotate') {
      need(st.g + 1 < GENERATIONS, 'rotation_limit', `an issuer rotates at most ${GENERATIONS - 1} times in a workspace: Reset`, 409);
      st.g += 1; st.published = input.retireOld === false ? [...st.published, st.g] : [st.g];
      this.audit('issuer.rotated', { issuer: meta.id, kid: this.kidOf(meta.id, st.g), note: input.retireOld === false ? 'the old key is still published beside the new one' : 'the old key is no longer published' });
      return { issuer: meta.id, kid: this.kidOf(meta.id, st.g), published: st.published.map((g) => this.kidOf(meta.id, g)) };
    }
    st.up = input.action === 'up';
    this.audit(st.up ? 'issuer.up' : 'issuer.down', { issuer: meta.id, note: st.up ? 'the issuer answers again' : 'the issuer does not answer key-set requests (workloads that already hold a token still present it)' });
    return { issuer: meta.id, up: st.up };
  }

  // The PUBLIC key set an issuer publishes now, for the in-browser signature check. Public halves only; a down issuer answers 503, as a real fetch would fail.
  jwksOf(issuerId) {
    const st = this.issuerState(issuerId);
    need(st, 'unknown_issuer', 'no such issuer', 404);
    need(st.up, 'issuer_down', 'the issuer does not answer key-set requests', 503);
    return { issuer: issuerId, keys: this.publishedJwks(issuerId) };
  }

  // ---------- key sets: validate at creation, refresh every fifteen lab minutes and on an unknown kid, keep the last known good set -----------------
  fetchKeyset(f) {
    if (f.jwksUri) {
      const iss = ISSUERS.find((i) => i.jwksUri === f.jwksUri);
      if (!iss) return { ok: false, detail: 'the key-set address is not one of the lab\'s issuers (the lab fetches nothing from the network)' };
      if (!this.s.issuers.get(iss.id).up) return { ok: false, detail: 'the issuer did not answer' };
      return { ok: true, source: 'jwks-uri', keys: this.publishedJwks(iss.id), detail: 'fetched the published key set' };
    }
    return { ok: true, source: 'pinned', keys: f.pinned || [], detail: 'pinned key material (nothing to fetch)' };
  }
  // One attempt. On success the cached set is replaced; on failure the last known good set is kept. Records the attempt either way.
  refreshKeyset(ident, reason, { quiet = false } = {}) {
    const f = ident.federation; const c = ident.cache;
    const r = this.fetchKeyset(f);
    const bad = r.ok && r.keys.some((k) => jwkProblem(k));
    let result;
    if (r.ok && !bad && r.keys.length) {
      c.keys = r.keys.map((k) => ({ ...k })); c.source = r.source;
      result = { at: iso(this.s.now), reason, ok: true, kept: false, kids: c.keys.map((k) => k.kid), detail: r.detail };
    } else {
      result = { at: iso(this.s.now), reason, ok: false, kept: true, kids: c.keys.map((k) => k.kid), detail: `${bad ? 'the published key set was not valid' : r.detail}: kept the last known good set` };
    }
    c.lastAttemptAt = this.s.now; c.nextRefreshAt = f.jwksUri ? this.s.now + REFRESH_SECONDS : null; c.last = result;
    c.log.push(result); if (c.log.length > LIMITS.refreshLog) c.log.shift();
    if (!quiet) this.hop('gateway fetches the issuer\'s key set', { method: 'GET', url: f.jwksUri || '(pinned: nothing is fetched)' }, { status: result.ok ? 200 : 'no answer', body: { kids: result.kids, kept: result.kept } });
    return result;
  }
  refreshKeys(input = {}) {
    strictKeys(input, ['identityId'], 'the refresh');
    const ident = this.identity(input.identityId); need(ident, 'unknown_identity', 'no such identity', 404);
    need(ident.federation.jwksUri, 'nothing_to_refresh', 'this identity pins its keys: there is no address to refresh from', 409);
    const r = this.refreshKeyset(ident, 'manual');
    this.audit('jwks.refresh', { identityId: ident.id, outcome: r.ok ? 'ok' : 'failed', note: r.detail });
    return r;
  }

  // ---------- Federated Identity (console API object NonHumanIdentity) ------------------------------------------------------------------------------
  normalizeFederation(f) {
    need(isObj(f), 'bad_federation', 'federation must be an object');
    strictKeys(f, ['issuer', 'subject', 'audience', 'jwksUri', 'jwks', 'pinFromIssuer', 'maxTokenLifetimeSec', 'requiredClaims', 'allowAnySubject'], 'the federation');
    const out = {};
    strictValue(f.issuer, SAFE_URL, 'bad_issuer', 'issuer must be an https URL on a .example or .invalid host');
    out.issuer = f.issuer;
    need(f.allowAnySubject === undefined || typeof f.allowAnySubject === 'boolean', 'bad_subject', 'allowAnySubject must be true or false');
    out.allowAnySubject = f.allowAnySubject === true;
    if (out.allowAnySubject && (f.subject === undefined || f.subject === '')) out.subject = '';
    else strictValue(f.subject, SAFE_VALUE, out.allowAnySubject ? 'bad_subject' : 'subject_required', out.allowAnySubject ? 'subject must be a short plain value' : 'a subject is required: the binding is exact (or accept any subject explicitly)');
    if (out.subject === undefined) out.subject = f.subject;
    strictValue(f.audience, SAFE_VALUE, 'audience_required', 'an audience is required: a token with no audience binding is replayable against anything else that trusts the issuer');
    out.audience = f.audience;
    out.jwksUri = null;
    if (f.jwksUri !== undefined && f.jwksUri !== '' && f.jwksUri !== null) { strictValue(f.jwksUri, SAFE_URL, 'bad_jwks_uri', 'the key-set address must be an https URL on a .example or .invalid host'); out.jwksUri = f.jwksUri; }
    out.pinned = null;
    if (f.pinFromIssuer !== undefined) {
      need(typeof f.pinFromIssuer === 'string' && Object.hasOwn(ISSUER, f.pinFromIssuer), 'bad_issuer', 'pinFromIssuer must name one of the lab\'s issuers');
      out.pinned = this.publishedJwks(f.pinFromIssuer);
    } else if (f.jwks !== undefined && f.jwks !== null) {
      const list = isObj(f.jwks) && Array.isArray(f.jwks.keys) ? f.jwks.keys : f.jwks;
      need(Array.isArray(list) && list.length >= 1 && list.length <= LIMITS.pinnedKeys, 'jwks_invalid', `pinned key material is 1 to ${LIMITS.pinnedKeys} public keys`);
      const picked = [];
      for (const k of list) {
        const problem = jwkProblem(k);
        if (problem) throw refuse(/private/.test(problem) ? 'jwks_private_material' : 'jwks_invalid', problem);
        picked.push({ kty: 'RSA', n: k.n, e: k.e, kid: k.kid, use: 'sig', alg: 'RS256' });
      }
      need(new Set(picked.map((k) => k.kid)).size === picked.length, 'jwks_invalid', 'each pinned key needs its own kid');
      out.pinned = picked;
    }
    need(out.jwksUri || (out.pinned && out.pinned.length), 'jwks_required', 'give a key-set address, or pin the issuer\'s public keys');
    const life = f.maxTokenLifetimeSec === undefined ? 0 : f.maxTokenLifetimeSec;
    need(Number.isInteger(life) && life >= 0 && life <= 86400, 'bad_lifetime', 'maxTokenLifetimeSec is a whole number from 0 to 86400 (0 means the gateway default, 3600)');
    out.maxTokenLifetimeSec = life;
    const rc = f.requiredClaims === undefined ? {} : f.requiredClaims;
    need(isObj(rc) && Object.keys(rc).length <= LIMITS.requiredClaims, 'bad_claims', `requiredClaims is an object of at most ${LIMITS.requiredClaims} claims`);
    out.requiredClaims = Object.fromEntries(Object.keys(rc).map((name) => {
      need(CLAIM_NAME.test(name) && !RESERVED_CLAIMS.has(name) && !credentialProblem(name), 'bad_claims', 'a pinned claim name is short and plain, is not credential-shaped, and is not one of iss, sub, aud, exp, iat or nbf');
      const v = rc[name];
      need((typeof v === 'string' && SAFE_VALUE.test(v) && !credentialShaped(v)) || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v)), 'bad_claims', 'a pinned claim value is a short plain string, a number or true or false');
      return [name, v];
    }));
    return out;
  }
  normalizeSpec(input, base) {
    const out = {};
    need(typeof input.name === 'string', 'bad_name', 'name must be text'); out.name = cleanFree(input.name, LIMITS.name); need(out.name.length > 0, 'bad_name', 'name must not be empty');
    out.description = input.description === undefined ? '' : (need(typeof input.description === 'string', 'bad_description', 'description must be text'), cleanFree(input.description, LIMITS.description));
    out.platform = input.platform === undefined ? 'oidc' : input.platform; need(PLATFORMS.includes(out.platform), 'bad_platform', `platform must be ${PLATFORMS.join(', ')}`);
    need(uniqueStrings(input.scopes, SCOPES, LIMITS.scopes), 'bad_scopes', `scopes is a list of ${SCOPES.join(', ')} with no repeats`); out.scopes = [...input.scopes];
    out.notAfter = input.notAfter === undefined ? '' : input.notAfter;
    need(out.notAfter === '' || (typeof out.notAfter === 'string' && RFC3339_Z.test(out.notAfter) && Number.isFinite(Date.parse(out.notAfter))), 'bad_not_after', 'notAfter is empty (no expiry) or a UTC time like 2026-11-03T09:00:00Z');
    out.enabled = input.enabled === undefined ? base?.enabled ?? true : input.enabled; need(typeof out.enabled === 'boolean', 'bad_enabled', 'enabled must be true or false');
    out.federation = this.normalizeFederation(input.federation);
    return out;
  }
  // The shape of an identity as input, from what is stored: used so an update is "the stored identity with these fields replaced", then checked as a whole.
  asInput(ident) {
    const f = ident.federation;
    return { name: ident.name, description: ident.description, platform: ident.platform, scopes: [...ident.scopes], notAfter: ident.notAfter, enabled: ident.enabled,
      federation: { issuer: f.issuer, subject: f.subject, audience: f.audience, jwksUri: f.jwksUri || undefined, jwks: f.pinned ? f.pinned.map((k) => ({ ...k })) : undefined, maxTokenLifetimeSec: f.maxTokenLifetimeSec, requiredClaims: { ...f.requiredClaims }, allowAnySubject: f.allowAnySubject } };
  }
  // The key set is validated when the identity is created: it must be fetched (or pinned) and hold usable public RSA keys.
  buildCache(f) {
    let r = this.fetchKeyset(f);
    if (!r.ok && f.pinned?.length) r = { ok: true, source: 'pinned', keys: f.pinned, detail: 'the address did not answer: the pinned key material is used' };
    need(r.ok, 'jwks_unreachable', 'the issuer\'s key set could not be fetched, so the identity was not created or changed', 502);
    need(r.keys.length >= 1 && r.keys.every((k) => !jwkProblem(k)), 'jwks_invalid', 'the issuer\'s key set holds no usable public RSA key', 502);
    const entry = { at: iso(this.s.now), reason: 'validated when the identity was saved', ok: true, kept: false, kids: r.keys.map((k) => k.kid), detail: r.detail };
    return { source: r.source, keys: r.keys.map((k) => ({ ...k })), lastAttemptAt: this.s.now, nextRefreshAt: f.jwksUri ? this.s.now + REFRESH_SECONDS : null, last: entry, log: [entry] };
  }
  insertIdentity(input) {
    const spec = this.normalizeSpec(input, null);
    const cache = this.buildCache(spec.federation);
    const id = `fid-${pad(++this.s.seq.identity, 3)}`;
    const ident = { id, ...spec, kind: input.kind === 'self-hosted-agent' ? 'self-hosted-agent' : 'agent', createdAt: iso(this.s.now), cache };
    this.s.identities.set(id, ident);
    return ident;
  }
  createIdentity(input = {}) {
    strictKeys(input, ['name', 'description', 'platform', 'scopes', 'notAfter', 'enabled', 'federation'], 'the identity');
    need(this.s.identities.size < LIMITS.identities, 'workspace_full', `a workspace keeps at most ${LIMITS.identities} identities: Reset`, 409);
    const ident = this.insertIdentity(input);
    this.audit('identity.created', { identityId: ident.id, platform: ident.platform });
    this.hop('gateway validates the key set at creation', { method: 'GET', url: ident.federation.jwksUri || '(pinned)' }, { status: 200, body: { kids: ident.cache.keys.map((k) => k.kid) } });
    return { identityId: ident.id, kids: ident.cache.keys.map((k) => k.kid) };
  }
  updateIdentity(input = {}) {
    strictKeys(input, ['identityId', 'name', 'description', 'platform', 'scopes', 'notAfter', 'enabled', 'federation'], 'the identity change');
    const ident = this.identity(input.identityId); need(ident, 'unknown_identity', 'no such identity', 404);
    const { identityId, federation, ...top } = input;
    need(federation === undefined || isObj(federation), 'bad_federation', 'federation must be an object');
    const merged = this.asInput(ident);
    Object.assign(merged, top);
    if (federation) {
      const f = { ...merged.federation, ...federation };
      if (federation.pinFromIssuer !== undefined || federation.jwks !== undefined) { if (federation.pinFromIssuer !== undefined) delete f.jwks; else delete f.pinFromIssuer; }
      merged.federation = f;
    }
    const spec = this.normalizeSpec(merged, ident);
    const keyChanged = JSON.stringify([spec.federation.issuer, spec.federation.jwksUri, spec.federation.pinned]) !== JSON.stringify([ident.federation.issuer, ident.federation.jwksUri, ident.federation.pinned]);
    const cache = keyChanged ? this.buildCache(spec.federation) : ident.cache;
    const wasEnabled = ident.enabled;
    Object.assign(ident, spec, { cache });
    const kind = wasEnabled && !ident.enabled ? 'identity.revoked' : !wasEnabled && ident.enabled ? 'identity.restored' : 'identity.updated';
    this.audit(kind, { identityId: ident.id, note: kind === 'identity.revoked' ? 'Enabled is false: the next request from this workload is refused' : undefined });
    return { identityId: ident.id, enabled: ident.enabled };
  }
  deleteIdentity(input = {}) {
    strictKeys(input, ['identityId'], 'the removal');
    const ident = this.identity(input.identityId); need(ident, 'unknown_identity', 'no such identity', 404);
    this.s.identities.delete(ident.id); this.s.policies.delete(ident.id); this.s.sensors.delete(ident.id);
    this.audit('identity.removed', { identityId: ident.id, note: 'the identity is gone: the next request from this workload is refused; keys it owned stay but name no identity' });
    return { identityId: ident.id, removed: true };
  }

  // ---------- agent access keys: owned by a person (a stored key) or by a Federated Identity ----------------------------------------------------------
  insertKey({ name, owner, scopes }) {
    const id = `key-${pad(++this.s.seq.key)}`;
    const key = { id, name: cleanFree(name, LIMITS.name), owner: { ...owner }, scopes: [...scopes], enabled: true, auth: owner.kind === 'human' ? 'stored' : 'federated' };
    this.s.keys.set(id, key);
    return key;
  }
  createKey(input = {}) {
    strictKeys(input, ['name', 'owner', 'scopes', 'ownFederation', 'userRef'], 'the key');
    need(this.s.keys.size < LIMITS.keys, 'workspace_full', `a workspace keeps at most ${LIMITS.keys} keys: Reset`, 409);
    need(typeof input.name === 'string' && cleanFree(input.name, LIMITS.name).length > 0, 'bad_name', 'name must be non-empty text');
    need(isObj(input.owner) && Object.keys(input.owner).every((k) => ['kind', 'ref'].includes(k)) && ['identity', 'human'].includes(input.owner.kind) && typeof input.owner.ref === 'string', 'bad_owner', 'owner is { kind: identity or human, ref }');
    need(uniqueStrings(input.scopes, SCOPES, LIMITS.scopes), 'bad_scopes', `scopes is a list of ${SCOPES.join(', ')} with no repeats`);
    need(input.ownFederation === undefined || typeof input.ownFederation === 'boolean', 'bad_owner', 'ownFederation must be true or false');
    need(input.userRef === undefined || typeof input.userRef === 'string', 'bad_owner', 'userRef must be text');
    if (input.owner.kind === 'identity') {
      const ident = this.identity(input.owner.ref); need(ident, 'unknown_identity', 'no such identity', 404);
      // Measured on our tenant (2026-10-21, console API refusals, our note): a key cannot carry its own workload identity AND name an identity as its owner.
      need(input.ownFederation !== true, 'mutually_exclusive', 'a key that names a Federated Identity as its owner cannot also carry its own workload identity: the identity supplies the verification material', 409);
      // Measured: the owner and the user reference must not name different principals.
      need(input.userRef === undefined, 'principal_conflict', 'a key owned by an identity cannot also name a person: the two would be different principals', 409);
      need(input.scopes.every((x) => ident.scopes.includes(x)), 'scope_not_on_identity', 'a key can only narrow the identity\'s scopes', 400);
      const key = this.insertKey({ name: input.name, owner: { kind: 'identity', ref: ident.id }, scopes: input.scopes });
      this.audit('key.created', { keyId: key.id, principal: `identity ${ident.name}` });
      return { keyId: key.id };
    }
    need(input.ownFederation !== true, 'not_modelled', 'a stored key does not federate; the lab does not model a key with its own workload identity');
    need(input.userRef === undefined, 'bad_owner', 'a person-owned key names its owner in owner.ref');
    need(this.s.humans.has(input.owner.ref), 'unknown_person', 'no such person', 404);
    const key = this.insertKey({ name: input.name, owner: { kind: 'human', ref: input.owner.ref }, scopes: input.scopes });
    this.audit('key.created', { keyId: key.id, principal: `person ${input.owner.ref} (borrowed)` });
    return { keyId: key.id };
  }
  updateKey(input = {}) {
    strictKeys(input, ['keyId', 'enabled', 'scopes'], 'the key change');
    const key = this.keyObj(input.keyId); need(key, 'unknown_key', 'no such key', 404);
    const next = { enabled: input.enabled === undefined ? key.enabled : input.enabled, scopes: input.scopes === undefined ? key.scopes : input.scopes };
    need(typeof next.enabled === 'boolean', 'bad_enabled', 'enabled must be true or false');
    need(uniqueStrings(next.scopes, SCOPES, LIMITS.scopes), 'bad_scopes', `scopes is a list of ${SCOPES.join(', ')} with no repeats`);
    if (key.owner.kind === 'identity') { const ident = this.identity(key.owner.ref); need(!ident || next.scopes.every((x) => ident.scopes.includes(x)), 'scope_not_on_identity', 'a key can only narrow the identity\'s scopes'); }
    key.enabled = next.enabled; key.scopes = [...next.scopes];
    this.audit('key.updated', { keyId: key.id, note: key.enabled ? 'enabled' : 'revoked' });
    return { keyId: key.id, enabled: key.enabled };
  }
  deleteKey(input = {}) {
    strictKeys(input, ['keyId'], 'the removal');
    const key = this.keyObj(input.keyId); need(key, 'unknown_key', 'no such key', 404);
    this.s.keys.delete(key.id); this.audit('key.removed', { keyId: key.id });
    return { keyId: key.id, removed: true };
  }
  setPerson(input = {}) {
    strictKeys(input, ['person', 'active'], 'the person change');
    need(typeof input.person === 'string' && this.s.humans.has(input.person), 'unknown_person', 'no such person', 404);
    need(typeof input.active === 'boolean', 'bad_active', 'active must be true or false');
    this.s.humans.get(input.person).active = input.active;
    this.audit(input.active ? 'person.active' : 'person.inactive', { principal: `person ${input.person}`, note: input.active ? 'the account is active' : 'the account is inactive: every key that borrows this person stops working; a key owned by an identity is unaffected' });
    return { person: input.person, active: input.active };
  }

  // ---------- backends: the token stops at the gateway; the application's own credential is injected ----------------------------------------------
  backendFor(service) { return this.backendList.find((b) => b.service === service) || null; }
  forwardRequest(service) {
    const b = this.backendFor(service); if (!b) return null;
    // The outbound request carries the application's own credential, MASKED here (the lab holds none). The inbound token is not part of it.
    return { backend: b.id, authMode: b.authMode, request: { method: 'POST', url: b.url, headers: { authorization: b.credential } }, inboundTokenForwarded: false };
  }
  // A stored key presented as a bearer secret (the fallback model). The key value itself is never part of this call.
  storedKeyCall(input = {}) {
    strictKeys(input, ['keyId', 'service'], 'the stored-key call');
    const key = this.keyObj(input.keyId); need(key, 'unknown_key', 'no such key', 404);
    need(key.auth === 'stored', 'not_a_stored_key', 'this key is owned by an identity: it authenticates by a token, not by a stored secret');
    need(SERVICE_SCOPES.includes(input.service), 'bad_service', 'service must be mcp, a2a or llm');
    const person = this.s.humans.get(key.owner.ref);
    const principal = `person ${key.owner.ref} (borrowed)`;
    const done = (ok, status, code, detail, extra = {}) => {
      this.audit('stored-key', { outcome: ok ? 'allowed' : 'refused', code: ok ? undefined : code, keyId: key.id, principal, service: input.service, scope: input.service });
      return { ok, status, code, detail, keyId: key.id, principal, service: input.service, ...extra };
    };
    if (!key.enabled) return done(false, 401, 'key_revoked', 'the key is revoked');
    if (!person?.active) return done(false, 401, 'owner_inactive', 'the person who owns this key is inactive, so the key stopped working (measured on our tenant, our note: a key stops when its custodian account goes inactive)');
    if (!key.scopes.includes(input.service)) return done(false, 403, 'scope_not_on_key', `key not scoped for ${input.service} access`);
    return done(true, 200, 'allowed', 'the stored key is accepted', { forwarded: this.forwardRequest(input.service) });
  }

  // ---------- minting: a mock issuer signs the claims the visitor chose (real RS256), or the forged forms -------------------------------------------
  mint(input = {}) {
    strictKeys(input, ['issuer', 'alg', 'generation', 'kid', 'claims', 'times'], 'the mint request');
    need(typeof input.issuer === 'string' && (Object.hasOwn(ISSUER, input.issuer) || input.issuer === ATTACKER.id), 'bad_issuer', 'issuer must be one of the lab\'s issuers or attacker');
    const isAttacker = input.issuer === ATTACKER.id;
    const alg = input.alg === undefined ? 'RS256' : input.alg; need(MINT_ALGS.includes(alg), 'bad_alg', `alg must be ${MINT_ALGS.join(', ')}`);
    const st = isAttacker ? { g: 0 } : this.issuerState(input.issuer);
    const gen = input.generation === undefined ? st.g : input.generation;
    need(Number.isInteger(gen) && gen >= 0 && gen <= st.g, 'bad_generation', 'generation is a key the issuer has used');
    let kid = isAttacker ? 'attacker-key-1' : this.kidOf(input.issuer, gen);
    if (input.kid === null) kid = null;
    else if (input.kid !== undefined) { strictValue(input.kid, KID, 'bad_kid', 'kid is a short plain value'); kid = input.kid; }
    const c = input.claims === undefined ? {} : input.claims;
    need(isObj(c) && Object.keys(c).every((k) => ['iss', 'sub', 'aud', 'extra'].includes(k)), 'bad_claims', 'claims takes iss, sub, aud and extra');
    const t = input.times === undefined ? {} : input.times;
    need(isObj(t) && Object.keys(t).every((k) => ['iat', 'exp', 'nbf'].includes(k)), 'bad_times', 'times takes iat, exp and nbf (seconds from the lab clock)');
    // Claim values are compared EXACTLY by the gateway, so the lab never rewrites one: a value is signed byte for byte, or refused (too long, or credential-shaped). The
    // answer shows the value with hidden characters written out, and a notice for anything that is not plain ASCII text.
    const notices = [];
    const text = (v, what, claim) => {
      need(typeof v === 'string', 'bad_claims', `${what} must be text`);
      need(v.length <= LIMITS.claimText, 'claim_too_long', `a claim is at most ${LIMITS.claimText} characters, and the lab will not cut one`);
      need(!credentialProblem(v), 'credential_shaped', 'that claim looks like a credential: the lab will not sign it or show it');
      const odd = oddities(v); if (odd.length) notices.push({ claim, text: `${claim} is signed exactly as typed and contains ${odd.join(', ')}` });
      return v;
    };
    const offset = (v, dflt) => { const x = v === undefined ? dflt : v; if (x === null) return null; need(Number.isInteger(x) && Math.abs(x) <= 31_536_000, 'bad_times', 'a time is a whole number of seconds from the lab clock (or null to leave it out)'); return this.s.now + x; };
    const payload = {};
    const iss = c.iss === undefined ? (isAttacker ? ATTACKER.url : ISSUER[input.issuer].url) : c.iss;
    if (iss !== null) payload.iss = text(iss, 'iss', 'iss');
    if (c.sub !== undefined && c.sub !== null) payload.sub = text(c.sub, 'sub', 'sub');
    if (c.aud !== undefined && c.aud !== null) {
      if (Array.isArray(c.aud)) { need(c.aud.length >= 1 && c.aud.length <= LIMITS.audienceValues, 'bad_claims', `aud lists at most ${LIMITS.audienceValues} values`); payload.aud = c.aud.map((a) => text(a, 'aud', 'aud')); } else payload.aud = text(c.aud, 'aud', 'aud');
    }
    const exp = offset(t.exp, 3600); const iat = offset(t.iat, 0); const nbf = offset(t.nbf, null);
    if (exp !== null) payload.exp = exp;
    if (iat !== null) payload.iat = iat;
    if (nbf !== null) payload.nbf = nbf;
    if (c.extra !== undefined) {
      need(isObj(c.extra) && Object.keys(c.extra).length <= LIMITS.extraClaims, 'bad_claims', `extra is an object of at most ${LIMITS.extraClaims} claims`);
      for (const name of Object.keys(c.extra)) {
        need(CLAIM_NAME.test(name) && !RESERVED_CLAIMS.has(name) && !credentialProblem(name), 'bad_claims', 'an extra claim name is short and plain, is not credential-shaped, and is not one of iss, sub, aud, exp, iat or nbf');
        const v = c.extra[name];
        need(typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v)), 'bad_claims', 'an extra claim value is text, a number or true or false');
        Object.defineProperty(payload, name, { value: typeof v === 'string' ? text(v, `an extra claim`, name) : v, enumerable: true, writable: true, configurable: true });
      }
    }
    const header = { alg, typ: 'JWT' }; if (kid !== null) header.kid = kid;
    const sloti = isAttacker ? ATTACKER_SLOT * GENERATIONS : this.slotIndex(input.issuer, gen);
    const k = keyAt(sloti);
    const inputText = signingInput(header, payload);
    let sig = '';
    if (alg === 'RS256' || alg === 'ES256') sig = signRS256(inputText, k.privateKey); // ES256 is a header label only: the signature is RS256, so the token is refused before any key is used
    else if (alg === 'HS256') sig = signHS256(inputText, Buffer.from(k.publicJwk.n)); // the classic confusion attack: the issuer's PUBLIC key used as the HMAC secret
    const token = `${inputText}.${sig}`;
    need(token.length <= 4096, 'token_too_large', 'the token would be longer than 4096 characters');
    return { mintedToken: token, label: 'lab-minted token: a real signature from a mock issuer, good only inside this lab', issuer: input.issuer, alg, kid, header: cleanClaims(header), claims: cleanClaims(payload), notices, notes: alg === 'HS256' ? 'signed with the issuer\'s public key as the secret (the algorithm-confusion attack)' : alg === 'none' ? 'unsigned' : alg === 'ES256' ? 'the header says ES256 but the signature is RS256' : isAttacker ? 'signed by a key no issuer publishes' : '' };
  }

  // ---------- verification: every step, in order, with the exact reason ----------------------------------------------------------------------------
  deploymentOf(ident, claims) {
    const g = (k) => (typeof claims[k] === 'string' ? show(claims[k], 60) : null);
    const sub = typeof claims.sub === 'string' ? show(claims.sub, 80) : '(no subject)';
    let parts;
    if (ident.platform === 'kubernetes') { const m = /^system:serviceaccount:([^:]+):([^:]+)$/.exec(String(claims.sub)); parts = [m ? `${show(m[1], 40)}/${show(m[2], 40)}` : sub, g('pod') && `pod ${g('pod')}`, g('node') && `node ${g('node')}`]; }
    else if (ident.platform === 'github_actions') parts = [g('repository') || sub, g('ref'), g('run_id') && `run ${g('run_id')}`];
    else if (ident.platform === 'gitlab_ci') parts = [g('project_path') || sub, g('ref'), g('pipeline_id') && `pipeline ${g('pipeline_id')}`];
    else parts = [sub];
    return parts.filter(Boolean).join(' ');
  }

  // The pipeline. Returns { ok, status, code, detail, steps, ... }; it never throws for a token problem. `identityId` names the identity under test; without it the gateway
  // finds the identity by the token's issuer and subject.
  verifyCore({ token, identityId, scope, keyId }) {
    const steps = STEPS.map((x) => ({ id: x.id, title: x.title, status: 'skip', detail: 'not reached' }));
    const out = { ok: false, status: 401, code: null, detail: '', steps, header: null, claims: null, identityId: null, identityName: null, keyId: null, principal: null, deployment: null, scope, refresh: null, forwarded: null, callerSees: null };
    const mark = (id, status, detail) => { const st = steps.find((x) => x.id === id); st.status = status; st.detail = detail; };
    const stop = (id, code, status, detail) => { mark(id, 'fail', detail); Object.assign(out, { ok: false, code, status, detail, callerSees: STATUS_TEXT[status] || String(status) }); return out; };
    const now = this.s.now;

    const p = parseToken(token);
    if (!p.ok) return stop('parse', p.code, 401, p.detail);
    out.header = cleanClaims(p.header); out.claims = cleanClaims(p.payload);
    // RFC 7515: a crit header names extensions the receiver must understand, and a token naming any it does not understand is rejected. The lab understands none.
    if (Object.hasOwn(p.header, 'crit')) return stop('parse', 'crit_unsupported', 401, 'the header has a crit parameter, which names extensions the lab does not understand: RFC 7515 says such a token is rejected');
    mark('parse', 'pass', 'three canonical base64url parts; the header and payload are UTF-8 JSON objects');

    let ident = null;
    if (identityId !== undefined) {
      ident = this.identity(identityId);
      if (!ident) return stop('identity', 'unknown_identity', 404, 'no such identity');
    } else {
      const iss = p.payload.iss; const sub = p.payload.sub;
      const hits = typeof iss === 'string' ? [...this.s.identities.values()].filter((x) => x.federation.issuer === iss && (x.federation.allowAnySubject || (typeof sub === 'string' && x.federation.subject === sub))) : [];
      if (!hits.length) return stop('identity', 'no_matching_identity', 401, 'no Federated Identity trusts this issuer and subject');
      if (hits.length > 1) return stop('identity', 'ambiguous_identity', 401, 'more than one identity matches this issuer and subject');
      [ident] = hits;
    }
    out.identityId = ident.id; out.identityName = ident.name;
    if (!ident.enabled) return stop('identity', 'identity_disabled', 401, `${ident.name} is disabled (Enabled is false: the kill switch)`);
    if (ident.notAfter && Date.parse(ident.notAfter) / 1000 <= now) return stop('identity', 'identity_expired', 401, `${ident.name} expired at ${ident.notAfter}`);
    mark('identity', 'pass', `${ident.name} (${ident.id}) is enabled${ident.notAfter ? ` until ${ident.notAfter}` : ''}`);
    const f = ident.federation;

    const alg = p.header.alg;
    if (typeof alg !== 'string') return stop('alg', 'alg_not_allowed', 401, 'the header has no algorithm');
    if (alg.toLowerCase() === 'none') return stop('alg', 'alg_none', 401, 'alg none: an unsigned token is never accepted');
    if (SYMMETRIC_ALGS.has(alg) || /^hs/i.test(alg)) return stop('alg', 'alg_symmetric', 401, `${show(alg, 12)} is a shared-secret algorithm: only asymmetric signatures are accepted`);
    if (alg !== 'RS256') return stop('alg', ASYMMETRIC_ALGS.has(alg) ? 'alg_unsupported_by_lab' : 'alg_not_allowed', 401, ASYMMETRIC_ALGS.has(alg) ? `${show(alg, 12)} is asymmetric, but this lab only verifies RS256` : `${show(alg, 12)} is not on the allow-list`);
    mark('alg', 'pass', 'RS256 (asymmetric)');

    if (p.payload.iss !== f.issuer) return stop('issuer', 'issuer_mismatch', 401, `iss is ${show(p.payload.iss)}, the identity requires ${show(f.issuer)} (exact match: no case folding, no trailing-slash tolerance)`);
    mark('issuer', 'pass', `iss is exactly ${show(f.issuer)}`);

    const kid = p.header.kid;
    if (typeof kid !== 'string' || !kid) return stop('keyset', 'kid_missing', 401, 'the header names no signing key (kid)');
    let jwk = ident.cache.keys.find((k) => k.kid === kid);
    let refreshNote = '';
    if (!jwk) {
      if (f.jwksUri) {
        // A cooldown (lab-invented: the deck does not say whether unknown-kid refreshes are limited): one such refresh per identity per lab minute, so a caller sending
        // endless made-up kids cannot make the gateway hammer the issuer. Within the cooldown the token is refused without a refresh.
        const c = ident.cache; const cooled = c.lastUnknownKidAt !== undefined && now - c.lastUnknownKidAt < LIMITS.unknownKidCooldownSec;
        if (cooled) {
          out.refresh = { attempted: false, cooledDown: true, ok: null, detail: 'cooldown' };
          refreshNote = ` No refresh was tried: the lab allows one unknown-kid refresh per identity per ${LIMITS.unknownKidCooldownSec / 60} lab minute (lab-invented limit; the deck does not say).`;
        } else {
          c.lastUnknownKidAt = now;
          const r = this.refreshKeyset(ident, 'unknown signing key (kid)');
          out.refresh = { attempted: true, ok: r.ok, detail: r.detail };
          jwk = ident.cache.keys.find((k) => k.kid === kid);
          refreshNote = r.ok ? ` The key set was refreshed on sight of the unknown kid.` : ` A refresh was tried and failed (${r.detail}).`;
        }
        jwk = jwk || ident.cache.keys.find((k) => k.kid === kid);
      } else refreshNote = ' This identity pins its keys and has no address to refresh from.';
      if (!jwk) return stop('keyset', 'unknown_kid', 401, `kid ${show(kid, 40)} is not in the key set.${refreshNote}`);
    }
    mark('keyset', 'pass', `kid ${show(kid, 40)} found in the ${ident.cache.source === 'pinned' ? 'pinned' : 'cached'} key set${refreshNote}`);

    if (!verifyRS256(p.input, p.signature, jwk)) return stop('signature', 'bad_signature', 401, 'the signature does not verify against that key: the token was altered or signed by someone else');
    mark('signature', 'pass', 'the RSA signature verifies: the claims below are authentic');

    const c = p.payload;
    const num = (v) => typeof v === 'number' && Number.isFinite(v);
    if (c.exp === undefined) return stop('expiry', 'exp_missing', 401, 'no exp claim: an expiry is required, so a workload cannot pick its own validity window');
    if (!num(c.exp)) return stop('expiry', 'exp_not_number', 401, 'exp is not a number');
    if (c.exp <= now) return stop('expiry', 'expired', 401, `the token expired ${now - c.exp} s ago (lab clock ${iso(now)})`);
    mark('expiry', 'pass', `exp is ${c.exp - now} s ahead of the lab clock`);

    if (c.nbf === undefined) mark('notbefore', 'pass', 'no nbf claim (optional)');
    else if (!num(c.nbf)) return stop('notbefore', 'nbf_not_number', 401, 'nbf is not a number');
    else if (c.nbf > now) return stop('notbefore', 'not_yet_valid', 401, `the token is not valid for another ${c.nbf - now} s`);
    else mark('notbefore', 'pass', 'nbf has been reached');

    if (c.iat === undefined) return stop('issued', 'iat_missing', 401, 'no iat claim: the lifetime (exp minus iat) cannot be checked');
    if (!num(c.iat)) return stop('issued', 'iat_not_number', 401, 'iat is not a number');
    if (c.iat > now) return stop('issued', 'iat_in_future', 401, `iat is ${c.iat - now} s in the future: a future iat would hide a long-lived token from the lifetime check`);
    mark('issued', 'pass', `issued ${now - c.iat} s ago`);

    const cap = f.maxTokenLifetimeSec || DEFAULT_MAX_LIFETIME; const life = c.exp - c.iat;
    if (life <= 0) return stop('lifetime', 'exp_before_iat', 401, 'exp is not after iat');
    if (life > cap) return stop('lifetime', 'lifetime_exceeds_cap', 401, `exp minus iat is ${life} s, above the cap of ${cap} s${f.maxTokenLifetimeSec ? '' : ' (the default)'}: a token that is still unexpired is refused if it was minted to live that long`);
    mark('lifetime', 'pass', `${life} s, within the cap of ${cap} s`);

    if (c.aud === undefined) return stop('audience', 'aud_missing', 401, 'no aud claim: the audience is mandatory');
    const audOk = typeof c.aud === 'string' ? c.aud === f.audience : Array.isArray(c.aud) && c.aud.every((x) => typeof x === 'string') && c.aud.includes(f.audience);
    if (!audOk) return stop('audience', 'aud_mismatch', 401, `aud is ${show(c.aud)}, the identity requires ${show(f.audience)}`);
    mark('audience', 'pass', `aud contains exactly ${show(f.audience)}`);

    if (f.allowAnySubject) mark('subject', 'pass', 'any subject is accepted: the identity opted in to AllowAnySubject (console swagger name; the deck describes exact binding only)');
    else if (c.sub === undefined) return stop('subject', 'sub_missing', 401, 'no sub claim');
    else if (c.sub !== f.subject) return stop('subject', 'subject_mismatch', 401, `sub is ${show(c.sub)}, the identity requires ${show(f.subject)} (exact match)`);
    else mark('subject', 'pass', `sub is exactly ${show(f.subject)}`);

    for (const [name, want] of Object.entries(f.requiredClaims)) {
      if (!Object.hasOwn(c, name)) return stop('claims', 'required_claim_missing', 401, `the token has no ${name} claim (pinned: ${show(want)})`);
      if (c[name] !== want) return stop('claims', 'required_claim_mismatch', 401, `${name} is ${show(c[name])}, the identity pins ${show(want)}`);
    }
    mark('claims', 'pass', Object.keys(f.requiredClaims).length ? `${Object.keys(f.requiredClaims).join(', ')} match exactly` : 'no claims are pinned');

    const owned = this.keysOf(ident.id);
    if (!owned.length) return stop('key', 'no_key_behind_identity', 401, 'no key names this identity as its owner, so nothing can authenticate as it (measured on our tenant, our note: the gateway logged "rebuilding 0 keys")');
    let key = null;
    if (keyId !== undefined) { key = owned.find((k) => k.id === keyId) || null; if (!key) return stop('key', 'key_not_owned_by_identity', 401, 'that key is not owned by this identity'); } else key = owned.find((k) => k.enabled) || owned[0];
    if (!key.enabled) return stop('key', 'key_revoked', 401, `${key.id} is revoked`);
    out.keyId = key.id;
    mark('key', 'pass', `${key.id} is owned by ${ident.name}: the principal is the identity, not a borrowed person`);

    const eff = this.effectiveScopes(ident, key);
    if (!eff.includes(scope)) return stop('scope', 'scope_not_on_key', 403, `key not scoped for ${scope} access (the key carries ${eff.length ? eff.join(', ') : 'no scope'})`);
    mark('scope', 'pass', `${scope} is on the key (${eff.join(', ')})`);

    out.ok = true; out.status = 200; out.code = 'allowed'; out.detail = 'the token is accepted'; out.callerSees = '200 OK';
    out.principal = `identity ${ident.name}`; out.deployment = this.deploymentOf(ident, c);
    if (SERVICE_SCOPES.includes(scope)) {
      out.forwarded = this.forwardRequest(scope);
      this.hop('gateway to the backend (the token stops here)', out.forwarded.request, { status: 200, body: { note: 'the backend received its own credential; the workload token was not forwarded' } });
    }
    return out;
  }

  // The Verify tab's operation.
  verify(input = {}) {
    strictKeys(input, ['token', 'identityId', 'service', 'keyId'], 'the verification');
    need(typeof input.token === 'string', 'bad_token', 'token must be text');
    need(SERVICE_SCOPES.includes(input.service), 'bad_service', 'service must be mcp, a2a or llm');
    need(input.identityId === undefined || typeof input.identityId === 'string', 'bad_identity', 'identityId must be text');
    need(input.keyId === undefined || typeof input.keyId === 'string', 'bad_key', 'keyId must be text');
    const top = this.hop('gateway verifies the token', { method: 'POST', url: `https://gateway.${this.cast.castHost}.example/${input.service}`, headers: { authorization: 'Bearer [the workload token: not shown here]' } }, { status: null, body: {} });
    const r = this.verifyCore({ token: input.token, identityId: input.identityId, scope: input.service, keyId: input.keyId });
    if (top) top.response = { status: r.status, body: { code: r.code } };
    const claimedSub = r.claims && typeof r.claims.sub === 'string' ? r.claims.sub : undefined;
    this.audit('verify', { outcome: r.ok ? 'allowed' : 'refused', code: r.ok ? undefined : r.code, identityId: r.identityId || undefined, keyId: r.keyId || undefined, principal: r.principal || undefined,
      deployment: r.ok ? r.deployment : undefined, claimed: r.ok ? undefined : claimedSub, service: input.service, scope: input.service, status: r.status,
      note: r.refresh ? (r.refresh.attempted ? `unknown kid: the key set was refreshed (${r.refresh.ok ? 'ok' : 'failed'})` : 'unknown kid: the refresh was cooled down') : undefined });
    return r;
  }

  // ---------- Self-Hosted Agents: the Kubernetes sensor ------------------------------------------------------------------------------------------------
  nodes() { return [this.cast.castNode1, this.cast.castNode2, this.cast.castNode3]; }
  workNamespaces() { return [this.cast.castNs, this.cast.castNs2, this.cast.castNs3]; }
  sensorIdentity(id) { const i = this.identity(id); return i && i.kind === 'self-hosted-agent' ? i : null; }
  // Enrol a sensor: its own Federated Identity, a Privilege-generated audience nobody can guess, and a key that identity owns.
  enrollSensor(input = {}) {
    strictKeys(input, ['name'], 'the enrolment');
    need(this.s.sensors.size < LIMITS.sensors, 'workspace_full', `a workspace keeps at most ${LIMITS.sensors} sensors: Reset`, 409);
    need(this.s.identities.size < LIMITS.identities, 'workspace_full', `a workspace keeps at most ${LIMITS.identities} identities: Reset`, 409);
    need(this.s.keys.size < LIMITS.keys, 'workspace_full', `a workspace keeps at most ${LIMITS.keys} keys: Reset`, 409);
    const name = input.name === undefined ? `Kubernetes sensor ${this.s.sensors.size + 1}` : (need(typeof input.name === 'string' && cleanFree(input.name, LIMITS.name).length > 0, 'bad_name', 'name must be non-empty text'), cleanFree(input.name, LIMITS.name));
    // Format measured on our tenant (priv-nhi-<random>, our note); the value here is the lab's own 64-bit random, not a Privilege one.
    const audience = `priv-nhi-${Buffer.from(this.rand(8)).toString('hex')}`;
    const ident = this.insertIdentity({ name, description: 'A Kubernetes sensor enrolled as a self-hosted agent: its own principal, no standing secret.', platform: 'kubernetes', scopes: ['shadowai:write', 'policy:read'], kind: 'self-hosted-agent', enabled: true,
      federation: { issuer: ISSUER.kube.url, jwksUri: ISSUER.kube.jwksUri, subject: `system:serviceaccount:${this.cast.castSensorNs}:node-sensor`, audience } });
    const key = this.insertKey({ name: `key for ${name}`, owner: { kind: 'identity', ref: ident.id }, scopes: ['shadowai:write', 'policy:read'] });
    this.s.sensors.set(ident.id, { identityId: ident.id, enrolledAt: iso(this.s.now) });
    this.audit('sensor.enrolled', { identityId: ident.id, keyId: key.id, principal: `identity ${name}`, note: 'the audience was generated at enrolment and is projected into the pod; nothing long-lived is stored on the node' });
    this.hop('controller generates the audience and creates the identity', { method: 'POST', url: `https://console.${this.cast.castHost}.example/v1/nonhumanidentities` }, { status: 201, body: { identityId: ident.id, audience } });
    return { identityId: ident.id, keyId: key.id, audience, subject: ident.federation.subject, nodes: this.nodes() };
  }
  // The token the kubelet projects into the pod on a node: short-lived, audience-bound, naming the node.
  projectedToken(ident, node, aud) {
    return this.mint({ issuer: 'kube', claims: { sub: ident.federation.subject, aud, extra: { node, pod: 'node-sensor-pod' } }, times: { exp: 3600, iat: 0 } }).mintedToken;
  }
  policyFor(identityId) { return this.s.policies.get(identityId) || null; }
  decide(policy, f) {
    if (!policy) return { action: null, effect: 'no-policy', note: 'no policy is bound to this identity' };
    if (policy.mode === 'off') return { action: policy.actions[f.kind], effect: 'off', note: 'the policy is off: nothing is evaluated' };
    if (!policy.scope.all && !policy.scope.namespaces.includes(f.namespace)) return { action: policy.actions[f.kind], effect: 'out-of-scope', note: 'this namespace is not in the policy\'s scope' };
    const action = policy.actions[f.kind];
    if (action === 'deny') return policy.mode === 'enforce' ? { action, effect: 'blocked', note: 'enforce: the sensor terminates it' } : { action, effect: 'would-have-blocked', note: 'audit: recorded, not blocked' };
    return { action, effect: action === 'allow' ? 'allowed' : action === 'monitor' ? 'monitored' : 'warned', note: '' };
  }
  setPolicy(input = {}) {
    strictKeys(input, ['identityId', 'mode', 'scope', 'actions'], 'the policy');
    const ident = this.sensorIdentity(input.identityId); need(ident, 'unknown_sensor', 'no such self-hosted agent', 404);
    need(POLICY_MODES.includes(input.mode), 'bad_mode', `mode must be ${POLICY_MODES.join(', ')}`);
    need(isObj(input.scope) && Object.keys(input.scope).every((k) => ['all', 'namespaces'].includes(k)), 'bad_scope', 'scope is { all } or { namespaces }');
    const all = input.scope.all === true; need(input.scope.all === undefined || typeof input.scope.all === 'boolean', 'bad_scope', 'scope.all must be true or false');
    const ns = input.scope.namespaces === undefined ? [] : input.scope.namespaces;
    need(Array.isArray(ns) && ns.length <= LIMITS.namespaces && new Set(ns).size === ns.length && ns.every((x) => typeof x === 'string' && K8S_NAME.test(x) && !credentialShaped(x)), 'bad_scope', `namespaces is at most ${LIMITS.namespaces} plain namespace names`);
    need(all !== ns.length > 0, 'bad_scope', 'name the namespaces, or choose the whole cluster, not both and not neither');
    need(isObj(input.actions) && Object.keys(input.actions).length === FINDING_KINDS.length && FINDING_KINDS.every((k) => Object.hasOwn(input.actions, k) && POLICY_ACTIONS.includes(input.actions[k])), 'bad_actions', `actions gives each of ${FINDING_KINDS.join(', ')} one of ${POLICY_ACTIONS.join(', ')}`);
    this.s.policies.set(ident.id, { identityId: ident.id, mode: input.mode, scope: { all, namespaces: all ? [] : [...ns] }, actions: Object.fromEntries(FINDING_KINDS.map((k) => [k, input.actions[k]])) });
    this.audit('policy.set', { identityId: ident.id, principal: `identity ${ident.name}`, note: `${input.mode}, ${all ? 'whole cluster' : `namespaces ${ns.join(', ')}`}` });
    return { identityId: ident.id, mode: input.mode };
  }
  // A simulated sensor report. The reporting node comes from the verified token's claims; a node field in the body is ignored and recorded as ignored.
  sensorReport(input = {}) {
    strictKeys(input, ['identityId', 'node', 'tokenFrom', 'token', 'body'], 'the report');
    const ident = this.sensorIdentity(input.identityId); need(ident, 'unknown_sensor', 'no such self-hosted agent', 404);
    need(typeof input.node === 'string' && this.nodes().includes(input.node), 'bad_node', 'node must be one of the lab\'s nodes');
    const from = input.tokenFrom === undefined ? 'projected' : input.tokenFrom; need(['projected', 'gateway-audience'].includes(from), 'bad_token_source', 'tokenFrom is projected or gateway-audience');
    need(input.token === undefined || typeof input.token === 'string', 'bad_token', 'token must be text');
    need(isObj(input.body) && Object.keys(input.body).every((k) => ['node', 'findings'].includes(k)), 'bad_body', 'body is { node, findings }');
    const list = input.body.findings;
    need(Array.isArray(list) && list.length >= 1 && list.length <= LIMITS.findingsPerReport, 'bad_findings', `a report carries 1 to ${LIMITS.findingsPerReport} findings`);
    const findings = list.map((x) => {
      need(isObj(x) && Object.keys(x).every((k) => ['kind', 'name', 'namespace', 'pod'].includes(k)), 'bad_findings', 'each finding is { kind, name, namespace, pod }');
      need(typeof x.kind === 'string' && FINDING_KINDS.includes(x.kind), 'bad_findings', `kind is ${FINDING_KINDS.join(', ')}`);
      strictValue(x.name, SAFE_NAME, 'bad_findings', 'a finding name is short and plain');
      need(typeof x.namespace === 'string' && K8S_NAME.test(x.namespace) && !credentialShaped(x.namespace) && typeof x.pod === 'string' && K8S_NAME.test(x.pod) && !credentialShaped(x.pod), 'bad_findings', 'namespace and pod are plain Kubernetes names');
      return { kind: x.kind, name: x.name, namespace: x.namespace, pod: x.pod };
    });
    need(this.s.findings.length + findings.length <= LIMITS.findings, 'workspace_full', `a workspace keeps at most ${LIMITS.findings} findings: Reset`, 409);
    const bodyNode = input.body.node === undefined ? null : cleanFree(typeof input.body.node === 'string' ? input.body.node : JSON.stringify(input.body.node), 40);

    const token = input.token !== undefined ? input.token : this.projectedToken(ident, input.node, from === 'gateway-audience' ? `https://gateway.${this.cast.castHost}.example` : ident.federation.audience);
    const r = this.verifyCore({ token, identityId: ident.id, scope: 'shadowai:write' });
    const claimNode = r.ok ? this.claimNodeOf(token) : null;
    let outcome = r;
    if (r.ok && !claimNode) outcome = { ...r, ok: false, status: 401, code: 'node_claim_missing', detail: 'the verified token names no node, so the report cannot be attributed to one', callerSees: STATUS_TEXT[401] };
    if (!outcome.ok) {
      this.audit('sensor.report', { outcome: 'refused', code: outcome.code, identityId: ident.id, claimed: typeof r.claims?.node === 'string' ? r.claims.node : undefined, status: outcome.status });
      return outcome;
    }
    const policy = this.policyFor(ident.id);
    const reportId = `rep-${pad(++this.s.seq.report)}`;
    const stored = findings.map((f) => {
      const d = this.decide(policy, f);
      return { id: `find-${pad(++this.s.seq.finding)}`, reportId, ...f, node: claimNode, nodeSource: 'token claim', identityId: ident.id, identityName: ident.name, at: iso(this.s.now), action: d.action, effect: d.effect, note: d.note };
    });
    this.s.findings.push(...stored);
    const rep = { id: reportId, at: iso(this.s.now), identityId: ident.id, node: claimNode, nodeSource: 'token claim', bodyNode, bodyNodeIgnored: bodyNode !== null, bodyNodeDiffers: bodyNode !== null && bodyNode !== claimNode, findings: stored.length,
      wouldHaveBlocked: stored.filter((x) => x.effect === 'would-have-blocked').length, blocked: stored.filter((x) => x.effect === 'blocked').length };
    this.s.reports.push(rep); if (this.s.reports.length > LIMITS.reports) this.s.reports.shift();
    this.audit('sensor.report', { outcome: 'allowed', identityId: ident.id, principal: r.principal, deployment: r.deployment, node: claimNode, note: rep.bodyNodeIgnored ? `the body's node field was ignored${rep.bodyNodeDiffers ? ' (it differed from the token)' : ''}` : undefined, status: 200 });
    this.hop('sensor report accepted: node taken from the token claims', { method: 'POST', url: `https://console.${this.cast.castHost}.example/v1/shadowai/reports` }, { status: 200, body: { node: claimNode, nodeSource: 'token claim', bodyNodeIgnored: rep.bodyNodeIgnored } });
    return { ...r, report: rep, findings: stored };
  }
  claimNodeOf(token) { const p = parseToken(token); return p.ok && typeof p.payload.node === 'string' && K8S_NAME.test(p.payload.node) ? p.payload.node : null; }

  // ---------- the whole state as the page reads it -----------------------------------------------------------------------------------------------------
  snapshot() {
    const s = this.s;
    const idView = (i) => {
      const f = i.federation; const c = i.cache;
      return { id: i.id, name: i.name, description: i.description, kind: i.kind, platform: i.platform, enabled: i.enabled, scopes: [...i.scopes], notAfter: i.notAfter, createdAt: i.createdAt,
        federation: { issuer: f.issuer, subject: f.subject, audience: f.audience, jwksUri: f.jwksUri, pinnedKids: f.pinned ? f.pinned.map((k) => k.kid) : [], maxTokenLifetimeSec: f.maxTokenLifetimeSec, effectiveCapSec: f.maxTokenLifetimeSec || DEFAULT_MAX_LIFETIME, requiredClaims: { ...f.requiredClaims }, allowAnySubject: f.allowAnySubject },
        keyset: { source: c.source, kids: c.keys.map((k) => k.kid), lastAttemptAt: iso(c.lastAttemptAt), cooldownUntil: c.lastUnknownKidAt === undefined || c.lastUnknownKidAt + LIMITS.unknownKidCooldownSec <= s.now ? null : iso(c.lastUnknownKidAt + LIMITS.unknownKidCooldownSec), nextRefreshAt: c.nextRefreshAt === null ? null : iso(c.nextRefreshAt), last: { ...c.last }, log: c.log.map((x) => ({ ...x })) },
        keys: this.keysOf(i.id).map((k) => k.id) };
    };
    return {
      clock: { now: s.now, at: iso(s.now), startedAt: iso(BASE_SECONDS), advancedMin: s.advancedMin, perMoveCapMin: LIMITS.clockPerMoveMin, totalCapMin: LIMITS.clockTotalMin, refreshSeconds: REFRESH_SECONDS, defaultMaxLifetimeSec: DEFAULT_MAX_LIFETIME },
      issuers: ISSUERS.map((m) => { const st = s.issuers.get(m.id); return { id: m.id, name: m.name, platform: m.platform, url: m.url, jwksUri: m.jwksUri, standsFor: m.standsFor, up: st.up, kid: this.kidOf(m.id, st.g), generation: st.g, rotationsLeft: GENERATIONS - 1 - st.g, published: st.published.map((g) => this.kidOf(m.id, g)) }; }),
      identities: [...s.identities.values()].map(idView),
      keys: [...s.keys.values()].map((k) => { const ident = k.owner.kind === 'identity' ? this.identity(k.owner.ref) : null; return { id: k.id, name: k.name, auth: k.auth, owner: { ...k.owner }, ownerName: ident ? ident.name : k.owner.kind === 'human' ? k.owner.ref : null, ownerMissing: k.owner.kind === 'identity' && !ident, scopes: [...k.scopes], effectiveScopes: ident ? this.effectiveScopes(ident, k) : [...k.scopes], enabled: k.enabled, principalLabel: k.owner.kind === 'human' ? `person ${k.owner.ref} (borrowed)` : ident ? `identity ${ident.name}` : 'identity (removed)' }; }),
      people: [...s.humans.values()].map((h) => ({ ...h })),
      backends: this.backendList.map((b) => ({ ...b })),
      audit: [...s.audit.changes, ...s.audit.requests, ...s.audit.refusals].sort((a, b) => a.n - b.n).map((a) => ({ ...a })), auditDropped: { ...s.auditDropped },
      sensors: [...s.sensors.values()].map((x) => { const i = this.identity(x.identityId); return { identityId: x.identityId, name: i?.name, enabled: i?.enabled, audience: i?.federation.audience, subject: i?.federation.subject, enrolledAt: x.enrolledAt, policy: this.policyFor(x.identityId) ? JSON.parse(JSON.stringify(this.policyFor(x.identityId))) : null, findings: s.findings.filter((f) => f.identityId === x.identityId).length }; }),
      nodes: this.nodes(), namespaces: this.workNamespaces(),
      findings: s.findings.map((f) => ({ ...f })), reports: s.reports.map((r) => ({ ...r })),
      limits: { ...LIMITS },
    };
  }
}
