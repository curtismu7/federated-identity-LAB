// Scripted scenarios: each is a list of engine operations run through the SAME dispatch the API uses (actions.js), on a fresh Engine with a deterministic random
// source. The Mock tables are generated from this run, so they cannot drift from the engine (a doctor check and a test fail on drift). A step may reuse the last
// minted token ('last') or a tampered copy of it ('tampered'). Tokens themselves are never stored in a table: only their decoded header and claims.
import crypto from 'node:crypto';
import { Engine } from './engine.js';
import { perform } from './actions.js';
import { PRESETS } from './data.js';
import { VERTICALS, fillDeep } from './cast.js';
import { tamperToken } from './jwt.js';

// A deterministic stand-in for crypto.randomBytes: the same calls give the same bytes.
export function seededRand(label = 'federated-identity-lab') {
  let n = 0;
  return (len) => crypto.createHash('sha256').update(`${label}:${++n}`).digest().subarray(0, len);
}

export function scenarioList(cast) {
  const P = Object.fromEntries(fillDeep(PRESETS, cast).map((p) => [p.id, p]));
  const mint = (id, say) => ({ say: say || `Mint: ${P[id].title}.`, op: 'mint', params: P[id].mint });
  const verify = (id, say, extra = {}) => ({ say: say || `Present it to ${P[id].service}.`, op: 'verify', params: { identityId: P[id].identityId, service: P[id].service, ...extra }, token: 'last' });
  const pair = (id) => [mint(id), verify(id)];
  const GW = `https://gateway.${cast.castHost}.example`;
  const k8sSub = `system:serviceaccount:${cast.castNs}:${cast.castAgent}`;
  const body = (node, findings) => ({ node, findings });
  const finding = (kind, name, ns, pod) => ({ kind, name, namespace: ns, pod });
  const reportFindings = [finding('model-server', 'vllm-server', cast.castNs, 'vllm-0'), finding('model-server', 'ollama', cast.castNs3, 'ollama-0'), finding('mcp-server', 'ledger-tools', cast.castNs, 'tools-0')];
  const policy = (mode) => ({ identityId: 'fid-006', mode, scope: { namespaces: [cast.castNs] }, actions: { 'ai-agent': 'monitor', 'mcp-server': 'warn', 'model-server': 'deny' } });
  return [
    { id: 'one-credential', title: 'One credential, three services', say: 'The Kubernetes identity for one ServiceAccount: a token the platform issued is allowed to the MCP server and to the peer agent, and refused for the LLM provider because the scope is not on the key.',
      steps: [mint('k8s-right'), verify('k8s-right', 'Present it to the MCP server: allowed.'), verify('k8s-right', 'The same token to the peer agent (A2A): allowed.', { service: 'a2a' }), verify('k8s-right', 'The same token to the LLM provider: the scope is not on the key.', { service: 'llm' })] },
    { id: 'exact-binding', title: 'Exact binding: subject, issuer, audience', say: 'Another ServiceAccount, the same name in another namespace, a token from another issuer, no audience and the wrong audience are each refused at their own step.',
      steps: ['k8s-wrong-subject', 'k8s-wrong-namespace', 'k8s-wrong-issuer', 'k8s-no-aud', 'k8s-wrong-aud'].flatMap(pair) },
    { id: 'fork-pr', title: 'A key bound to main cannot be used by a pull request', say: 'GitHub Actions: main of the right repository is allowed; a pull request, a pull request from a fork, the wrong environment and a missing pinned claim are refused.',
      steps: ['gh-right', 'gh-pr', 'gh-fork-pr', 'gh-staging', 'gh-no-env'].flatMap(pair) },
    { id: 'lifetimes', title: 'Enforced lifetimes', say: 'Expired, unexpired but minted to live two hours, no expiry, issued in the future and not valid yet are refused; a good token is allowed, and refused once the lab clock passes its expiry.',
      steps: [...['k8s-expired', 'k8s-long-lived', 'k8s-no-exp', 'k8s-future-iat', 'k8s-nbf'].flatMap(pair), ...pair('k8s-right'), { say: 'Move the lab clock 61 minutes.', op: 'advance', params: { minutes: 61 } }, verify('k8s-right', 'The same token again: it has expired.')] },
    { id: 'algorithms', title: 'Algorithms and tampering', say: 'alg none, HS256 signed with the public key, an ES256 header, an attacker\'s key (under the issuer\'s kid and under its own), no kid, and a payload altered after signing.',
      steps: [...['alg-none', 'alg-hs256', 'alg-es256', 'attacker-forged-kid', 'attacker-own-kid', 'no-kid'].flatMap(pair), mint('k8s-right', 'Mint a good token.'), { ...verify('k8s-right', 'Alter the payload after signing and present it.'), token: 'tampered' }] },
    { id: 'keyset-refresh', title: 'An unknown signing key triggers a refresh', say: 'The issuer rotates. A token signed by the new key has a kid the gateway does not know: it refreshes the key set and the token verifies. A token signed by the retired key does not.',
      steps: [{ say: 'Rotate the Kubernetes issuer\'s key.', op: 'issuer', params: { issuer: 'kube', action: 'rotate' } }, mint('k8s-right', 'Mint a token with the new key.'), verify('k8s-right', 'Present it: unknown kid, refresh, verified.'),
        { say: 'Mint a token with the retired key.', op: 'mint', params: { ...P['k8s-right'].mint, generation: 0 } }, verify('k8s-right', 'Present it: the key is no longer published.')] },
    { id: 'issuer-outage', title: 'The issuer is down: the last known good key set carries on', say: 'With the issuer down, a token signed by a key the gateway already holds still verifies. A token signed by a key rotated in during the outage cannot be resolved. When the issuer returns it is.',
      steps: [mint('k8s-right', 'Mint a token with the current key.'), { say: 'Take the issuer down.', op: 'issuer', params: { issuer: 'kube', action: 'down' } }, verify('k8s-right', 'Present it: the cached key set is the last known good one.'),
        { say: 'The issuer rotates while it is down.', op: 'issuer', params: { issuer: 'kube', action: 'rotate' } }, mint('k8s-right', 'Mint a token with the new key.'), verify('k8s-right', 'Present it: unknown kid, and the refresh fails.'),
        { say: 'Bring the issuer back.', op: 'issuer', params: { issuer: 'kube', action: 'up' } }, verify('k8s-right', 'Present it again: the refresh succeeds.'), { say: 'Move the lab clock fifteen minutes.', op: 'advance', params: { minutes: 15 } }] },
    { id: 'private-pinned', title: 'A private issuer with pinned keys', say: 'The private issuer has no address to fetch from. After it rotates its key the pinned set has no such kid and nothing to refresh from, until the keys are pinned again.',
      steps: [...pair('private-right'), { say: 'The private issuer rotates its key.', op: 'issuer', params: { issuer: 'private', action: 'rotate' } }, mint('private-right', 'Mint with the new key.'), verify('private-right', 'Present it: the pinned set does not hold it.'),
        { say: 'Pin the issuer\'s current public key again.', op: 'updateIdentity', params: { identityId: 'fid-005', federation: { pinFromIssuer: 'private' } } }, verify('private-right', 'Present it again.')] },
    { id: 'revocation', title: 'Revocation and per-deployment attribution', say: 'Two pods of one ServiceAccount are attributed separately. Revoke the identity: the very next request is refused. Restore it, then remove it: the gateway can find no identity for the token.',
      steps: [{ say: 'Mint a token for one pod.', op: 'mint', params: { ...P['k8s-right'].mint, claims: { ...P['k8s-right'].mint.claims, extra: { pod: `${cast.castAgent}-aaaa` } } } }, verify('k8s-right', 'Present it: allowed, attributed to that pod.'),
        { say: 'Mint a token for another pod.', op: 'mint', params: { ...P['k8s-right'].mint, claims: { ...P['k8s-right'].mint.claims, extra: { pod: `${cast.castAgent}-bbbb` } } } }, verify('k8s-right', 'Present it: allowed, attributed to the other pod.'),
        { say: 'Revoke the identity (Enabled false).', op: 'updateIdentity', params: { identityId: 'fid-001', enabled: false } }, verify('k8s-right', 'The very next request is refused.'),
        { say: 'Restore it.', op: 'updateIdentity', params: { identityId: 'fid-001', enabled: true } }, verify('k8s-right', 'Allowed again.'),
        { say: 'Remove the identity.', op: 'deleteIdentity', params: { identityId: 'fid-001' } }, { say: 'The gateway looks for an identity by issuer and subject: none.', op: 'verify', params: { service: 'mcp' }, token: 'last' }] },
    { id: 'key-owner', title: 'A key owned by an identity, or by a person', say: 'A key can name an identity as its owner; the console refuses two contradictory forms. When the person who owns a stored key goes inactive that key stops, and the identity-owned key does not. An identity with no key behind it authenticates nobody.',
      steps: [{ say: 'Create a key owned by the Kubernetes identity.', op: 'createKey', params: { name: 'narrow key', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] } },
        { say: 'The same, but the key also carries its own workload identity.', op: 'createKey', params: { name: 'both', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], ownFederation: true } },
        { say: 'The same, but the key also names a person.', op: 'createKey', params: { name: 'both', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'], userRef: cast.castOwner } },
        { say: 'The stored key that borrows a person calls MCP: allowed.', op: 'storedKeyCall', params: { keyId: 'key-0006', service: 'mcp' } },
        { say: 'The person becomes inactive.', op: 'setPerson', params: { person: cast.castOwner, active: false } },
        { say: 'The stored key is refused.', op: 'storedKeyCall', params: { keyId: 'key-0006', service: 'mcp' } },
        mint('k8s-right'), verify('k8s-right', 'The identity-owned key is unaffected.'),
        { say: 'Remove both keys the identity owns.', op: 'deleteKey', params: { keyId: 'key-0001' } }, { say: 'And the new one.', op: 'deleteKey', params: { keyId: 'key-0007' } }, verify('k8s-right', 'With no key behind it the identity authenticates nobody.')] },
    { id: 'platforms', title: 'Four platforms, one gateway', say: 'GitHub Actions to MCP, GitLab CI to the LLM provider, a SPIFFE JWT-SVID to a peer agent, and a private issuer with pinned keys: each verified the same way.',
      steps: ['gh-right', 'gitlab-right', 'spiffe-right', 'private-right'].flatMap(pair) },
    { id: 'sensor', title: 'The sensor reports with its own token', say: 'Enrol a sensor and it reports with a token minted for a generated audience. The node comes from the token: a forged node in the body is ignored. A token for another audience is refused. Revoke the identity and the next report is refused; the findings stay.',
      steps: [{ say: 'Enrol a Kubernetes sensor as a self-hosted agent.', op: 'enrollSensor', params: { name: 'node sensor' } },
        { say: `The sensor on ${cast.castNode1} reports; the body claims another node.`, op: 'sensorReport', params: { identityId: 'fid-006', node: cast.castNode1, body: body(cast.castNode3, reportFindings.slice(0, 2)) } },
        { say: 'A report with a token minted for the gateway audience.', op: 'sensorReport', params: { identityId: 'fid-006', node: cast.castNode2, tokenFrom: 'gateway-audience', body: body(undefined, reportFindings.slice(0, 1)) } },
        { say: 'Revoke the sensor\'s identity.', op: 'updateIdentity', params: { identityId: 'fid-006', enabled: false } },
        { say: 'The next report is refused.', op: 'sensorReport', params: { identityId: 'fid-006', node: cast.castNode1, body: body(undefined, reportFindings.slice(0, 1)) } }] },
    { id: 'enforcement', title: 'Enforcement: audit first, then enforce', say: 'A policy bound to the sensor\'s identity: in audit mode a denied finding is recorded as would-have-blocked; in enforce mode the same report is blocked; a finding outside the named namespaces is not evaluated.',
      steps: [{ say: 'Enrol a sensor.', op: 'enrollSensor', params: { name: 'node sensor' } }, { say: 'Bind an audit policy to one namespace.', op: 'setPolicy', params: policy('audit') },
        { say: 'Report: one model server would have been blocked, one is out of scope.', op: 'sensorReport', params: { identityId: 'fid-006', node: cast.castNode1, body: body(undefined, reportFindings) } },
        { say: 'Switch the policy to enforce.', op: 'setPolicy', params: policy('enforce') },
        { say: 'Report the same findings again: the model server is blocked.', op: 'sensorReport', params: { identityId: 'fid-006', node: cast.castNode1, body: body(undefined, reportFindings) } }] },
  ];
}

// The result each step must give: 'ok' or the refusal code.
export const EXPECTED = {
  'one-credential': ['ok', 'ok', 'ok', 'scope_not_on_key'],
  'exact-binding': ['ok', 'subject_mismatch', 'ok', 'subject_mismatch', 'ok', 'issuer_mismatch', 'ok', 'aud_missing', 'ok', 'aud_mismatch'],
  'fork-pr': ['ok', 'ok', 'ok', 'subject_mismatch', 'ok', 'subject_mismatch', 'ok', 'required_claim_mismatch', 'ok', 'required_claim_missing'],
  lifetimes: ['ok', 'expired', 'ok', 'lifetime_exceeds_cap', 'ok', 'exp_missing', 'ok', 'iat_in_future', 'ok', 'not_yet_valid', 'ok', 'ok', 'ok', 'expired'],
  algorithms: ['ok', 'alg_none', 'ok', 'alg_symmetric', 'ok', 'alg_unsupported_by_lab', 'ok', 'bad_signature', 'ok', 'unknown_kid', 'ok', 'kid_missing', 'ok', 'bad_signature'],
  'keyset-refresh': ['ok', 'ok', 'ok', 'ok', 'unknown_kid'],
  'issuer-outage': ['ok', 'ok', 'ok', 'ok', 'ok', 'unknown_kid', 'ok', 'ok', 'ok'],
  'private-pinned': ['ok', 'ok', 'ok', 'ok', 'unknown_kid', 'ok', 'ok'],
  revocation: ['ok', 'ok', 'ok', 'ok', 'ok', 'identity_disabled', 'ok', 'ok', 'ok', 'no_matching_identity'],
  'key-owner': ['ok', 'mutually_exclusive', 'principal_conflict', 'ok', 'ok', 'owner_inactive', 'ok', 'ok', 'ok', 'ok', 'no_key_behind_identity'],
  platforms: ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok'],
  sensor: ['ok', 'ok', 'aud_mismatch', 'ok', 'identity_disabled'],
  enforcement: ['ok', 'ok', 'ok', 'ok', 'ok'],
};

const sanitize = (x) => JSON.parse(JSON.stringify(x, (k, v) => (k === 'mintedToken' ? undefined : v)));

// Runs one scenario on a fresh Engine. Returns { steps: [{ say, op, ok, status, code, detail, result }], state }.
export function runScenario(cast, sc) {
  const e = new Engine(cast, { rand: seededRand() });
  let token = ''; const steps = [];
  for (const st of sc.steps) {
    const params = { ...st.params };
    if (st.token) params.token = st.token === 'tampered' ? tamperToken(token) : token;
    const r = perform(e, st.op, params);
    if (st.op === 'mint' && r.ok) token = r.result.mintedToken;
    steps.push({ say: st.say, op: st.op, ok: r.ok, status: r.ok ? 200 : r.status, code: r.ok ? undefined : r.code, detail: r.ok ? undefined : r.detail, result: sanitize(r.ok ? r.result : r.result || null) });
  }
  return { steps, state: e.snapshot() };
}

export function buildMockTable() {
  const verticals = {};
  for (const [name, cast] of Object.entries(VERTICALS)) {
    verticals[name] = { scenarios: scenarioList(cast).map((sc) => { const { steps, state } = runScenario(cast, sc); return { id: sc.id, title: sc.title, say: sc.say, steps, state }; }) };
  }
  return sanitize({ schema: 'fid-mock-table/1', verticals });
}
