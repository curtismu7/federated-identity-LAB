// Builds content-pack.json for the Learning Hub from the story data, so the pack cannot drift from the lab.
//   node scripts/build-content-pack.mjs        (writes content-pack.json)
// The pack uses .invalid placeholders and no documentation URLs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CAST } from '../server/src/cast.js';
import { buildStory } from '../server/src/story.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const UNV = 'Ping release claim, UNVERIFIED on our tenant.';

export function buildPack() {
  const story = buildStory(DEFAULT_CAST, 'finance');
  const sid = (n) => `S${String(n).padStart(2, '0')}`;
  const terms = {
    'one-credential': ['federated-identity', 'key-owned'], 'exact-binding': ['exact-binding'], 'fork-pr': ['exact-binding', 'pinned-claims'], lifetimes: ['enforced-lifetimes'], algorithms: ['enforced-lifetimes'],
    'keyset-refresh': ['key-set'], 'issuer-outage': ['key-set'], 'private-pinned': ['key-set'], revocation: ['federated-identity', 'attribution'], 'key-owner': ['key-owned'], platforms: ['deployment-models'], sensor: ['self-hosted-agents', 'node-from-claims'], enforcement: ['enforcement-policy'],
  };
  const why = (id) => story.talkTrack.find((t) => t.id === id).say;
  return {
    schema: 'demo-content-pack/1',
    id: 'federated-identity-lab',
    title: 'Federated Identity LAB',
    version,
    demo: { id: 'federated-identity-lab', name: 'Federated Identity LAB', catalog: 'D107', baseUrl: 'http://localhost:7400', doctor: '/api/health', tags: ['federated-identity', 'self-hosted-agents', 'workload-identity', 'jwt', 'jwks', 'revocation', 'kubernetes-sensor', 'simulated'] },
    glossary: [
      { id: 'federated-identity', term: 'Federated Identity', definition: `Platform-issued, short-lived identity for agents: the workload presents the token its own platform issues (a Kubernetes service-account token, a GitHub Actions or GitLab CI job token, a SPIFFE JWT-SVID, or any OIDC token with published keys) and nothing long-lived is stored in it. The new display name of Non-Human Identity (slide 35); the console API object is still NonHumanIdentity at /v1/nonhumanidentities (console swagger name, schema only). Slide 57 still says Non-Human Identity. ${UNV}`, aliases: ['Non-Human Identity', 'NHI', 'NonHumanIdentity'] },
      { id: 'exact-binding', term: 'Exact identity binding', definition: `Issuer and subject are matched exactly and the audience is mandatory, so a key bound to one ServiceAccount, or to one repository on main, cannot be used by anything else, including a pull request from a fork. The lab compares strings exactly (no case folding, no trailing-slash tolerance). ${UNV}`, aliases: ['issuer', 'subject', 'audience'] },
      { id: 'pinned-claims', term: 'Pinned claims', definition: `Additional claims (repository, workflow, environment) can be pinned and must be present and match exactly. The claim names the lab uses are its own flat names (lab-invented); RequiredClaims is a console swagger name (schema only). ${UNV}`, aliases: ['RequiredClaims'] },
      { id: 'enforced-lifetimes', term: 'Enforced lifetimes', definition: `Expiry is required and the lifetime is capped (default one hour), so a workload that signs its own tokens cannot choose its own validity window; only asymmetric algorithms are accepted (none and HS* are refused). The lab reads lifetime as exp minus iat (a lab reading of the swagger description of MaxTokenLifetimeSec) and verifies RS256 only (a lab limit). ${UNV}`, aliases: ['lifetime cap', 'MaxTokenLifetimeSec'] },
      { id: 'key-set', term: 'Resilient key handling', definition: `The issuer's key set is validated when the identity is created, refreshed every fifteen minutes and on sight of an unknown signing key, and the last known good set is kept through issuer outages; private issuers use pinned key material. Time in the lab is a lab clock. ${UNV}`, aliases: ['JWKS', 'last known good'] },
      { id: 'key-owned', term: 'A key owned by an identity', definition: `An agent access key can name a Federated Identity as the principal it acts as, instead of borrowing a human owner (console swagger name CustodianRef, schema only). The refusals shown for a key that also carries its own workload identity or names a person are measured on our tenant (our note, 2026-10-21), not the deck's. ${UNV}`, aliases: ['CustodianRef'] },
      { id: 'backend-isolation', term: 'Backend isolation', definition: `The token stops at the gateway and is never forwarded; backends receive the application's own configured credential (static, per-user from the vault, or OAuth), shown masked because the lab holds none. The console swagger also lists a token-pass mode that forwards the assertion: shown, not resolved. ${UNV}`, aliases: ['token pass-through'] },
      { id: 'deployment-models', term: 'Five deployment models', definition: `Direct token read, per-job CI/CD tokens, SPIFFE/SPIRE, a stored agent key as the fallback, and sidecar injection, which is in development on the slide: the lab claims no behaviour for it. ${UNV}`, aliases: [] },
      { id: 'attribution', term: 'Per-deployment attribution and revocation', definition: `Every request is attributed to a specific deployment (the lab names it from namespace and service account and pod, or repository and ref and run: a lab reading) and revoking the identity (Enabled false, the console swagger's only kill switch) cuts the workload off at once. We did not measure revocation speed on our tenant. ${UNV}`, aliases: ['revocation'] },
      { id: 'self-hosted-agents', term: 'Self-Hosted Agents', definition: `A platform component acting as its own non-human principal: an identity the platform issued, a short-lived token minted for a Privilege-generated audience and projected into the pod, verified on every report. The new name of NHI Agents Discovery & Enforcement. The first one is the Kubernetes eBPF sensor; the lab runs no eBPF and simulates the reports. ${UNV}`, aliases: ['NHI Agents Discovery & Enforcement', 'Kubernetes sensor'] },
      { id: 'node-from-claims', term: 'Verified, not vouched', definition: `The controller verifies issuer, subject, audience and scope on every report and takes the reporting node from the token's claims, not the sender's word, so a compromised agent cannot misattribute its findings. The claim is named node in the lab (lab-invented). ${UNV}`, aliases: [] },
      { id: 'enforcement-policy', term: 'Enforcement policy', definition: `A policy bound to a Federated Identity decides what that agent may do, scoped to named namespaces or the whole cluster, with modes off, audit and enforce and actions allow, monitor, warn and deny; audit mode records every decision that would have blocked without blocking. The console swagger names seven actions and a Disabled flag: shown, not resolved. Nothing is terminated in the lab. ${UNV}`, aliases: ['audit mode'] },
    ],
    sources: [
      { id: 'deck-slides', title: 'Ping ID4AI Workforce H2 2026 deck, slides 35, 40, 41 and 44', url: 'https://example.invalid/ping-id4ai-workforce-h2-2026-deck', kind: 'deck', use: 'The Federated Identity and Self-Hosted Agents release claims and the renaming.', status: 'read', checked: '2026-10-31' },
      { id: 'console-swagger', title: 'Privilege console swagger, 2026-10-31 (schema only)', url: 'https://example.invalid/privilege-console-swagger', kind: 'schema', use: 'Field names for NonHumanIdentity, AgentWorkloadIdentity, CustodianRef and the shadow-AI policy. It proves names exist, not behaviour.', status: 'read', checked: '2026-10-31' },
      { id: 'our-notes', title: 'Our own earlier tests on the pre-release gateway (measured, our note)', url: 'https://example.invalid/our-measured-notes', kind: 'measurement', use: 'Where our test of the MCP path did not prove workload-token acceptance, and the two key refusals.', status: 'read', checked: '2026-10-31' },
    ],
    cards: [
      ...story.scenarios.map((sc, i) => ({ id: `try-${sc.id}`, label: `Scenario ${i + 1}: ${sc.title}`, description: sc.say, group: 'try-it', action: { type: 'route', href: '/#verify' }, terms: terms[sc.id], story: sid(i + 1) })),
      { id: 'try-tamper', label: 'Tamper with a token', description: 'Mint a good token, change the subject, keep the signature, and verify: the real RS256 check fails.', group: 'try-it', action: { type: 'route', href: '/#verify' }, terms: ['enforced-lifetimes'] },
      { id: 'try-revoke', label: 'Revoke an identity', description: 'Revoke it and send the very next request: refused, and the audit log says why.', group: 'try-it', action: { type: 'route', href: '/#audit' }, terms: ['attribution'] },
      { id: 'concept-why-federated-identity', label: 'Why it matters: Federated Identity (slide 40)', description: why('why-federated-identity'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['federated-identity', 'exact-binding'] },
      { id: 'concept-why-self-hosted-agents', label: 'Why it matters: Self-Hosted Agents (slide 41)', description: why('why-self-hosted-agents'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['self-hosted-agents', 'node-from-claims'] },
      { id: 'concept-mcp-acceptance', label: 'Accepted across the MCP and LLM gateways: the deck says so, our test did not prove it', description: story.discrepancies.find((d) => d.id === 'mcp-acceptance').text, group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['federated-identity'] },
      { id: 'concept-naming', label: 'Federated Identity versus Non-Human Identity', description: story.discrepancies.find((d) => d.id === 'naming').text, group: 'concept', action: { type: 'route', href: '/#identities' }, terms: ['federated-identity'] },
      { id: 'concept-diagram', label: 'Diagrams', description: 'Three diagrams: the Federated Identity flow, the verification steps, and a Self-Hosted Agent.', group: 'concept', action: { type: 'route', href: '/#diagram' }, terms: ['key-set', 'self-hosted-agents'] },
      { id: 'ref-doctor', label: 'Doctor and health', description: 'Preflight checks and the demo-health/1 endpoint.', group: 'setup', action: { type: 'route', href: '/api/health' } },
    ],
    stories: story.scenarios.map((sc, i) => ({ id: sid(i + 1), title: sc.title, say: sc.say })),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fs.writeFileSync(path.join(ROOT, 'content-pack.json'), `${JSON.stringify(buildPack(), null, 2)}\n`);
  console.log('wrote content-pack.json');
}
