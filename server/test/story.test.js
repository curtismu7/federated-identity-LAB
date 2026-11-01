import test from 'node:test';
import assert from 'node:assert/strict';
import { buildStory } from '../src/story.js';
import { DEFAULT_CAST, VERTICALS } from '../src/cast.js';
import { AVAILABILITY, BANNER, CLAIM_LABEL, CLAIMS, DISCREPANCIES, FIELD_SOURCES, FIELD_SOURCE_NAMES, MEASURED, NOT_DEMONSTRATED, PRESETS, TALK_TRACK, WHY, WHY_TEXT } from '../src/data.js';
import { DEPLOYMENT_MODELS, SCOPES } from '../src/catalog.js';
import { scanHosts, scanKeys } from '../src/safety.js';
import { findCredentials } from '../src/credentials.js';

const s = buildStory(DEFAULT_CAST, 'finance');

test('both banners say SIMULATED, name their mode, carry the unverified label and the release', () => {
  for (const m of ['mock', 'live']) { assert.match(BANNER[m], new RegExp(`^SIMULATED, ${m.toUpperCase()} mode`)); assert.ok(BANNER[m].includes(CLAIM_LABEL)); assert.ok(BANNER[m].includes('2026-11-02')); assert.match(BANNER[m], /UNVERIFIED on our tenant/); }
  assert.match(BANNER.live, /loopback only, zero outbound network/);
});

test('every claim names its slide (40 or 41) and the deck rows are all present', () => {
  for (const c of CLAIMS) { assert.ok([40, 41].includes(c.slide), c.id); assert.ok(c.claim.length > 40, c.id); }
  assert.equal(CLAIMS.filter((c) => c.slide === 40).length, 9); assert.equal(CLAIMS.filter((c) => c.slide === 41).length, 6);
  const text = CLAIMS.map((c) => c.claim).join(' ');
  for (const w of ['Kubernetes service-account tokens', 'GitHub Actions and GitLab CI job tokens', 'SPIFFE JWT-SVIDs', 'three service families', 'cannot be used by a pull request from a fork', 'fifteen minutes', 'last known good', 'pinned key material', 'never forwarded', 'sidecar injection', 'in development', 'Audit mode records every decision that would have blocked', 'not the sender\'s word', 'eBPF']) assert.ok(text.includes(w), w);
});

test('the naming is stated: Federated Identity, the API object NonHumanIdentity, slide 35 versus 57, Self-Hosted Agents', () => {
  assert.match(s.intro, /Non-Human Identity \(slide 35\)/); assert.match(s.intro, /NonHumanIdentity at \/v1\/nonhumanidentities/);
  const n = DISCREPANCIES.find((d) => d.id === 'naming').text;
  assert.match(n, /Slide 57/); assert.match(n, /NHI Agents Discovery & Enforcement/); assert.match(n, /NonHumanIdentity/);
  assert.ok(TALK_TRACK.find((t) => t.id === 'honesty').say.includes('slide 57'));
});

test('the measured nuance is reproduced honestly: the deck says accepted across MCP and LLM, our own earlier MCP test did not prove it', () => {
  const d = DISCREPANCIES.find((x) => x.id === 'mcp-acceptance').text;
  assert.match(d, /Measured \(our note, 2026-10-21/); assert.match(d, /401/); assert.match(d, /Not re-tested on the release/);
  assert.match(TALK_TRACK.find((t) => t.id === 'honesty').say, /did not prove it \(measured, our note\)/);
  assert.match(MEASURED.find((m) => m.id === 'mcp-llm-not-proven').note, /NOT proven/);
  for (const m of MEASURED) assert.match(m.note, /^Measured \(our note/, m.id);
});

test('the other discrepancies are shown, not resolved: token-pass, modes and actions, scopes, revocation speed, GA tag', () => {
  assert.deepEqual(DISCREPANCIES.map((d) => d.id), ['naming', 'mcp-acceptance', 'token-pass', 'modes-actions', 'scopes', 'revocation-speed', 'ga-tag']);
  assert.match(DISCREPANCIES.find((d) => d.id === 'token-pass').text, /token-pass/); assert.match(DISCREPANCIES.find((d) => d.id === 'modes-actions').text, /RequireApproval/);
  assert.match(DISCREPANCIES.find((d) => d.id === 'revocation-speed').text, /four minutes/);
});

test('availability: sidecar injection is in development and not modelled with "no behaviour is claimed"; the sensor is simulated, not run', () => {
  const by = (n) => AVAILABILITY.find((a) => a.capability.startsWith(n));
  assert.equal(by('Sidecar injection').availability, 'in development'); assert.match(by('Sidecar injection').lab, /No behaviour is claimed/);
  assert.match(by('The Kubernetes eBPF sensor').lab, /Not run/); assert.match(by('The Kubernetes eBPF sensor').lab, /simulates/);
  const sidecar = DEPLOYMENT_MODELS.find((m) => m.id === 'sidecar'); assert.equal(sidecar.modelled, false); assert.match(sidecar.lab, /No behaviour is claimed/);
  assert.deepEqual(DEPLOYMENT_MODELS.map((m) => m.id), ['direct-read', 'per-job', 'spiffe', 'stored-key', 'sidecar']);
});

test('every field source is a known kind; the swagger names are there with their roles, and the measured and lab-invented markers', () => {
  for (const f of FIELD_SOURCES) assert.ok(Object.hasOwn(FIELD_SOURCE_NAMES, f.source), f.field);
  const all = JSON.stringify(FIELD_SOURCES);
  for (const name of ['imodelNonHumanIdentitySpec', 'SubjectBinding', 'UserClaim', 'NotAfter', 'modelAgentWorkloadIdentity', 'JwksURI', 'MaxTokenLifetimeSec', 'RequiredClaims', 'AllowAnySubject', 'CustodianRef', 'imodelShadowAIPolicySpec', 'AllNamespaces']) assert.ok(all.includes(name), name);
  for (const k of ['deck', 'swagger', 'reading', 'invented', 'measured']) assert.ok(FIELD_SOURCES.some((f) => f.source === k), k);
  assert.deepEqual(FIELD_SOURCE_NAMES, { deck: 'deck claim', swagger: 'console swagger name (schema only)', reading: 'lab reading', invented: 'lab-invented', measured: 'measured (our note)' });
  for (const f of FIELD_SOURCES.filter((x) => x.source === 'swagger')) assert.ok(!/behaves|proves/.test(f.note) || /not a measured|names from/i.test(f.note), f.field);
});

test('"Why it matters" has challenge, technical and business for both features, marked as Ping claims, with the deck\'s wording', () => {
  assert.equal(WHY.length, 2);
  for (const w of WHY) { assert.match(w.say, /Challenge:/); assert.match(w.say, /Technical:/); assert.match(w.say, /Business:/); assert.match(w.say, /Ping claims, unverified on our tenant/); }
  assert.match(WHY_TEXT['federated-identity'].technical, /Secretless, exactly bound, short-lived tokens/); assert.match(WHY_TEXT['self-hosted-agents'].business, /simplifies compliance evidence/);
  assert.equal(TALK_TRACK[0].id, 'why-federated-identity');
});

test('presets: every preset names a seeded identity, a service and an expectation; every scope string the lab uses is one the lab lists', () => {
  assert.equal(PRESETS.length, 35); assert.equal(new Set(PRESETS.map((p) => p.id)).size, 35);
  for (const p of PRESETS) { assert.match(p.identityId, /^fid-00[1-5]$/); assert.ok(['mcp', 'a2a', 'llm'].includes(p.service)); assert.ok(p.expect.length > 1); assert.ok(p.title.length > 8); }
  assert.deepEqual(SCOPES, ['mcp', 'a2a', 'llm', 'shadowai:write', 'policy:read']);
});

test('the story names no real host, holds no credential-shaped value, and does not use the word "door"; the Unverified label is on every claim section', () => {
  for (const v of Object.keys(VERTICALS)) {
    const text = JSON.stringify(buildStory(VERTICALS[v], v));
    assert.deepEqual(scanHosts(text), [], v); assert.deepEqual(scanKeys(text), []); assert.deepEqual(findCredentials(text).filter((x) => x.id !== 'long-blob'), []);
    assert.ok(!/\bdoor\b/i.test(text), 'say P1 Privilege Agent App, not door');
  }
  assert.ok(NOT_DEMONSTRATED.length >= 6); assert.ok(NOT_DEMONSTRATED.some((n) => /MCP path or the LLM route/.test(n)));
});
