import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildPack } from './build-content-pack.mjs';
import { validatePack } from './validate-content-pack.mjs';

const root = new URL('..', import.meta.url);
const committed = JSON.parse(fs.readFileSync(new URL('content-pack.json', root), 'utf8'));

test('the pack validates against the schema and its cross-references hold, with catalog D107', () => {
  assert.deepEqual(validatePack(buildPack()), []);
  assert.equal(buildPack().demo.catalog, 'D107'); assert.equal(buildPack().schema, 'demo-content-pack/1');
});
test('the committed content-pack.json is exactly what the builder makes (no drift)', () => { assert.deepEqual(committed, buildPack()); });
test('every scripted scenario has a story and a try-it card', () => {
  const pack = buildPack();
  assert.equal(pack.stories.length, 13);
  for (const s of pack.stories) assert.ok(pack.cards.find((c) => c.story === s.id), s.id);
});
test('a broken pack is caught: unknown term and unknown story', () => {
  const pack = buildPack(); pack.cards[0].terms = ['nope']; pack.cards[1].story = 'ghost';
  const errors = validatePack(pack).join('\n');
  assert.match(errors, /unknown term nope/); assert.match(errors, /unknown story ghost/);
});
test('the pack has a Why it matters entry per feature (challenge, technical, business) marked as Ping claims; names no real company or documentation URL, holds no credential', () => {
  const pack = buildPack(); const t = JSON.stringify(pack).toLowerCase();
  for (const w of ['united', 'mileageplus', 'datapower', 'optum', 'uhg', 'benefit']) assert.ok(!t.includes(w), w);
  assert.ok(!/https?:\/\/(?!(localhost|example\.invalid))/.test(t), 'only localhost and .invalid links');
  assert.ok(!/\bdoor\b/.test(t), 'say P1 Privilege Agent App, not door');
  assert.ok(!t.includes('sk-mock'), 'no credential-shaped value');
  for (const id of ['concept-why-federated-identity', 'concept-why-self-hosted-agents']) {
    const d = pack.cards.find((c) => c.id === id).description;
    assert.match(d, /Challenge:/); assert.match(d, /Technical:/); assert.match(d, /Business:/); assert.match(d, /Ping claims, unverified on our tenant/);
  }
});
test('every glossary definition says it is UNVERIFIED on our tenant; the measured, lab-invented and swagger parts say so', () => {
  const pack = buildPack();
  for (const g of pack.glossary) assert.match(g.definition, /UNVERIFIED on our tenant/, g.id);
  assert.match(pack.glossary.find((g) => g.id === 'federated-identity').definition, /NonHumanIdentity/);
  assert.match(pack.glossary.find((g) => g.id === 'federated-identity').definition, /Slide 57 still says/);
  assert.match(pack.glossary.find((g) => g.id === 'key-owned').definition, /measured on our tenant/);
  assert.match(pack.glossary.find((g) => g.id === 'deployment-models').definition, /no behaviour/);
  assert.match(pack.glossary.find((g) => g.id === 'self-hosted-agents').definition, /simulates the reports/);
  assert.match(pack.cards.find((c) => c.id === 'concept-mcp-acceptance').description, /Not re-tested on the release/);
});
