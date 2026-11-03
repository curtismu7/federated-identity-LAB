import test from 'node:test';
import assert from 'node:assert/strict';
import { DIAGRAM_NAMES, buildDiagram, loadDiagram, rawDiagram } from '../src/diagramData.js';
import { validateDiagram } from '../src/diagramStudioValidate.js';
import { DEFAULT_CAST, VERTICALS, unfilled } from '../src/cast.js';

test('the three diagrams are valid diagram-studio/1 data loaded by name, every step is one edge, and they carry the unverified label', () => {
  assert.deepEqual(DIAGRAM_NAMES, ['federated-identity-flow', 'verification-steps', 'self-hosted-agent']);
  for (const n of DIAGRAM_NAMES) {
    const d = loadDiagram(n); assert.deepEqual(validateDiagram(d), [], n);
    const b = buildDiagram(DEFAULT_CAST, n);
    assert.equal(b.steps.length, d.edges.length, `${n}: one step per arrow`);
    assert.match(b.intro, /UNVERIFIED on our tenant/); assert.match(b.intro, /Simulated/);
    const ids = new Set(b.nodes.map((x) => x.id)); for (const s of b.steps) { assert.ok(ids.has(s.from) && ids.has(s.to)); assert.ok(s.say.length > 10); }
    for (const v of Object.values(VERTICALS)) assert.deepEqual(unfilled(JSON.stringify(rawDiagram(n)), v), [], n);
  }
});
test('an unknown diagram name falls back to the first, never an error', () => { assert.equal(buildDiagram(DEFAULT_CAST, '__proto__').name, 'federated-identity-flow'); });
test('the diagrams name no non-reserved host', () => { assert.ok(!/https?:\/\/(?!.*\.example)/.test(JSON.stringify(DIAGRAM_NAMES.map((n) => rawDiagram(n))))); });

test('the response mask leaves every diagram, in every vertical, and the whole Mock table untouched (prose must not read as an assignment)', async () => {
  const { maskStatic: maskDeep } = await import('../src/mask.js'); const { MOCK_TABLE } = await import('../src/mockTable.js');
  for (const v of Object.values(VERTICALS)) for (const n of DIAGRAM_NAMES) { const d = buildDiagram(v, n); assert.deepEqual(maskDeep(d), d, n); }
  assert.deepEqual(maskDeep(MOCK_TABLE), MOCK_TABLE);
});
