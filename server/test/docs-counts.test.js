// Every count the docs state comes from one source in the code and is tested here, so a count cannot go stale (N1: the README said thirteen scenarios, there are fourteen).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scenarioList } from '../src/scenarios.js';
import { VERTICALS } from '../src/cast.js';
import { PRESETS } from '../src/data.js';
import { STEPS } from '../src/engine.js';
import { DIAGRAM_NAMES } from '../src/diagramData.js';
import { runChecks } from '../src/doctor.js';
import { MOCK_TABLE } from '../src/mockTable.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const WORDS = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18 };
const num = (w) => (/^\d+$/.test(w) ? Number(w) : WORDS[w.toLowerCase()]);
const NUM = '(\\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen)';
// Every "<number> <noun>" the shipped docs state, as numbers.
const stated = (re) => ['README.md', 'CLAUDE.md', 'docs/talk-track.md', 'docs/safety.md'].flatMap((f) => [...read(f).matchAll(re)].map((m) => ({ file: f, n: num(m[1]), text: m[0] })));

test('the scenario count in the docs is the number of scripted scenarios, in every vertical and in the mock table', () => {
  const counts = Object.values(VERTICALS).map((c) => scenarioList(c).length);
  const N = counts[0];
  assert.ok(counts.every((n) => n === N), 'the same scenarios in every vertical');
  assert.equal(N, 14);
  for (const v of Object.keys(VERTICALS)) assert.equal(MOCK_TABLE.verticals[v].scenarios.length, N, `mock table ${v}`);
  const list = stated(new RegExp(`${NUM}\\s+scripted\\s+scenarios`, 'gi'));
  assert.ok(list.length >= 2, 'README and CLAUDE.md both state it');
  for (const s of list) assert.equal(s.n, N, `${s.file}: "${s.text}"`);
  // the numbered scenario list in the talk track
  const numbered = [...read('docs/talk-track.md').matchAll(/^(\d+)\. \*\*/gm)].map((m) => Number(m[1]));
  assert.equal(Math.max(...numbered), N, 'the talk track lists every scenario');
});

test('the preset, lookalike, step, diagram and doctor counts in the docs match the code', async () => {
  const lookalikes = PRESETS.filter((p) => /^lk-/.test(p.id)).length;
  for (const s of stated(new RegExp(`${NUM}\\s+presets`, 'gi'))) assert.equal(s.n, PRESETS.length, `${s.file}: ${s.text}`);
  for (const s of stated(new RegExp(`${NUM} of them lookalikes`, 'gi'))) assert.equal(s.n, lookalikes, `${s.file}: ${s.text}`);
  // a number of ten or more in front of "step(s)" is the verification pipeline ("fifteen steps", "15-step verification")
  const TEN_UP = '(\\d\\d+|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen)';
  const found = stated(new RegExp(`${TEN_UP}[- ]steps?\\b`, 'gi'));
  assert.ok(found.length >= 3, 'the docs state the step count');
  for (const s of found) assert.equal(s.n, STEPS.length, `${s.file}: ${s.text}`);
  for (const s of stated(new RegExp(`${NUM} diagrams`, 'gi'))) assert.equal(s.n, DIAGRAM_NAMES.length, `${s.file}: ${s.text}`);
  // npm run doctor prints the shared checks, then the HTTP cycle and the port check (scripts/doctor.mjs)
  const total = (await runChecks()).length + 2;
  for (const s of stated(new RegExp(`${NUM} checks`, 'gi'))) assert.equal(s.n, total, `${s.file}: ${s.text}`);
  assert.equal(PRESETS.length, 35); assert.equal(lookalikes, 8); assert.equal(STEPS.length, 15); assert.equal(DIAGRAM_NAMES.length, 3);
});
