// The shared-masker 1.4.0 corpora (test/corpus/*.json, copied unchanged) run through THIS app's adapters: every leak probe must lose its secret (maskText, maskDeep, cleanFree, reveal),
// every ordinary string must stay as it is. Probes are stored as arrays of short fragments (gitleaks safety) and joined here at run time.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { dir, expand, isDeep, join, leaks, ordinary } from './corpus.js';
import { looksLikeCredential, maskDeep, maskText } from '../src/mask.js';
import { cleanFree, tidy } from '../src/credentials.js';
import { credentialProblem, escapeHidden, reveal } from '../src/clean.js';

const BIG = 1_000_000;

test('the corpora are the shared-masker 1.4.0 files (3754 leak probes in 65 families, 1926 ordinary strings) and the copied masker names its commit', () => {
  assert.equal(leaks.length, 3754); assert.equal(ordinary.length, 1926);
  assert.equal(new Set(leaks.map((r) => r.family)).size, 65);
  assert.equal(leaks.filter(isDeep).length, 338); assert.equal(ordinary.filter(isDeep).length, 109);
  for (const f of ['mask.js', 'hygiene.js']) {
    const first = fs.readFileSync(path.join(dir, '..', '..', 'src', 'shared', f), 'utf8').split('\n', 1)[0];
    assert.match(first, /shared-masker 1\.4\.0, commit 9bc664a/, f);
  }
  for (const row of [...leaks, ...ordinary]) for (const f of [...row.input, ...(row.secret || [])]) assert.ok(Array.from(f).length <= 4, `${row.id}: fragments stay short`);
});

test('leaks.json: through the adapter the secret never survives, in the answer mask, the free-text cleaner and the claim display, and the claim is refused', () => {
  const failures = []; let checked = 0;
  for (const row of leaks) {
    if (isDeep(row)) continue;
    const input = expand(row); const secret = join(row.secret); checked += 1;
    if (maskText(input).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: maskText`);
    if (!looksLikeCredential(input)) failures.push(`${row.id} ${row.family}/${row.enc}: looksLikeCredential false`);
    if (!credentialProblem(input)) failures.push(`${row.id} ${row.family}/${row.enc}: a claim of it is not refused`);
    if (cleanFree(input, BIG).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: cleanFree`);
    if (reveal(input, BIG).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: reveal`);
  }
  assert.equal(checked, 3416);
  assert.deepEqual(failures, [], `${failures.length} failed:\n${failures.slice(0, 30).join('\n')}`);
});

test('leaks.json: the structured probes lose the secret through the answer mask, keep their shape and do not mutate the input', () => {
  const failures = []; let checked = 0;
  for (const row of leaks.filter(isDeep)) {
    const value = JSON.parse(join(row.input)); const secret = join(row.secret); const before = JSON.stringify(value); checked += 1;
    const out = maskDeep(value);
    if (JSON.stringify(value) !== before) failures.push(`${row.id}: input mutated`);
    if (JSON.stringify(out).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}`);
  }
  assert.equal(checked, 338);
  assert.deepEqual(failures, [], failures.slice(0, 30).join('\n'));
});

test('leaks.json: typed as a value, a list member and an object KEY of the answer mask, the secret never survives', () => {
  const failures = []; let checked = 0;
  for (const row of leaks.filter((r) => !isDeep(r))) {
    const input = expand(row); if (input.length > 5000) continue; const secret = join(row.secret); checked += 1;
    const asValue = JSON.stringify(maskDeep({ note: input, list: [input] })); const asKey = JSON.stringify(maskDeep({ [input]: 1 }));
    if (asValue.includes(secret) || asKey.includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}`);
  }
  assert.equal(checked, 3402);
  assert.deepEqual(failures, [], failures.slice(0, 30).join('\n'));
});

test('ordinary.json: every string is left as it is by the adapter, the cleaner (up to whitespace), the claim display (up to hidden characters) and the answer mask', () => {
  const changed = []; let checked = 0;
  for (const row of ordinary) {
    const input = join(row.input);
    if (isDeep(row)) { const value = JSON.parse(input); checked += 1; if (JSON.stringify(maskDeep(value)) !== JSON.stringify(value)) changed.push(`${row.id}: maskDeep`); continue; }
    checked += 1;
    if (maskText(input) !== input) changed.push(`${row.id} maskText ${JSON.stringify(input)}`);
    if (looksLikeCredential(input)) changed.push(`${row.id} looksLikeCredential`);
    if (cleanFree(input, BIG) !== tidy(input)) changed.push(`${row.id} cleanFree ${JSON.stringify(input)}`);
    const wrapped = { note: input, list: [input] };
    if (JSON.stringify(maskDeep(wrapped)) !== JSON.stringify(wrapped)) changed.push(`${row.id} maskDeep ${JSON.stringify(input)}`);
    if (!credentialProblem(input) && reveal(input, BIG) !== escapeHidden(input)) changed.push(`${row.id} reveal ${JSON.stringify(input)}`);
  }
  assert.equal(checked, 1926);
  assert.deepEqual(changed, [], `${changed.length} changed:\n${changed.slice(0, 30).join('\n')}`);
});

test('ordinary.json as CLAIMS: three strings of 1,817 are refused by the lab\'s own 24-letter rule (a trace id and two image digests), the price of never signing a hex run', () => {
  const refused = ordinary.filter((r) => !isDeep(r) && credentialProblem(join(r.input)));
  assert.deepEqual(refused.map((r) => r.id), ['O1461', 'O1462', 'O1463']);
  for (const r of refused) assert.match(join(r.input), /[0-9a-f]{24,}/, 'each holds a hex run of 24 or more characters');
  assert.equal(ordinary.filter((r) => !isDeep(r)).length, 1817);
});

test('KNOWN MASKER GAP (shared-masker 1.4.0): 34 of the 3,416 plain probes are not masked when ordinary words come first in the same text, and the lab does not paper over it', () => {
  // The masker finds a JSON blob of parameters, an INI section named after the credential, a column list and a NUL-split blob only when the layout starts the text. A field of this lab
  // that holds "n " + such a layout shows the secret. It is the masker's limit (a fix belongs in shared-masker); this test pins the count so a fixed masker flips it, and README says so.
  const byFamily = {}; let checked = 0;
  for (const row of leaks.filter((r) => !isDeep(r))) {
    checked += 1; const secret = join(row.secret);
    if (maskText(`n ${expand(row)}`).includes(secret)) (byFamily[row.family] ??= []).push(row.id);
    assert.ok(!maskText(expand(row)).includes(secret), `${row.id}: masked when it starts the text`);
  }
  assert.equal(checked, 3416);
  assert.deepEqual(Object.fromEntries(Object.entries(byFamily).map(([k, v]) => [k, v.length])), { json: 23, nul: 6, section: 4, structure: 1 });
});
