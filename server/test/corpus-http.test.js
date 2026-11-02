// A modest sample of the shared-masker leak corpus typed over HTTP: the first usable probe of each family (62 payloads) goes, one at a time, into every free-text field, object key, path
// segment, query, header and body of every endpoint (sweepAll), and the secret must be absent from every answer, from the state afterwards and from stdout / stderr.
// The whole corpus runs through the adapters in corpus.test.js; this is the end-to-end check that the adapters are wired into the HTTP edge.
import test from 'node:test';
import assert from 'node:assert/strict';
import { get, withServer } from './helpers.js';
import { sweepAll } from './sweep.js';
import { expand, isDeep, join, leaks } from './corpus.js';
import { maskText } from '../src/mask.js';

// One probe per family: the first row that is plain text (not a structured probe), short enough to send as a header, whose secret is at least 8 characters, and that the shared masker
// still masks when a word comes before it (every field the sweep fills puts a word first: "n <text>"). 34 of the 3,416 plain probes are not masked after a leading word (a JSON blob,
// an INI section, a column list, a NUL-split blob: the masker finds those layouts only at the start of the text; corpus.test.js pins the 34 and README lists the limit), so the
// sample skips such a row and takes the next one of its family. A family with no usable row is not in the sample.
const SAMPLE = [];
for (const family of new Set(leaks.map((r) => r.family))) {
  const row = leaks.find((r) => r.family === family && !isDeep(r) && expand(r).length <= 600 && join(r.secret).length >= 8 && !maskText(`n ${expand(r)}`).includes(join(r.secret)));
  if (row) SAMPLE.push(row);
}

test('the sample is 62 probes, one per family, none of them structured', () => {
  assert.equal(SAMPLE.length, 62);
  assert.equal(new Set(SAMPLE.map((r) => r.family)).size, 62);
  assert.ok(SAMPLE.every((r) => !isDeep(r)));
});

test('62 corpus payloads typed into every field, key, path segment, query and header of every endpoint are absent from every answer, from the state afterwards and from the log', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  const failures = [];
  await withServer(async (url) => {
    process.stdout.write = (c, ...a) => { out.push(String(c)); return realOut(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return realErr(c, ...a); };
    try {
      for (const row of SAMPLE) {
        const secret = join(row.secret);
        const text = await sweepAll(url, expand(row));
        if (text.includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: answer: ${text.split('\n').find((l) => l.includes(secret)).slice(0, 120)}`);
        const state = await (await get(url, '/api/state?mode=live')).text();
        if (state.includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: state`);
      }
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
  });
  assert.deepEqual(failures, [], `${failures.length} leaked:\n${failures.slice(0, 20).join('\n')}`);
  const log = out.join('');
  for (const row of SAMPLE) assert.ok(!log.includes(join(row.secret)), `${row.id}: not logged`);
});
