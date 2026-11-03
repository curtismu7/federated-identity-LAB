// Loader for the shared-masker corpora (corpus/leaks.json, corpus/ordinary.json). Rows hold their text as arrays of short fragments (gitleaks safety); join() makes the text at run time.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'corpus');
export const leaks = JSON.parse(fs.readFileSync(path.join(dir, 'leaks.json'), 'utf8'));
export const ordinary = JSON.parse(fs.readFileSync(path.join(dir, 'ordinary.json'), 'utf8'));
export const join = (a) => a.join('');
export const expand = (row) => `${row.fillBefore ? `${'a'.repeat(row.fillBefore)} ` : ''}${join(row.input)}${row.fillAfter ? ` ${'a'.repeat(row.fillAfter)}` : ''}`;
export const isDeep = (row) => row.api === 'deep';
