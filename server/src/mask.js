// Defence in depth: every API response passes through maskDeep, so a credential-shaped value can never leave in any field even if a code path
// forgot to clean its input. Iterative: a deep structure cannot overflow the stack. The generic long-blob detector is NOT applied here
// (ids, hashes and trace ids are long and legitimate); the specific token, key, bearer and assignment detectors are. Visitor text is
// already fully cleaned (long blobs included) on the way in by cleanFree.
import { DETECTORS, fold, maskSpans } from './credentials.js';

const SPECIFIC = DETECTORS.filter((d) => d.id !== 'long-blob');
const OPAQUE = new Set(['traceparent', 'traceId', 'mintedToken', 'n', 'e']); // ids, the lab-minted token and PUBLIC key halves (the JWKS the browser check reads)

// The response mask matches on the FOLDED text (invisible characters deleted, percent-decoded, NFKC): a secret hidden with zero-width, Hangul-filler, variation-selector or
// tag characters, or percent-encoded once or twice, is found. When the text needed folding the answer carries the folded (and masked) form.
export function maskResponseText(text) {
  const flat = text.length > 40000 ? text : fold(text);
  const spans = [];
  for (const d of SPECIFIC) { d.re.lastIndex = 0; for (const m of flat.matchAll(d.re)) spans.push({ start: m.index, end: m.index + m[0].length, id: d.id }); }
  const out = spans.length ? maskSpans(flat, spans) : flat;
  return out === text ? text : out;
}

export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { dst[key] = opaque ? src : maskResponseText(src); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src); dst[key] = copy;
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k, OPAQUE.has(k)]);
  }
  return root.v;
}
