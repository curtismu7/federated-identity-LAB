// Defence in depth: every API response passes through maskDeep, so a credential-shaped value can never leave in any field even if a code path
// forgot to clean its input. Iterative: a deep structure cannot overflow the stack. The generic long-blob detector is NOT applied here
// (ids, hashes and trace ids are long and legitimate); the specific token, key, bearer and assignment detectors are. Visitor text is
// already fully cleaned (long blobs included) on the way in by cleanFree.
import { DETECTORS, fold, maskSpans } from './credentials.js';

const SPECIFIC = DETECTORS.filter((d) => d.id !== 'long-blob');
const OPAQUE = new Set(['traceparent', 'traceId', 'mintedToken', 'n', 'e']); // ids, the lab-minted token and PUBLIC key halves (the JWKS the browser check reads)

// The response mask matches on the FOLDED text (invisible characters deleted, percent-decoded, NFKC): a secret hidden with zero-width, Hangul-filler, variation-selector or
// tag characters, or percent-encoded once or twice, is found. Text with nothing credential-shaped in it is returned EXACTLY as given (a claim's hidden characters are
// written out as \u{...} by the cleaners, and exactness is the point); text with a secret in it is returned folded and masked.
export function maskResponseText(text) {
  if (text.length > 40000) return maskRaw(text);
  const flat = fold(text);
  const spans = spansOf(flat);
  return spans.length ? maskSpans(flat, spans) : text;
}
const spansOf = (flat) => { const spans = []; for (const d of SPECIFIC) { d.re.lastIndex = 0; for (const m of flat.matchAll(d.re)) spans.push({ start: m.index, end: m.index + m[0].length, id: d.id }); } return spans; };
const maskRaw = (text) => { const spans = spansOf(text); return spans.length ? maskSpans(text, spans) : text; };

// Object KEYS carry typed text too (a pinned-claim name, an unknown field): a credential-shaped key is replaced by its masked form, and two keys that mask to the
// same text are kept apart with a numeric suffix.
const maskKey = (k) => (OPAQUE.has(k) ? k : maskResponseText(k));

export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  // Objects get their (masked) keys through defineProperty, so a key named __proto__ is plain data and two keys that mask alike are kept apart with a suffix.
  const put = (dst, key, v) => {
    if (Array.isArray(dst) || dst === root) { dst[key] = v; return; }
    let k = key; for (let i = 2; Object.hasOwn(dst, k); i++) k = `${key}#${i}`;
    Object.defineProperty(dst, k, { value: v, enumerable: true, writable: true, configurable: true });
  };
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { put(dst, key, opaque ? src : maskResponseText(src)); continue; }
    if (src === null || typeof src !== 'object') { put(dst, key, src); continue; }
    const copy = clone(src); put(dst, key, copy);
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, Array.isArray(src) ? k : maskKey(k), OPAQUE.has(k)]);
  }
  return root.v;
}
