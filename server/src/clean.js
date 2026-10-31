// Visitor-supplied structure made safe to show and to keep: strings cleaned and masked (control and bidi characters removed, credential-shaped
// runs masked, then cut), numbers and booleans kept, depth and width bounded. Object keys are built with Object.fromEntries, so a key named
// __proto__ becomes plain data and never reaches a prototype.
// Claim values use cleanValue, not cleanFree: the generic 32-character blob detector would mask a legitimate SPIFFE ID, so a "blob" here is a run of 24 or more
// letters, digits, + _ = with no separator, plus every specific detector. It is a heuristic (README says so).
import { DETECTORS, maskSpans } from './credentials.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const SPECIFIC = DETECTORS.filter((d) => d.id !== 'long-blob');
const BLOB = /[A-Za-z0-9+_=]{24,}/g;
const INVISIBLE = /\p{Cf}/gu; // zero-width, bidi and other format characters: deleted BEFORE matching, so interleaving cannot hide a secret
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;

export function cleanValue(value, max = 160) {
  const flat = String(value ?? '').normalize('NFKC').replace(INVISIBLE, '').replace(CONTROL, ' ').slice(0, 100000);
  const spans = [];
  for (const d of SPECIFIC) { d.re.lastIndex = 0; for (const m of flat.matchAll(d.re)) spans.push({ start: m.index, end: m.index + m[0].length, id: d.id }); }
  for (const m of flat.matchAll(BLOB)) spans.push({ start: m.index, end: m.index + m[0].length, id: 'long-blob' });
  return maskSpans(flat, spans).replace(/\s+/g, ' ').trim().slice(0, max);
}

export function cleanClaims(value, depth = 0) {
  if (typeof value === 'string') return cleanValue(value, 160);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return depth >= 3 ? '[too deep]' : value.slice(0, 10).map((v) => cleanClaims(v, depth + 1));
  if (isObj(value)) return depth >= 3 ? '[too deep]' : Object.fromEntries(Object.keys(value).slice(0, 30).map((k) => [cleanValue(k, 40), cleanClaims(value[k], depth + 1)]));
  return null;
}
// One value, for a step's detail text.
export const show = (v, max = 100) => (typeof v === 'string' ? cleanValue(v, max) : cleanValue(JSON.stringify(v) ?? 'undefined', max));
