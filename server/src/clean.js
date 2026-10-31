// Visitor-supplied structure made safe to show and to keep: strings cleaned and masked (control and bidi characters removed, credential-shaped
// runs masked, then cut), numbers and booleans kept, depth and width bounded. Object keys are built with Object.fromEntries, so a key named
// __proto__ becomes plain data and never reaches a prototype.
import { cleanFree } from './credentials.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function cleanClaims(value, depth = 0) {
  if (typeof value === 'string') return cleanFree(value, 160);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return depth >= 3 ? '[too deep]' : value.slice(0, 10).map((v) => cleanClaims(v, depth + 1));
  if (isObj(value)) return depth >= 3 ? '[too deep]' : Object.fromEntries(Object.keys(value).slice(0, 30).map((k) => [cleanFree(k, 40), cleanClaims(value[k], depth + 1)]));
  return null;
}
// One value, for a step's detail text.
export const show = (v, max = 100) => (typeof v === 'string' ? cleanFree(v, max) : cleanFree(JSON.stringify(v) ?? 'undefined', max));
