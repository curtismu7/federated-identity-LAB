// Visitor-supplied structure made safe to show and to keep. Two different jobs, kept apart:
//  * names, descriptions and notes (cleanFree, in credentials.js) are masked: nothing depends on their exact bytes;
//  * CLAIM values and names, which the lab compares EXACTLY, are never rewritten. A claim that looks like a credential (after folding) is REFUSED when minting, and masked
//    when it is only being shown from a token the visitor pasted. Any other claim is signed byte for byte, and shown with its hidden characters made visible
//    (U+200B appears as \u{200b}), so what is shown is what was signed or presented.
// The detection is the shared masker (credentials.js -> mask.js -> shared/mask.js). Object keys are built with Object.fromEntries, so a key named __proto__ becomes plain data.
import { credentialShaped, maskLongRuns, maskText, tidy } from './credentials.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const HIDDEN = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Zl}\p{Zp}\u{FFFD}]/gu;
const HIDDEN_ONE = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Zl}\p{Zp}\u{FFFD}]/u;

// True when the value holds anything credential-shaped (folded: a hidden-character, percent-encoded or fullwidth disguise does not help).
export const credentialProblem = credentialShaped;

// The masked form of a credential-shaped value (what is shown instead of it).
export const maskedForm = (value, max = 160) => tidy(maskText(maskLongRuns(value))).slice(0, max);

// Hidden characters (zero-width, bidi, format, control) written out as \u{...} so they can be seen. Nothing else is changed.
export const escapeHidden = (s) => s.replace(HIDDEN, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);

// Why a claim value is not plain ASCII text, for the notice the mint shows. Empty when it is plain.
export function oddities(v) {
  const out = [];
  if (HIDDEN_ONE.test(v)) out.push('hidden characters');
  if (/[^ -~]/.test(v.replace(HIDDEN, ''))) out.push('non-ASCII characters (a lookalike is a different string)');
  if (v !== v.trim()) out.push('leading or trailing space');
  if (/%[0-9a-fA-F]{2}/.test(v)) out.push('percent-encoding (it is not decoded)');
  return out;
}

// A visitor string for display: credential-shaped -> masked; otherwise exactly as given with hidden characters visible. Never trimmed, never normalised.
export function reveal(value, max = 160) {
  const s = String(value ?? '');
  return (credentialProblem(s) ? maskedForm(s, max) : escapeHidden(s)).slice(0, max);
}

export function cleanClaims(value, depth = 0) {
  if (typeof value === 'string') return reveal(value, 160);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return depth >= 3 ? '[too deep]' : value.slice(0, 10).map((v) => cleanClaims(v, depth + 1));
  if (isObj(value)) return depth >= 3 ? '[too deep]' : Object.fromEntries(Object.keys(value).slice(0, 30).map((k) => [reveal(k, 40), cleanClaims(value[k], depth + 1)]));
  return null;
}
// One value, for a step's detail text.
export const show = (v, max = 100) => (typeof v === 'string' ? reveal(v, max) : reveal(JSON.stringify(v) ?? 'undefined', max));
