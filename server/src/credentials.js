// Credential-shaped text. Anything a visitor types that looks like a token, a key, a password or key material is masked on the way IN
// (a name, a claim, a note) so the raw value never enters state, an audit entry, a hop pane, a log line or an error.
// Lab-written detectors; linear patterns only (no nested quantifiers), run on input capped at 100000 characters. A heuristic: it can miss a secret.
export const MAX_FREE = 400;

const D = (id, re) => ({ id, re });
export const DETECTORS = [
  D('private-key', /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[^]{0,4000}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)/g),
  D('github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})/g),
  D('gitlab-token', /\bglpat-[A-Za-z0-9_-]{12,}/g),
  D('slack-token', /\bxox[abprs]-[A-Za-z0-9-]{8,}/g),
  D('aws-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g),
  D('api-key', /\bsk-[A-Za-z0-9_-]{12,}/g),
  D('jwt', /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g),
  D('bearer', /\b(?:Bearer|Basic)\s+(?:(?!Bearer|Basic)[A-Za-z0-9._~+/=-]){10,}/gi), // a value stops before the next keyword, so glued values are each masked
  D('userinfo', /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^\s/@:]{1,64}:[^\s/@]{1,128}@/gi),
  D('assignment', /\b(?:(?:password|passwd|pwd|pw|passphrase)s?\s*(?:[:=]|is)\s*\S{3,}|(?:secret|token|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|access[_-]?key|credential)s?\s*[:=]\s*\S{3,})/gi),
  D('authorization', /\bAuthorization\s*[:=]\s*\S+(?:\s+\S+)?/gi),
  D('long-blob', /[A-Za-z0-9+/_=-]{32,}/g),
];

// Spans { start, end, id } of every credential-shaped run in the text.
export function findCredentials(text) {
  const t = String(text).slice(0, 100000);
  const spans = [];
  for (const d of DETECTORS) { d.re.lastIndex = 0; for (const m of t.matchAll(d.re)) spans.push({ start: m.index, end: m.index + m[0].length, id: d.id }); }
  return spans;
}

export function maskSpans(text, spans) {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  let out = ''; let at = 0;
  for (const s of sorted) { if (s.start < at) { at = Math.max(at, s.end); continue; } out += `${text.slice(at, s.start)}[masked:${s.id}]`; at = s.end; }
  return out + text.slice(at);
}

export function maskText(input) {
  const text = String(input);
  return text ? maskSpans(text, findCredentials(text)) : text;
}

const INVISIBLE = /\p{Cf}/gu; // zero-width, bidi and other format characters: deleted BEFORE matching, so interleaving cannot hide a secret
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;

// Free text from the visitor: NFKC-folded, invisible characters deleted, control and bidi characters turned into spaces, credential-shaped runs masked
// BEFORE the text is cut to length. Never throws, never echoes a raw credential.
export function cleanFree(value, max = MAX_FREE) {
  const flat = String(value ?? '').normalize('NFKC').replace(INVISIBLE, '').replace(CONTROL, ' ');
  return maskText(flat.slice(0, 100000)).replace(/\s+/g, ' ').trim().slice(0, max);
}
