// Credential-shaped text. Anything a visitor types that looks like a token, a key, a password or key material is masked on the way IN
// (a name, a claim, a note) so the raw value never enters state, an audit entry, a hop pane, a log line or an error.
// Lab-written detectors; linear patterns only (no nested quantifiers), run on input bounded by fold(). A heuristic: it can miss a secret.
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
  // keyword, optional quotes, then : or = (or "is" for a password word), then the value. No leading word boundary, so a glued form (xpassword: zq81xkzq) is found too.
  D('assignment', /(?:(?:password|passwd|pwd|pw|passphrase)s?["']?\s*(?:[:=]|is)\s*["']?\S{3,}|(?:secret|token|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|access[_-]?key|credential)s?["']?\s*[:=]\s*["']?\S{3,})/gi),
  // a JSON key: {"password":"x"}, even when the value is one character
  D('json-secret', /["'](?:password|passwd|pwd|pw|passphrase|secret|token|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|access[_-]?key|credential)s?["']\s*:\s*["']?[^"'\s]{1,}/gi),
  D('authorization', /\bAuthorization\s*[:=]\s*\S+(?:\s+\S+)?/gi),
  D('long-blob', /[A-Za-z0-9+/_=-]{32,}/g),
];

// Spans { start, end, id } of every credential-shaped run in the text.
export function findCredentials(text) {
  const t = String(text).slice(0, 200000);
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

// Invisible and format characters are DELETED (never turned into a space): zero-width, bidi, soft hyphen, Hangul fillers (U+3164, U+FFA0, U+115F, U+1160), combining
// grapheme joiner (U+034F), Mongolian vowel separator (U+180E), variation selectors, tag characters, Arabic letter mark (U+061C), the U+206A-206F controls, U+17B4/U+17B5,
// and the replacement character U+FFFD. Everything in Unicode's Default_Ignorable_Code_Point and Cf classes goes.
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Cf}\u{FFFD}]/gu;
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;
const PERCENT_RUN = /(?:%[0-9a-fA-F]{2})+/g;
const PRE_CAP = 40000; // the JSON body limit is 32 KB, so no real input is longer; this bounds NFKC expansion (one character can become eighteen)

// Percent-encoded text is decoded (at most three rounds, so once- and twice-encoded values are found, and a decoder bomb cannot loop) BEFORE any masking.
export function decodePercent(text) {
  let t = text;
  for (let i = 0; i < 3 && t.includes('%'); i++) {
    const next = t.replace(PERCENT_RUN, (m) => { try { return decodeURIComponent(m); } catch { return m.replace(/%([0-7][0-9a-fA-F])/g, (_, h) => String.fromCharCode(parseInt(h, 16))); } });
    if (next === t) break;
    t = next;
  }
  return t;
}

// The one normaliser the cleaners and the response mask share: bounded, NFKC-folded, invisible characters deleted, percent-decoded, folded again, controls to spaces.
export function fold(value) {
  const strip = (s) => s.normalize('NFKC').replace(INVISIBLE, '');
  return strip(decodePercent(strip(String(value ?? '').slice(0, PRE_CAP)))).replace(CONTROL, ' ').slice(0, 200000);
}

// Free text from the visitor: folded as above, credential-shaped runs masked BEFORE the text is cut to length. Never throws, never echoes a raw credential.
export function cleanFree(value, max = MAX_FREE) {
  return maskText(fold(value)).replace(/\s+/g, ' ').trim().slice(0, max);
}
