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
  // A value runs to the first character that cannot be part of one, so a value that CONTAINS the word "bearer" or "basic" (CANARYbearer1234) is masked whole. A second
  // detector finds a keyword glued behind a value (Bearer aaaaaaaaaa" + "Bearer bbbbbbbbbb" with no space between), which the first match has consumed.
  D('bearer', /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{10,}/gi),
  D('bearer', /(?<=[A-Za-z0-9._~+/=-])(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{10,}/gi),
  D('userinfo', /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^\s/@:]{1,64}:[^\s/@]{1,128}@/gi),
  // the same without a scheme (bob:pw@host.example, //bob:pw@host.example): not inside a longer word, and only before something that looks like a host. A user name of 65 or
  // more characters is not found by this one (the long-blob detector may still catch it). mailto:alice@host.example looks the same and is masked too.
  D('userinfo', /(?<![A-Za-z0-9._~%+-])[^\s/@:]{1,64}:[^\s/@]{1,128}@(?=[A-Za-z0-9-]+\.[A-Za-z0-9-]|localhost\b)/gi),
  // keyword, then the value. No leading word boundary on the long words, so a glued form (xpassword: zq81xkzq) is found too. Four detectors, all reported as "assignment":
  //  1. a separator (: = := => ->) after any keyword: the next 3 or more characters are the value, whatever they are;
  //  2. "is", "are" or "was" after a password word (pass, password, passwd, pwd, pw, passcode, passphrase): the next 3 or more characters, whatever they are;
  //  3. anything looser (a space, a dash, "is" after secret/token/key words): the value must look like a secret, 6 or more characters with a digit in them;
  //  4. a login pair (login: bob / hunter2xyz, user: bob | hunter2xyz): the second part must look like a secret in the same way.
  // So "password hunter2xyz" and "my token is abc12345" are masked, while "password reset", "the token is accepted" and "secret santa" stay readable. README documents the tradeoff.
  // Keywords: password, passwd, passcode, passphrase, pwd, pw (+s) | the word pass | secret, token, api key, client secret, private key, access key, credential (+s). A key word may be
  // written with a space, underscore or hyphen between its words.
  D('assignment', /(?:(?:password|passwd|passcode|passphrase|pwd|pw)s?|(?<![a-z])pass(?![a-z])|(?:secret|token|api[\s_-]?key|apikey|client[\s_-]?secret|private[\s_-]?key|access[\s_-]?key|credential)s?)["']?\s*(?::=|=>|->|[:=])\s*["']?\S{3,}/gi),
  D('assignment', /(?:(?:password|passwd|passcode|passphrase|pwd|pw)s?|(?<![a-z])pass(?![a-z]))["']?\s+(?:is|are|was)\s+["']?\S{3,}/gi),
  D('assignment', /(?:(?:password|passwd|passcode|passphrase|pwd|pw)s?|(?<![a-z])pass(?![a-z])|(?:secret|token|api[\s_-]?key|apikey|client[\s_-]?secret|private[\s_-]?key|access[\s_-]?key|credential)s?)["']?\s+(?:(?:is|are|was)\s+|[-–—]+\s+)?["']?(?=\S*\d)\S{6,}/gi),
  D('assignment', /(?<![a-z])(?:login|log-in|user(?:name)?|usr|account)(?![a-z])\s*[:=]\s*[^\s/|]{1,64}\s*[/|]\s*["']?(?=\S*\d)\S{6,}/gi),
  // a JSON key: {"password":"x"}, even when the value is one character
  D('json-secret', /["'](?:password|passwd|passcode|pwd|pw|pass|passphrase|secret|token|api[\s_-]?key|apikey|client[\s_-]?secret|private[\s_-]?key|access[\s_-]?key|credential)s?["']\s*:\s*["']?[^"'\s]{1,}/gi),
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
// and the replacement character U+FFFD. Everything in Unicode's Default_Ignorable_Code_Point and Cf classes goes, and so do the controls named below.
// C0 and C1 control characters and DEL are deleted as well (except tab, line feed and carriage return, which are separators): p<U+0001>a<U+0001>s... is "pass...".
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Cf}\u{FFFD}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu;
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;
// A \uXXXX or \u{X...} escape written out as TEXT ({"\u0070assword":"x"}) is the character it names, for matching (it is read twice, so a doubly wrapped one is found too).
const ESCAPE = /\\u(?:([0-9a-fA-F]{4})|\{([0-9a-fA-F]{1,6})\})/g;
const unescapeOne = (m, four, braced) => { const cp = parseInt(four || braced, 16); return cp <= 0x10ffff ? String.fromCodePoint(cp) : m; };
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

// The one normaliser the cleaners and the response mask share: bounded, NFKC-folded, invisible characters deleted, percent-decoded, folded again, then tab, line feed, carriage return and the line and paragraph separators to spaces.
export function fold(value) {
  const strip = (s) => s.normalize('NFKC').replace(ESCAPE, unescapeOne).replace(INVISIBLE, '');
  return strip(decodePercent(strip(String(value ?? '').slice(0, PRE_CAP)))).replace(CONTROL, ' ').slice(0, 200000);
}

// Free text from the visitor: folded as above, credential-shaped runs masked BEFORE the text is cut to length. Never throws, never echoes a raw credential.
export function cleanFree(value, max = MAX_FREE) {
  return maskText(fold(value)).replace(/\s+/g, ' ').trim().slice(0, max);
}
