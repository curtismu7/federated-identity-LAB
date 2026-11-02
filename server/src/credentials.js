// Credential-shaped text. A thin adapter over the shared masker (./mask.js -> ./shared/mask.js); this file holds no detector of its own. Anything a visitor types that looks like a
// token, a key, a password or key material is masked on the way IN (a name, a claim, a note) so the raw value never enters state, an audit entry, a hop pane, a log line or an error.
import { looksLikeCredential, maskText } from './mask.js';

export const MAX_FREE = 400;
export { maskText };

// The lab's one policy of its own, kept apart from the masker: a run of 24 or more letters and digits (and +) is not an identity name. A SPIFFE ID, a Kubernetes subject or a snake_case
// name has separators, a signature or a key does not. A claim or a stored value (an audience, a subject, a namespace) holding one is credential-shaped; the shared masker leaves a bare
// run alone in free text (a hash or a commit id is ordinary there), so this is the lab's rule for the values it SIGNS and STORES, not a second detector for text. A digest or a trace id
// in a claim is refused by it (README says so); break it up with a separator or leave it out.
const RUN = /[A-Za-z0-9+]{24,}/;
const RUN_ALL = /[A-Za-z0-9+]{24,}/g;
const SEPARATORS = /[\t\n\r\p{Zl}\p{Zp}]/gu;
const HIDDEN = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Zl}\p{Zp}\u{FFFD}]/gu;
// The text as the policy reads it: look-alikes folded (NFKC), percent-escapes decoded (three rounds), line breaks and tabs as spaces, every other hidden character deleted.
const unfold = (text) => {
  let t = String(text ?? '').normalize('NFKC');
  for (let i = 0; i < 3 && t.includes('%'); i++) { const next = t.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return m; } }); if (next === t) break; t = next; }
  return t.replace(SEPARATORS, ' ').replace(HIDDEN, '');
};
// True when the text, folded (hidden characters, percent-encoding, look-alikes), holds anything credential-shaped: the shared masker's verdict, or a 24-character run.
export const credentialShaped = (text) => looksLikeCredential(String(text ?? '')) || RUN.test(unfold(text));

// What a refused value shows instead of itself, given the shared masker's output for it: when a 24-character run is left in it, the DECODED form with each run replaced by
// [masked:long-run] (never the encoded text, which would carry the run); otherwise the output unchanged.
export const maskLongRuns = (masked) => {
  const flat = unfold(masked);
  return RUN.test(flat) ? flat.replace(RUN_ALL, '[masked:long-run]') : masked;
};

// Hidden characters (zero-width, bidi, format, control) written out as \u{...} so they can be seen. Nothing else is changed. They are made visible, never deleted: deleting after
// masking could join the pieces of a secret that the masker left alone on purpose.
export const escapeHidden = (s) => s.replace(HIDDEN, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);

// Display hygiene for a name, a note or a masked claim: tab, line feed, carriage return and the line and paragraph separators become spaces, hidden characters are written out,
// runs of space collapse. Run AFTER masking, which folds hidden characters itself, so a keyword split by one was already found.
export const tidy = (text) => escapeHidden(text.replace(SEPARATORS, ' ')).replace(/\s+/g, ' ').trim();

// Free text from the visitor: masked FIRST (on the whole text), then tidied and cut to the cap. Never throws, never echoes a raw credential.
export function cleanFree(value, max = MAX_FREE) {
  return tidy(maskText(value)).slice(0, max);
}
