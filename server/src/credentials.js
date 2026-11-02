// Credential-shaped text. A thin adapter over the shared masker (./mask.js -> ./shared/mask.js); this file holds no detector of its own. Anything a visitor types that looks like a
// token, a key, a password or key material is masked on the way IN (a name, a claim, a note) so the raw value never enters state, an audit entry, a hop pane, a log line or an error.
import { looksLikeCredential, maskText } from './mask.js';

export const MAX_FREE = 400;
export { maskText };

// The lab's one policy of its own, kept apart from the masker: a run of 24 or more letters, digits, + _ = with no separator is not an identity name. A SPIFFE ID or a Kubernetes
// subject has separators, a signature or a key does not. A claim or a stored value (an audience, a subject, a namespace) holding one is credential-shaped; the shared masker
// leaves a bare run alone in free text (a hash or a commit id is ordinary there), so this is the lab's rule for the values it SIGNS and STORES, not a second detector for text.
const RUN = /[A-Za-z0-9+_=]{24,}/;
const RUN_ALL = /[A-Za-z0-9+_=]{24,}/g;
const unfold = (text) => {
  let t = String(text ?? '').normalize('NFKC');
  for (let i = 0; i < 3 && t.includes('%'); i++) { const next = t.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return m; } }); if (next === t) break; t = next; }
  return t.replace(HIDDEN_ALL, '');
};
// True when the text, folded (hidden characters, percent-encoding, look-alikes), holds anything credential-shaped: the shared masker's verdict, or a 24-character run.
export const credentialShaped = (text) => looksLikeCredential(String(text ?? '')) || RUN.test(unfold(text));

// What a refused value shows instead of itself: when it holds a 24-character run, the DECODED form with each run replaced by [masked:long-run] (never the encoded text, which
// would carry the run); otherwise the value unchanged. maskText (the shared masker) is applied to the result by the caller.
export const maskLongRuns = (value) => {
  const flat = unfold(value);
  return RUN.test(flat) ? flat.replace(RUN_ALL, '[masked:long-run]') : String(value ?? '');
};

// Display hygiene for a name, a note or a masked claim: invisible and format characters and C0/C1 controls are DELETED; tab, line feed, carriage return and the line and
// paragraph separators become spaces. Run AFTER masking, so a keyword hidden behind one of them was already found by the masker (which folds them itself).
const HIDDEN_ALL = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Zl}\p{Zp}\u{FFFD}]/gu;
const HIDDEN = /[\p{Default_Ignorable_Code_Point}\p{Cf}\u{FFFD}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu;
export const tidy = (text) => text.replace(/[\t\n\r\u2028\u2029]/g, ' ').replace(HIDDEN, '').replace(/\s+/g, ' ').trim();

// Free text from the visitor: masked FIRST (on the whole text), then tidied and cut to the cap. Never throws, never echoes a raw credential.
export function cleanFree(value, max = MAX_FREE) {
  return tidy(maskText(value)).slice(0, max);
}
