// The one masker of this lab: shared-masker 1.4.0 (commit 9bc664a, copied unchanged to ./shared/), configured once for this app. Masking is a heuristic: it catches the
// shapes it knows and can miss a short random value that has no keyword in front of it. README says so.
//
// Opaque names (the value under them is NOT a secret, or is shown raw by design). The lab writes each one itself:
//   traceparent, traceId   W3C trace ids the lab generates for every action (the engine refuses a visitor claim of the same name: RESERVED_CLAIMS in engine.js);
//   mintedToken            the token the lab's own mock issuer just minted. Education: it is shown raw and labelled "lab-minted" (a pasted token is masked, never shown; same RESERVED_CLAIMS);
//   n, e                   the PUBLIC half of an RSA key in a JWKS (the browser check reads them); a pasted key set is validated as RSA public keys before it is stored.
import { createMasker } from './shared/mask.js';
import { backends } from './catalog.js';
import { PRESETS } from './data.js';

export const OPAQUE_KEYS = new Set(['traceparent', 'traceId', 'mintedToken', 'n', 'e']);

// Two members whose NAME looks like a secret but whose value is the lab's own text, decided by the VALUE (a visitor cannot make a value equal to one of these):
//   credential  the placeholder text of a backend's configured credential ("[masked: the application's own static credential]"), the lab holds no secret;
//   preset      the id of one of the lab's presets ("k8s-right");
//   inboundTokenForwarded   the lab's own boolean (always false: the token stops at the gateway); a boolean carries no text.
const PLACEHOLDERS = new Set(backends({ castBrand: 'x', castHost: 'x' }).map((b) => b.credential));
const PRESET_IDS = new Set(PRESETS.map((p) => p.id));
const labText = (key, _path, value) => (typeof value === 'string' && ((key === 'credential' && PLACEHOLDERS.has(value)) || (key === 'preset' && PRESET_IDS.has(value)))) || (key === 'inboundTokenForwarded' && typeof value === 'boolean');

// maxNodes / maxTotalChars: the whole Mock table (three verticals, every scenario) is one object in the tests and in the table builder; the defaults (20,000 nodes) would cut it
// with a [masked:too-large] mark. A request body is capped at 32 KB, so the larger bound is not a cost a visitor can drive up.
const BOUNDS = { maxNodes: 400000, maxTotalChars: 16_000_000 };

// The answer mask: every answer that can carry something a visitor typed (Live state, every write, hops, audit). A member NAMED like a secret (token, password ...) is masked
// whatever its value looks like, except the opaque ones above.
const masker = createMasker({ opaqueKeys: OPAQUE_KEYS, opaque: labText, ...BOUNDS });
// The static mask: what the lab itself wrote (the story, the diagrams, the Mock tables), which no visitor can change. Prose may use the words "token" and "password" as words, so the
// member name is not read ('none'); secret-looking TEXT inside a value is still masked.
const prose = createMasker({ opaqueKeys: OPAQUE_KEYS, keyMode: 'none', ...BOUNDS });

export const { maskText, maskDeep, looksLikeCredential, isCredentialId } = masker;
export const maskStatic = prose.maskDeep;
// An older name of maskText, kept so no call site changes.
export const maskResponseText = (text) => masker.maskText(String(text));
