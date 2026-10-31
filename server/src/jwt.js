// Real JWT mechanics on node:crypto: base64url, parse, RS256 sign and verify, and the two forged forms the lab shows (alg none and HS256).
// No library, no network. RSA only (EC keys are never generated here).
import crypto from 'node:crypto';

export const MAX_TOKEN = 4096;
const B64U = /^[A-Za-z0-9_-]*$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
export const fromB64u = (text) => Buffer.from(text, 'base64url');

export const signingInput = (header, payload) => `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;

// The signature step of each form. `key` is a KeyObject for RS256, a secret for HS256.
export const signRS256 = (input, privateKey) => b64u(crypto.sign('RSA-SHA256', Buffer.from(input), privateKey));
export const signHS256 = (input, secret) => b64u(crypto.createHmac('sha256', secret).update(input).digest());

// Splits and decodes without trusting anything. Returns { ok: true, header, payload, input, signature } or { ok: false, code, detail }.
// Every refusal is fixed text: the token itself is never echoed.
export function parseToken(text) {
  const bad = (detail) => ({ ok: false, code: 'malformed_token', detail });
  if (typeof text !== 'string' || text.length === 0) return bad('a token is required');
  if (text.length > MAX_TOKEN) return bad(`the token is longer than ${MAX_TOKEN} characters`);
  const parts = text.split('.');
  if (parts.length !== 3) return bad('a JWT has exactly three dot-separated parts');
  const [h, p, s] = parts;
  if (!h || !p || !B64U.test(h) || !B64U.test(p) || !B64U.test(s)) return bad('the parts are not base64url');
  let header; let payload;
  try { header = JSON.parse(fromB64u(h).toString('utf8')); payload = JSON.parse(fromB64u(p).toString('utf8')); } catch { return bad('the header or payload is not JSON'); }
  if (!isObj(header) || !isObj(payload)) return bad('the header and payload must be JSON objects');
  return { ok: true, header, payload, input: `${h}.${p}`, signature: s };
}

// True only when the RSA signature over the signing input verifies against this public JWK. Never throws.
export function verifyRS256(input, signature, jwk) {
  try {
    if (!signature) return false;
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.verify('RSA-SHA256', Buffer.from(input), key, fromB64u(signature));
  } catch { return false; }
}

// A pinned or published JWK must be a PUBLIC RSA key with a kid. Returns a problem string or null.
export function jwkProblem(jwk) {
  if (!isObj(jwk)) return 'each key must be an object';
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']) if (Object.hasOwn(jwk, k)) return 'private key material is not accepted: pin public keys only';
  if (jwk.kty !== 'RSA') return 'only RSA keys are accepted';
  if (typeof jwk.kid !== 'string' || !/^[A-Za-z0-9._:-]{1,60}$/.test(jwk.kid)) return 'each key needs a short kid';
  if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string' || jwk.n.length > 700 || jwk.e.length > 16 || !B64U.test(jwk.n) || !B64U.test(jwk.e)) return 'n and e must be short base64url strings';
  try { crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }); } catch { return 'not a usable RSA public key'; }
  return null;
}

// A token with its payload altered after signing (the subject gains a character) and the signature left as it was: the "tamper" the lab shows. Never throws.
export function tamperToken(token) {
  const p = parseToken(token);
  if (!p.ok) return typeof token === 'string' ? token : '';
  const payload = { ...p.payload, sub: `${typeof p.payload.sub === 'string' ? p.payload.sub : ''}x` };
  const [h, , s] = token.split('.');
  return `${h}.${b64u(JSON.stringify(payload))}.${s}`;
}
