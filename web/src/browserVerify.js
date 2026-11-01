// The browser-side signature check (WebCrypto, RSASSA-PKCS1-v1_5 with SHA-256). It checks the SIGNATURE ONLY: claims, audience, lifetime, subject, pinned claims, the key
// and the scope are the server's fifteen steps, so this result is never the full verdict. It reads only the issuer's PUBLIC key set from the lab's own origin
// (GET /api/issuers/:id/jwks); no secret or private key ever reaches the page. It never throws: every failure is a result.
import { visible } from "./safeText";
import { workspaceFetch } from "./workspace";

// The same cap as the server (server/src/jwt.js MAX_TOKEN): a longer token is refused at the parse step by both. A test pins the two numbers together.
export const MAX_TOKEN = 4096;
const B64U = /^[A-Za-z0-9_-]*$/;
const bytes = (s) => { const p = s.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };
const reencode = (u8) => { let bin = ""; u8.forEach((b) => { bin += String.fromCharCode(b); }); return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
// Strict, exactly like the server's parser: canonical base64url (decode then re-encode must give the same text), UTF-8 that is valid, a byte-order mark kept (so JSON.parse refuses it), nothing trimmed.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const canonical = (s) => { try { return reencode(bytes(s)) === s; } catch { return false; } };
const json = (s) => { try { const v = JSON.parse(UTF8.decode(bytes(s))); return v !== null && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; } };
const result = (status, reason, extra = {}) => ({ status, reason, ...extra });

// One fetch of the issuer's current public key set: { ok: true, keys } or { ok: false, status }. Same origin only, never cached.
export async function fetchJwks(issuerId, vertical) {
  try {
    const r = await workspaceFetch(`/api/issuers/${encodeURIComponent(issuerId)}/jwks?mode=live&vertical=${encodeURIComponent(vertical)}`, { method: "GET", cache: "no-store" });
    if (!r.ok) return { ok: false, status: r.status };
    const j = await r.json();
    return Array.isArray(j?.keys) ? { ok: true, keys: j.keys } : { ok: false, status: 0 };
  } catch { return { ok: false, status: 0 }; }
}

// status: ok (the signature verifies) | bad (it does not) | no-key (no key to check it against) | refused (the token cannot be checked: malformed, or not RS256) | unavailable (the check could not run)
export async function verifyInBrowser(token, { issuers, vertical, getJwks = fetchJwks, subtle = globalThis.crypto?.subtle } = {}) {
  try {
    if (typeof token !== "string" || token === "") return result("refused", "Malformed token: there is no token to check.");
    if (token.length > MAX_TOKEN) return result("refused", `Malformed token: it is longer than ${MAX_TOKEN} characters, which the lab refuses at the parse step (the browser and the server share this cap).`);
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts.every((p) => B64U.test(p))) return result("refused", "Malformed token: a JWT has exactly three base64url parts (the browser trims nothing, like the server).");
    if (!parts.every(canonical)) return result("refused", "Malformed token: a part is not canonical base64url (several texts can decode to the same bytes, so the lab accepts only one).");
    const header = json(parts[0]); const claims = json(parts[1]);
    if (!header || !claims) return result("refused", "Malformed token: the header and payload must be UTF-8 JSON objects (a byte-order mark or invalid UTF-8 is refused).");
    if (Object.hasOwn(header, "crit")) return result("refused", "The header has a crit parameter naming extensions this check does not understand: RFC 7515 says such a token is rejected.");
    if (header.alg !== "RS256") {
      const alg = typeof header.alg === "string" ? header.alg : "(none given)";
      return result("refused", header.alg === undefined || String(header.alg).toLowerCase() === "none" ? "alg none or missing: an unsigned token has no signature to check." : /^hs/i.test(alg) ? `${visible(alg.slice(0, 12))} is a shared-secret algorithm: there is no public key to check it with.` : `${visible(alg.slice(0, 12))} is not RS256: this check verifies RS256 only.`);
    }
    if (typeof header.kid !== "string" || !header.kid) return result("refused", "The header names no signing key (kid), so there is no key to look up.");
    const issuer = (issuers || []).find((i) => i.url === claims.iss);
    if (!issuer) return result("no-key", "The token's iss names no issuer the lab publishes a key set for.", { kid: header.kid });
    if (!subtle) return result("unavailable", "This browser offers no WebCrypto here (it needs a secure context such as localhost).");
    const set = await getJwks(issuer.id, vertical);
    if (!set.ok) return result("unavailable", set.status === 503 ? "The issuer is down: its key set cannot be fetched. A browser has no last-known-good cache, unlike the gateway." : "The issuer's key set could not be fetched.", { kid: header.kid });
    const jwk = set.keys.find((k) => k && k.kid === header.kid);
    if (!jwk) return result("no-key", `kid ${visible(header.kid.slice(0, 40))} is not in ${visible(issuer.name)}'s published key set now (no key: not the same as an invalid signature).`, { kid: header.kid });
    const key = await subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await subtle.verify("RSASSA-PKCS1-v1_5", key, bytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    return ok ? result("ok", "The RSA signature verifies against the issuer's published key.", { kid: header.kid }) : result("bad", "The signature does not verify against the published key: the token was altered or signed by someone else.", { kid: header.kid });
  } catch {
    return result("unavailable", "The browser check could not run.");
  }
}

// Compare the browser's signature result with what the server's fifteen steps said about the signature. Only the signature is comparable. When they differ the text says
// WHY: a parse-stage difference, a key lookup difference (cache against the published set now), or a retired key.
export function compareResults(server, browser) {
  if (!browser) return { kind: "none", text: "" };
  if (!server || !Array.isArray(server.steps)) return { kind: "none", text: "Run Verify to compare this with the server's verdict." };
  if (browser.status === "unavailable") return { kind: "not-comparable", text: "The browser check could not run, so there is nothing to compare." };
  const sig = server.steps.find((s) => s.id === "signature");
  const stop = server.steps.find((s) => s.status === "fail");
  const serverSig = sig?.status === "pass" ? "ok" : sig?.status === "fail" ? "bad" : "not-reached";
  const say = (kind, text) => ({ kind, text });
  const bs = browser.status === "no-key" ? "there is no key" : browser.status;
  if (serverSig === "ok") return browser.status === "ok" ? say("agree", "Both checked the signature and it verifies.") : say("disagree", `Key lookup difference: the server's signature step passed (against the key set the gateway holds, which may be cached), but the browser says ${bs} against the key set the issuer publishes now. A retired or rotated key looks like this.`);
  if (serverSig === "bad") return browser.status === "bad" ? say("agree", "Both found the signature invalid.") : say("disagree", `The server found the signature invalid, but the browser says ${bs}: the two looked at different keys or the browser could not find one.`);
  const early = ["parse", "alg", "keyset"].includes(stop?.id);
  if (!early) return say("not-comparable", `The server stopped at the ${stop?.id || "an earlier"} step, before the signature, so only the browser looked at it.`);
  if (browser.status === "refused" || browser.status === "no-key") return say("agree", `Neither could check a signature: the server stopped at the ${stop.id} step (${server.code}) and the browser says ${browser.status}.`);
  if (stop.id === "parse") return say("disagree", `Parse-stage difference: the server refused the token while parsing it (${server.code}), but the browser parsed it and says ${browser.status}. The two parsers are meant to be identical, so this is a defect to report.`);
  if (stop.id === "alg") return say("disagree", `Algorithm-stage difference: the server refused the algorithm (${server.code}) but the browser went on to check a signature and says ${browser.status}.`);
  return say("disagree", `Key lookup difference: the gateway could not find the key (${server.code}${server.refresh?.attempted === false ? ", its refresh was cooled down" : server.refresh?.ok === false ? ", its refresh failed" : ""}) but the issuer publishes it now, and the browser says ${browser.status}.`);
}
