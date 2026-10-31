// Browser-side token helpers: decode a pasted token for display (never trusted, never sent anywhere), and tamper with it the way the lab shows.
const dec = (s) => { try { const p = s.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4)); return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))); } catch { return null; } };
const enc = (obj) => { const bytes = new TextEncoder().encode(JSON.stringify(obj)); let bin = ""; bytes.forEach((b) => { bin += String.fromCharCode(b); }); return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };

export function decodeToken(token) {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3) return null;
  const header = dec(parts[0]); const payload = dec(parts[1]);
  return header && payload ? { header, payload, signature: parts[2] } : null;
}
// The payload's subject gains a character; the signature stays as it was, so the signature no longer matches.
export function tamper(token) {
  const parts = String(token || "").trim().split(".");
  const payload = parts.length === 3 ? dec(parts[1]) : null;
  if (!payload || typeof payload !== "object") return token;
  return `${parts[0]}.${enc({ ...payload, sub: `${typeof payload.sub === "string" ? payload.sub : ""}x` })}.${parts[2]}`;
}
const pad2 = (n) => String(n).padStart(2, "0");
// A lab time (epoch seconds) as "2026-11-02 09:05:00" UTC.
export const labTime = (sec) => { const d = new Date(sec * 1000); return Number.isFinite(d.getTime()) ? `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}` : "-"; };
