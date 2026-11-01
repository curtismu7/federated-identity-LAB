// Fixes from the independent review, driven against the real server: a verdict or browser answer started under one (vertical, mode) never lands in another, the editor
// shows notices for what it signs, and the browser parser is as strict as the server's.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { VERTICALS } from "../../server/src/cast.js";
import App from "./App";
import { forgetWorkspace } from "./workspace";

const C = VERTICALS.finance;
let server; let base; const realFetch = globalThis.fetch; let seen = []; let gate = () => null; let consumed = [];
beforeAll(async () => {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json" }) }));
  base = base.replace(/\/$/, "");
  globalThis.fetch = async (u, init = {}) => {
    const url = typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u;
    seen.push({ url: String(url), body: typeof init.body === "string" ? init.body : "" });
    const g = gate(String(url), init); if (g) await g;
    const res = await realFetch(url, { ...init, headers: { origin: base, ...(init.headers || {}) } });
    const json = res.json.bind(res);
    res.json = async () => { const j = await json(); consumed.push(String(url)); return j; };
    return res;
  };
});
afterAll(async () => { globalThis.fetch = realFetch; await new Promise((r) => server.close(r)); });
beforeEach(() => { cleanup(); forgetWorkspace(); seen = []; gate = () => null; consumed = []; try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; });

const T = { timeout: 20000 };
const mount = async () => { render(<App />); await screen.findByTestId("identities", {}, T); };
const tab = (name) => userEvent.click(screen.getByRole("tab", { name }));
const click = (id) => userEvent.click(screen.getByTestId(id));
const live = async () => { await click("mode-live"); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/)); await waitFor(() => expect(screen.getByTestId("revoke-fid-001")).toBeEnabled(), T); };
const setValue = (id, value) => fireEvent.change(screen.getByTestId(id), { target: { value } });
const pick = (id, value) => userEvent.selectOptions(screen.getByTestId(id), value);
const settled = async (v) => { await waitFor(() => expect(screen.getByTestId("vertical").value).toBe(v), T); await waitFor(() => expect(screen.queryByTestId("settling")).toBeNull(), T); expect(screen.queryByTestId("render-error")).toBeNull(); };
const mintPreset = async (id) => { await tab("Verify"); await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T); await pick("preset", id); await click("mint"); await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T); };
const verifyIt = async () => { await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T); await waitFor(() => expect(screen.getByTestId("browser-status")).toBeInTheDocument(), T); };
const code = () => screen.getByTestId("verdict-code").textContent;
const browserStatus = () => screen.getByTestId("browser-status").textContent;
const releaseAfter = async (needle) => { await waitFor(() => expect(consumed.some((u) => u.includes(needle))).toBe(true), T); await act(async () => { await Promise.resolve(); await Promise.resolve(); }); };
const holdOnce = (needle) => { let release; const held = new Promise((r) => { release = r; }); let used = false; gate = (u) => (!used && u.includes(needle) ? ((used = true), held) : null); return release; };
const freshEditor = () => { expect(screen.queryByTestId("verdict")).toBeNull(); expect(screen.queryByTestId("browser-summary")).toBeNull(); expect(screen.getByTestId("token").value).toBe(""); };

describe("a verdict started under one vertical or mode never lands in another", () => {
  it("a verify in flight when the vertical changes: the Health editor stays clean (no Finance verdict, no steps, no deployment) after the held answer arrives", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    const release = holdOnce("/api/verify");
    await click("verify");
    await pick("vertical", "health"); await settled("health");
    release(); await releaseAfter("/api/verify");
    await tab("Verify"); await waitFor(() => expect(screen.getByTestId("f-sub").value).toContain(VERTICALS.health.castAgent), T);
    freshEditor(); expect(document.body.textContent).not.toContain(`${C.castNs}/${C.castAgent}`);
  }, 60000);

  it("a verify in flight when the MODE changes (and changes back): the editor is fresh and the late answer is dropped, even though the context looks the same again", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    const release = holdOnce("/api/verify");
    await click("verify");
    await click("mode-mock"); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/MOCK mode/), T);
    await click("mode-live"); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/), T); await waitFor(() => expect(screen.queryByTestId("settling")).toBeNull(), T);
    release(); await releaseAfter("/api/verify");
    await tab("Verify"); await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    freshEditor();
  }, 60000);

  it("a browser check in flight when the vertical changes: its late answer is dropped too", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    const release = holdOnce("/jwks");
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T);
    await pick("vertical", "health"); await settled("health");
    release(); await releaseAfter("/jwks");
    await tab("Verify"); await waitFor(() => expect(screen.getByTestId("f-sub").value).toContain(VERTICALS.health.castAgent), T);
    freshEditor();
  }, 60000);

  it("starting a new verification clears the previous verdict at once (a stale verdict is never read as the new one)", async () => {
    await mount(); await live(); await mintPreset("k8s-right"); await verifyIt();
    const release = holdOnce("/api/verify");
    await click("verify");
    await waitFor(() => expect(screen.queryByTestId("verdict")).toBeNull(), T);
    expect(screen.queryByTestId("browser-summary")).toBeNull();
    release(); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T);
  }, 60000);
});

describe("the editor signs exactly what is typed and says so", () => {
  it("a zero-width space in the subject is signed as typed, noticed, shown written out, and refused by the gateway; a credential is refused", async () => {
    await mount(); await live(); await mintPreset("lk-zero-width-sub");
    expect(screen.getByTestId("mint-notices")).toHaveTextContent(/hidden characters/); expect(screen.getByTestId("mint-notices")).toHaveTextContent(/signs exactly what you typed/i);
    await verifyIt(); expect(code()).toBe("subject_mismatch");
    expect(screen.getByTestId("step-subject")).toHaveTextContent(/\\u\{200b\}/);
    expect(browserStatus()).toBe("ok"); expect(screen.getByTestId("agreement")).toBeInTheDocument();
  }, 60000);

  it("every lookalike preset is refused at its own step; a trailing slash on the audience is not forgiven", async () => {
    await mount(); await live();
    for (const [id, want] of [["lk-fullwidth-sub", "subject_mismatch"], ["lk-cyrillic-sub", "subject_mismatch"], ["lk-case-sub", "subject_mismatch"], ["lk-percent-sub", "subject_mismatch"], ["lk-trailing-space-sub", "subject_mismatch"], ["lk-trailing-slash-aud", "aud_mismatch"], ["lk-trailing-slash-iss", "issuer_mismatch"]]) {
      await mintPreset(id); await verifyIt(); expect(code()).toBe(want);
    }
    await mintPreset("lk-fullwidth-sub"); expect(screen.getByTestId("mint-notices")).toHaveTextContent(/non-ASCII/);
  }, 120000);
});

describe("the browser parser is as strict as the server's, and finds the issuer by iss", () => {
  const part = (o) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const b64 = (u8) => { let s = ""; u8.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
  const submit = async (text) => { setValue("token", text); await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T); await waitFor(() => expect(screen.getByTestId("browser-status")).toBeInTheDocument(), T); };

  it("trailing and leading whitespace, a BOM in the header or payload, a non-canonical signature and a crit header are refused by BOTH, and the page says they agree", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    const good = screen.getByTestId("token").value; const [h, p, s] = good.split(".");
    const bom = (txt) => b64(Uint8Array.from([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(txt)]));
    const dec = (x) => new TextDecoder().decode(Uint8Array.from(atob(x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
    const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; const last = ALPHA.indexOf(s.at(-1)); const alt = [...ALPHA].find((c, i) => i !== last && (i & ~15) === (last & ~15));
    const cases = { trailing: `${good}  `, leading: ` ${good}`, bomHeader: `${bom(dec(h))}.${p}.${s}`, bomPayload: `${h}.${bom(dec(p))}.${s}`, nonCanonical: `${h}.${p}.${s.slice(0, -1)}${alt}` };
    for (const [name, t] of Object.entries(cases)) { await submit(t); expect(code(), name).toBe("malformed_token"); expect(browserStatus(), name).toBe("refused"); expect(screen.queryByTestId("disagreement"), name).toBeNull(); expect(screen.getByTestId("agreement"), name).toBeInTheDocument(); }
    await submit(`${part({ alg: "RS256", typ: "JWT", kid: "kube-key-1", crit: ["exp"] })}.${p}.${s}`);
    expect(code()).toBe("crit_unsupported"); expect(browserStatus()).toBe("refused"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/crit/); expect(screen.queryByTestId("disagreement")).toBeNull();
  }, 120000);

  it("a token of another issuer is checked against THAT issuer's key set (not the first one): GitHub, GitLab, SPIFFE and the private issuer all verify in the browser", async () => {
    await mount(); await live();
    for (const id of ["gh-right", "gitlab-right", "spiffe-right", "private-right"]) { await mintPreset(id); await verifyIt(); expect(code(), id).toBe("allowed"); expect(browserStatus(), id).toBe("ok"); }
    expect(seen.map((x) => x.url).some((u) => /issuers\/github\/jwks/.test(u)) && seen.some((x) => /issuers\/spire\/jwks/.test(x.url)) && seen.some((x) => /issuers\/private\/jwks/.test(x.url))).toBe(true);
  }, 120000);

  it("when the two still differ the page says WHY: a retired key is a key lookup difference", async () => {
    await mount(); await live(); await mintPreset("k8s-right"); await verifyIt(); const old = screen.getByTestId("token").value;
    await tab("Issuers and keys"); await click("rotate-kube"); await waitFor(() => expect(screen.getByTestId("kid-kube")).toHaveTextContent("kube-key-2"), T);
    await tab("Verify"); setValue("token", old); await verifyIt();
    expect(screen.getByTestId("disagreement")).toHaveTextContent(/Key lookup difference/);
  }, 60000);
});
