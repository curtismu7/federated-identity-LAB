// The browser-side WebCrypto signature check next to the server's verdict, and the vertical-switch / render-guard patterns, driven against the real server.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { VERTICALS } from "../../server/src/cast.js";
import App, { TABS } from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import { compareResults, verifyInBrowser } from "./browserVerify";
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
beforeEach(async () => { cleanup(); forgetWorkspace(); seen = []; gate = () => null; consumed = []; try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; // rule 19: the server holds the mode, so every test starts from mock
  await realFetch(`${base}/api/mode`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ source: "mock" }) }); });

const T = { timeout: 20000 };
const mount = async () => { render(<App />); await screen.findByTestId("identities", {}, T); };
const tab = (name) => userEvent.click(screen.getByRole("tab", { name }));
const click = (id) => userEvent.click(screen.getByTestId(id));
const live = async () => { await click("mode-live"); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/)); await waitFor(() => expect(screen.getByTestId("revoke-fid-001")).toBeEnabled(), T); };
const setValue = (id, value) => fireEvent.change(screen.getByTestId(id), { target: { value } });
const pick = (id, value) => userEvent.selectOptions(screen.getByTestId(id), value);
const mintPreset = async (id) => { await tab("Verify"); await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T); await pick("preset", id); await click("mint"); await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T); };
const verifyIt = async () => { await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T); await waitFor(() => expect(screen.getByTestId("browser-status")).toBeInTheDocument(), T); };
const browserStatus = () => screen.getByTestId("browser-status").textContent;
const code = () => screen.getByTestId("verdict-code").textContent;

describe("the in-browser WebCrypto signature check beside the server verdict", () => {
  it("a valid token: the server allows it and the browser verifies the signature; both are shown side by side and the page says the browser result is not the full verdict", async () => {
    await mount(); await live(); await mintPreset("k8s-right"); await verifyIt();
    expect(code()).toBe("allowed"); expect(browserStatus()).toBe("ok");
    expect(screen.getByTestId("browser-side")).toHaveTextContent(/Verified in this browser \(WebCrypto RS256\)/);
    expect(screen.getByTestId("server-summary")).toHaveTextContent(/signature step:\s*pass/);
    expect(screen.getByTestId("compare")).toHaveTextContent(/only the signature/); expect(screen.getByTestId("compare")).toHaveTextContent(/not the full verdict/);
    expect(screen.getByTestId("agreement")).toHaveTextContent(/Both checked the signature and it verifies/); expect(screen.queryByTestId("disagreement")).toBeNull();
    for (const s of seen) expect(s.url.startsWith(base)).toBe(true); // same origin only
    expect(seen.some((s) => /\/api\/issuers\/kube\/jwks\?mode=live/.test(s.url))).toBe(true);
  });

  it("a payload tampered in the browser: the browser's WebCrypto check fails and the server says bad_signature; they agree", async () => {
    await mount(); await live(); await mintPreset("k8s-right"); await click("tamper"); await verifyIt();
    expect(code()).toBe("bad_signature"); expect(browserStatus()).toBe("bad"); expect(screen.getByTestId("agreement")).toHaveTextContent(/Both found the signature invalid/);
  });

  it("alg none and HS256 are refused by the browser with the reason, and the server refuses them before any key", async () => {
    await mount(); await live();
    await mintPreset("alg-none"); await verifyIt(); expect(code()).toBe("alg_none"); expect(browserStatus()).toBe("refused"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/unsigned/); expect(screen.getByTestId("agreement")).toBeInTheDocument();
    await mintPreset("alg-hs256"); await verifyIt(); expect(code()).toBe("alg_symmetric"); expect(browserStatus()).toBe("refused"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/shared-secret/);
    await mintPreset("alg-es256"); await verifyIt(); expect(browserStatus()).toBe("refused"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/not RS256/);
  });

  it("an unknown kid: the issuer rotated, the browser fetches the CURRENT published key set (not a cached one) and verifies; a kid nobody publishes is 'no key', not 'invalid'", async () => {
    await mount(); await live();
    await mintPreset("k8s-right"); await verifyIt(); expect(browserStatus()).toBe("ok");
    await tab("Issuers and keys"); await click("rotate-kube"); await waitFor(() => expect(screen.getByTestId("kid-kube")).toHaveTextContent("kube-key-2"), T);
    await mintPreset("k8s-right"); await verifyIt(); expect(code()).toBe("allowed"); expect(browserStatus()).toBe("ok");
    expect(seen.filter((s) => /\/jwks\?/.test(s.url)).length).toBeGreaterThanOrEqual(2); // fetched again after the rotation
    await mintPreset("attacker-own-kid"); await verifyIt();
    expect(code()).toBe("unknown_kid"); expect(browserStatus()).toBe("no-key"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/not the same as an invalid signature/); expect(screen.getByTestId("agreement")).toBeInTheDocument();
  });

  it("a retired key: the gateway still holds the old key in its cache and verifies, the issuer no longer publishes it so the browser finds no key: the page flags the DISAGREEMENT", async () => {
    await mount(); await live();
    await mintPreset("k8s-right"); await verifyIt();
    const old = screen.getByTestId("token").value;
    await tab("Issuers and keys"); await click("rotate-kube"); await waitFor(() => expect(screen.getByTestId("kid-kube")).toHaveTextContent("kube-key-2"), T);
    await tab("Verify"); setValue("token", old); await verifyIt();
    expect(code()).toBe("allowed"); expect(browserStatus()).toBe("no-key");
    expect(screen.getByTestId("disagreement")).toHaveTextContent(/DISAGREEMENT/); expect(screen.getByTestId("disagreement")).toHaveTextContent(/cached/);
  });

  it("a malformed token is refused by the browser (and by the server) without throwing into the page", async () => {
    await mount(); await live(); await tab("Verify");
    await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    for (const text of ["not a token", "a.b", "a.b.c.d", "@@@.@@@.@@@", "e30.e30.e30", "e30.W10.e30"]) {
      setValue("token", text); await click("browser-check");
      await waitFor(() => expect(screen.getByTestId("browser-status")).toHaveTextContent(/refused|no-key/), T);
      expect(screen.queryByTestId("render-error")).toBeNull();
    }
    setValue("token", "not a token"); await verifyIt(); expect(code()).toBe("malformed_token"); expect(browserStatus()).toBe("refused"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/Malformed/);
  });

  it("the issuer being down is 'unavailable' for the browser (it has no last-known-good cache) and not a disagreement, while the gateway still verifies from its cache", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    await tab("Issuers and keys"); await click("down-kube"); await waitFor(() => expect(screen.getByTestId("up-kube")).toBeInTheDocument(), T);
    await tab("Verify"); await verifyIt();
    expect(code()).toBe("allowed"); expect(browserStatus()).toBe("unavailable"); expect(screen.getByTestId("browser-summary")).toHaveTextContent(/no last-known-good cache/); expect(screen.queryByTestId("disagreement")).toBeNull();
  });

  it("Mock mode: the browser check is Live only, disabled, with the reason shown; the Mock table holds no token or key", async () => {
    await mount(); await tab("Verify");
    expect(await screen.findByTestId("browser-live-only", {}, T)).toBeInTheDocument();
    expect(screen.getByTestId("browser-check-mock")).toBeDisabled(); expect(screen.getByTestId("browser-live-only-reason")).toHaveTextContent(/Live only/); expect(screen.getByTestId("browser-live-only-reason")).toHaveTextContent(/never a token or a key/);
    expect(seen.some((s) => /\/jwks/.test(s.url))).toBe(false);
  });

  it("only the public key set is fetched: no private member ever reaches the page", async () => {
    await mount(); await live(); await mintPreset("k8s-right"); await verifyIt();
    const r = await realFetch(`${base}/api/issuers/kube/jwks?mode=live&vertical=finance`); const t = await r.text();
    expect(t).not.toMatch(/"(d|p|q|dp|dq|qi)":/);
  });

  it("a stale browser answer never replaces a newer one: the held JWKS answer arrives after the token was edited and is dropped", async () => {
    await mount(); await live(); await mintPreset("k8s-right");
    let release; const held = new Promise((r) => { release = r; });
    gate = (u) => (u.includes("/jwks") ? held : null);
    await click("browser-check");
    await click("tamper");
    release();
    await waitFor(() => expect(consumed.some((u) => u.includes("/jwks"))).toBe(true), T);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.queryByTestId("browser-summary")).toBeNull();
    gate = () => null; await click("browser-check");
    await waitFor(() => expect(browserStatus()).toBe("bad"), T);
  }, 60000);
});

describe("verifyInBrowser and compareResults never throw", () => {
  const issuers = [{ id: "kube", name: "Kube", url: "https://kube-api.cluster-a.example" }];
  const part = (o) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const tok = (h, p) => `${part(h)}.${part(p)}.c2ln`;
  it("every odd input is a result, never an exception", async () => {
    const inputs = [undefined, null, 5, {}, [], "", "   ", "x".repeat(100000), "a.b.c", tok({ alg: 5 }, {}), tok({ alg: "RS256" }, {}), tok({ alg: "RS256", kid: 5 }, {}), tok({ alg: "RS256", kid: "k" }, { iss: 5 }), tok({ alg: "RS256", kid: "k" }, { iss: "https://nowhere.example" }),
      tok({ alg: "RS256", kid: "k" }, { iss: issuers[0].url }), `${part({ alg: "RS256", kid: "k" })}.%%%.c2ln`, `${part([1])}.${part({})}.x`];
    for (const t of inputs) { const r = await verifyInBrowser(t, { issuers, vertical: "finance", getJwks: async () => ({ ok: true, keys: [{ kid: "k", n: "AQAB", e: "AQAB" }] }) }); expect(["ok", "bad", "no-key", "refused", "unavailable"]).toContain(r.status); expect(typeof r.reason).toBe("string"); }
    const good = tok({ alg: "RS256", kid: "k" }, { iss: issuers[0].url });
    expect((await verifyInBrowser(good, { issuers, vertical: "x", getJwks: async () => { throw new Error("boom"); } })).status).toBe("unavailable");
    expect((await verifyInBrowser(good, { issuers, vertical: "x", getJwks: async () => ({ ok: false, status: 503 }) })).status).toBe("unavailable");
    expect(["unavailable", "bad"]).toContain((await verifyInBrowser(good, { issuers, vertical: "x", getJwks: async () => ({ ok: true, keys: [null, { kid: "k", n: "!!", e: "!!" }] }) })).status);
    expect((await verifyInBrowser(good, { issuers, vertical: "x", subtle: null, getJwks: async () => ({ ok: true, keys: [] }) })).status).toBe("unavailable");
    expect((await verifyInBrowser(good, { issuers, vertical: "x", getJwks: async () => ({ ok: true, keys: [] }) })).status).toBe("no-key");
  });
  it("the comparison: agree, disagree and not-comparable in each combination", () => {
    const steps = (sig, stop) => ["parse", "identity", "alg", "issuer", "keyset", "signature", "expiry"].map((id) => ({ id, status: id === "signature" ? sig : id === stop ? "fail" : "pass" }));
    const srv = (sig, stop) => ({ steps: steps(sig, stop) });
    const b = (status) => ({ status });
    expect(compareResults(srv("pass"), b("ok")).kind).toBe("agree"); expect(compareResults(srv("pass"), b("bad")).kind).toBe("disagree"); expect(compareResults(srv("pass"), b("no-key")).kind).toBe("disagree"); expect(compareResults(srv("pass"), b("refused")).kind).toBe("disagree");
    expect(compareResults(srv("fail"), b("bad")).kind).toBe("agree"); expect(compareResults(srv("fail"), b("ok")).kind).toBe("disagree");
    expect(compareResults(srv("skip", "alg"), b("refused")).kind).toBe("agree"); expect(compareResults(srv("skip", "keyset"), b("no-key")).kind).toBe("agree"); expect(compareResults(srv("skip", "alg"), b("ok")).kind).toBe("disagree");
    expect(compareResults(srv("skip", "identity"), b("ok")).kind).toBe("not-comparable"); expect(compareResults(srv("skip", "issuer"), b("bad")).kind).toBe("not-comparable");
    expect(compareResults(srv("pass"), b("unavailable")).kind).toBe("not-comparable"); expect(compareResults(null, b("ok")).kind).toBe("none"); expect(compareResults(srv("pass"), null).kind).toBe("none"); expect(compareResults({}, b("ok")).kind).toBe("none");
  });
});

describe("the vertical switch on every tab, in both modes", () => {
  const NAMES = (v) => VERTICALS[v].castAgent;
  const noError = () => expect(screen.queryByTestId("render-error")).toBeNull();
  const settled = async (v) => { await waitFor(() => expect(screen.getByTestId("vertical").value).toBe(v), T); await waitFor(() => expect(screen.queryByTestId("settling")).toBeNull(), T); noError(); };

  it("finance > health > retail > finance on every tab in Mock and in Live: no blank page, no thrown error, the names follow", async () => {
    await mount();
    for (const mode of ["mock", "live"]) {
      if (mode === "live") { await tab("Federated Identity"); await live(); }
      for (const t of TABS) {
        await tab(t.label);
        for (const v of ["health", "retail", "finance"]) {
          await pick("vertical", v); await settled(v);
          expect(document.querySelector("[role=tabpanel]").textContent.length).toBeGreaterThan(50);
          if (t.id === "identities") await waitFor(() => expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(NAMES(v)), T);
          if (t.id === "verify" && mode === "live") await waitFor(() => expect(screen.getByTestId("f-sub").value).toContain(NAMES(v)), T);
          if (t.id === "talk") expect(screen.getByTestId("talk-track")).toBeInTheDocument();
        }
      }
    }
  }, 240000);

  it("rapid back-to-back changes (no waiting between them) never blank the page; the last choice wins", async () => {
    await mount(); await live();
    for (const t of ["Federated Identity", "Verify", "Self-Hosted Agents", "Audit", "Issuers and keys", "Diagram"]) {
      await tab(t);
      fireEvent.change(screen.getByTestId("vertical"), { target: { value: "health" } }); fireEvent.change(screen.getByTestId("vertical"), { target: { value: "retail" } }); fireEvent.change(screen.getByTestId("vertical"), { target: { value: "finance" } }); fireEvent.change(screen.getByTestId("vertical"), { target: { value: "health" } });
      await settled("health"); await pick("vertical", "finance"); await settled("finance");
    }
    await tab("Federated Identity"); await waitFor(() => expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(NAMES("finance")), T);
  }, 120000);

  it("a vertical change while a write is held in flight: the stale answer is dropped and nothing crashes", async () => {
    await mount(); await live(); await tab("Issuers and keys");
    await waitFor(() => expect(screen.getByTestId("advance-5")).toBeEnabled(), T);
    let release; const held = new Promise((r) => { release = r; });
    gate = (u) => (u.includes("/api/clock") ? held : null);
    await click("advance-5"); await pick("vertical", "health"); await settled("health");
    release(); await waitFor(() => expect(consumed.some((u) => u.includes("/api/clock"))).toBe(true), T);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    noError(); expect(screen.getByTestId("vertical").value).toBe("health");
  }, 60000);

  it("the Verify editor and the sensor forms follow a vertical change (no stale node or namespace from the previous one)", async () => {
    await mount(); await live(); await tab("Self-Hosted Agents");
    await waitFor(() => expect(screen.getByTestId("enrol")).toBeEnabled(), T); await click("enrol"); await waitFor(() => expect(screen.getByTestId("r-node")).toBeInTheDocument(), T);
    expect(screen.getByTestId("r-node").value).toBe(C.castNode1);
    await pick("vertical", "retail"); await settled("retail");
    await tab("Self-Hosted Agents"); await waitFor(() => expect(screen.getByTestId("enrol")).toBeEnabled(), T); await click("enrol"); await waitFor(() => expect(screen.getByTestId("r-node")).toBeInTheDocument(), T);
    expect(screen.getByTestId("r-node").value).toBe(VERTICALS.retail.castNode1);
    await waitFor(() => expect(screen.getByTestId("r-send")).toBeEnabled(), T); await click("r-send");
    await waitFor(() => expect(screen.getByTestId("report-result")).toHaveTextContent(/allowed/), T);
  }, 90000);
});

describe("the render guard", () => {
  it("a tab that throws while rendering shows a short message and a way back instead of a blank page; changing the key clears it", () => {
    let boom = true; const Bad = () => { if (boom) throw new Error("render mismatch"); return <p>fine</p>; };
    const { rerender } = render(<ErrorBoundary key="a"><Bad /></ErrorBoundary>);
    expect(screen.getByTestId("render-error")).toHaveTextContent(/could not be drawn/);
    boom = false; fireEvent.click(screen.getByTestId("render-retry")); expect(screen.getByText("fine")).toBeInTheDocument();
    boom = true; rerender(<ErrorBoundary key="b"><Bad /></ErrorBoundary>); expect(screen.getByTestId("render-error")).toBeInTheDocument();
    boom = false; rerender(<ErrorBoundary key="c"><Bad /></ErrorBoundary>); expect(screen.queryByTestId("render-error")).toBeNull();
  });
});
