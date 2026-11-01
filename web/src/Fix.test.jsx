// Fix pass: the browser and server verifiers share one token cap (S4), the diagram tab recovers from a failed load (N6), the workspace id the page keeps is one the server accepts (N3), and the
// diagram opens with every box in view at phone width (N4).
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { Engine } from "../../server/src/engine.js";
import { VERTICALS } from "../../server/src/cast.js";
import { ISSUER } from "../../server/src/catalog.js";
import { keyAt } from "../../server/src/keys.js";
import { MAX_TOKEN as SERVER_MAX_TOKEN } from "../../server/src/jwt.js";
import { validWorkspaceId as serverValid } from "../../server/src/workspaces.js";
import App from "./App";
import { MAX_TOKEN, compareResults, verifyInBrowser } from "./browserVerify";
import { MIN_ZOOM, fitFor } from "./components/PatternDiagram";
import { forgetWorkspace, validWorkspaceId, workspaceFetch, workspaceId } from "./workspace";

const C = VERTICALS.finance;
const SUB = `system:serviceaccount:${C.castNs}:${C.castAgent}`;
const GW = `https://gateway.${C.castHost}.example`;
let server; let base; const realFetch = globalThis.fetch; let fail = null;
beforeAll(async () => {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json" }) }));
  base = base.replace(/\/$/, "");
  globalThis.fetch = async (u, init = {}) => {
    const url = typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u;
    if (fail && fail(String(url))) throw new TypeError("Failed to fetch");
    return realFetch(url, { ...init, headers: { origin: base, ...(init.headers || {}) } });
  };
});
afterAll(async () => { globalThis.fetch = realFetch; await new Promise((r) => server.close(r)); });
beforeEach(() => { cleanup(); forgetWorkspace(); fail = null; try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; });

const T = { timeout: 20000 };
const b64 = (b) => Buffer.from(b).toString("base64url");
// A validly signed token for the Kubernetes issuer's first key with the given header and payload text.
const tok = (hText, pText) => { const h = b64(hText); const p = b64(pText); return `${h}.${p}.${b64(crypto.sign("RSA-SHA256", Buffer.from(`${h}.${p}`), keyAt(ISSUER.kube.slot * 6).privateKey))}`; };
const HDR = '{"alg":"RS256","typ":"JWT","kid":"kube-key-1"}';
const payload = (e, over = {}) => JSON.stringify({ iss: ISSUER.kube.url, sub: SUB, aud: GW, exp: e.s.now + 3600, iat: e.s.now, ...over });

describe("one token cap for the browser and the server (S4)", () => {
  it("the cap is the same number on both sides", () => { expect(MAX_TOKEN).toBe(4096); expect(MAX_TOKEN).toBe(SERVER_MAX_TOKEN); });

  it("matrix classes pay:hugeClaim, sig:over4096 and hdr:deepNest: the server says malformed_token, the browser refuses too, and the page calls it agreement (not a defect)", async () => {
    const e = new Engine(C);
    const issuers = e.snapshot().issuers;
    const getJwks = async (id) => ({ ok: true, keys: e.jwksOf(id).keys });
    const cases = {
      "pay:hugeClaim": tok(HDR, payload(e, { big: "A".repeat(5000) })),
      "sig:over4096": tok(HDR, payload(e, { big: "A".repeat(4200) })),
      "hdr:deepNest": tok(`{"alg":"RS256","kid":"kube-key-1","x":${"[".repeat(2000)}${"]".repeat(2000)}}`, payload(e)),
      "sig:over4096huge": "a".repeat(100000),
    };
    for (const [name, token] of Object.entries(cases)) {
      expect(token.length, name).toBeGreaterThan(4096);
      const r = e.verify({ token, identityId: "fid-001", service: "mcp" });
      const b = await verifyInBrowser(token, { issuers, vertical: "finance", getJwks });
      expect(r.code, name).toBe("malformed_token");
      expect(b.status, name).toBe("refused"); expect(b.reason, name).toMatch(/longer than 4096/);
      expect(compareResults(r, b).kind, name).toBe("agree");
    }
  });

  it("an empty token is refused the way the server refuses it: malformed on both sides", async () => {
    const e = new Engine(C);
    const r = e.verify({ token: "", identityId: "fid-001", service: "mcp" }); const b = await verifyInBrowser("", { issuers: e.snapshot().issuers, vertical: "finance" });
    expect(r.code).toBe("malformed_token"); expect(b.status).toBe("refused"); expect(b.reason).toMatch(/^Malformed token/);
    expect(compareResults(r, b).kind).toBe("agree");
  });

  it("exactly 4096 characters is within the cap on both sides (the browser checks it), 4097 is refused", async () => {
    const e = new Engine(C);
    const issuers = e.snapshot().issuers; const getJwks = async (id) => ({ ok: true, keys: e.jwksOf(id).keys });
    const h = b64(HDR);
    const sigLen = b64(Buffer.alloc(256)).length; // an RSA-2048 signature is always 256 bytes
    const exact = (n) => {
      for (let pad = 0; pad < 6000; pad++) for (let extra = 0; extra < 4; extra++) {
        const p = b64(payload(e, { pad: "x".repeat(pad), z: "y".repeat(extra) }));
        if (h.length + 1 + p.length + 1 + sigLen !== n) continue;
        return `${h}.${p}.${b64(crypto.sign("RSA-SHA256", Buffer.from(`${h}.${p}`), keyAt(ISSUER.kube.slot * 6).privateKey))}`;
      }
      throw new Error(`no token of ${n} characters`);
    };
    const at = exact(4096); const over = exact(4097);
    expect(at.length).toBe(4096); expect(over.length).toBe(4097);
    expect((await verifyInBrowser(at, { issuers, vertical: "finance", getJwks })).status).toBe("ok");
    expect(e.verify({ token: at, identityId: "fid-001", service: "mcp" }).code).not.toBe("malformed_token");
    const b = await verifyInBrowser(over, { issuers, vertical: "finance", getJwks });
    expect(b.status).toBe("refused"); expect(b.reason).toMatch(/longer than 4096/);
    expect(e.verify({ token: over, identityId: "fid-001", service: "mcp" }).code).toBe("malformed_token");
  });

  it("the Verify page counts the token's characters, says when it is over the limit, cuts nothing, and the browser check and the gateway agree on the long token", async () => {
    render(<App />); await screen.findByTestId("identities", {}, T);
    await userEvent.click(screen.getByTestId("mode-live")); await waitFor(() => expect(screen.getByTestId("revoke-fid-001")).toBeEnabled(), T);
    await userEvent.click(screen.getByRole("tab", { name: "Verify" }));
    await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    const long = tok(HDR, payload(new Engine(C), { big: "A".repeat(4200) }));
    expect(long.length).toBeGreaterThan(4096);
    fireEvent.change(screen.getByTestId("token"), { target: { value: long } });
    expect(screen.getByTestId("token").value).toBe(long); // nothing is cut
    expect(screen.getByTestId("token-length")).toHaveTextContent(new RegExp(`^${long.length} / 4096 characters: over the limit`));
    await userEvent.click(screen.getByTestId("verify"));
    await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("malformed_token"), T);
    await userEvent.click(screen.getByTestId("browser-check"));
    await waitFor(() => expect(screen.getByTestId("browser-status")).toBeInTheDocument(), T);
    expect(screen.getByTestId("browser-status").textContent).toBe("refused");
    expect(screen.getByTestId("agreement")).toBeInTheDocument(); expect(screen.queryByTestId("disagreement")).toBeNull();
    fireEvent.change(screen.getByTestId("token"), { target: { value: "a".repeat(4096) } });
    expect(screen.getByTestId("token-length")).toHaveTextContent(/^4096 \/ 4096 characters$/);
  }, 60000);
});

describe("the diagram tab recovers from a failed load (N6)", () => {
  it("an error belongs to the diagram that failed: choosing another clears it, the switcher stays, and Try again reloads", async () => {
    render(<App />); await screen.findByTestId("identities", {}, T);
    fail = (u) => u.includes("name=verification-steps");
    await userEvent.click(screen.getByRole("tab", { name: "Diagram" }));
    await waitFor(() => expect(screen.getByTestId("pattern-canvas")).toBeInTheDocument(), T);
    await userEvent.click(screen.getByTestId("dg-verification-steps"));
    await waitFor(() => expect(screen.getByTestId("diagram-error")).toHaveTextContent(/Could not load the diagram \(Failed to fetch\)/), T);
    expect(screen.getByTestId("dg-self-hosted-agent")).toBeInTheDocument(); // the switcher is still there
    await userEvent.click(screen.getByTestId("dg-self-hosted-agent"));
    await waitFor(() => expect(screen.queryByTestId("diagram-error")).toBeNull(), T);
    await waitFor(() => expect(screen.getByTestId("pattern-canvas")).toBeInTheDocument(), T);
    await userEvent.click(screen.getByTestId("dg-verification-steps"));
    await waitFor(() => expect(screen.getByTestId("diagram-error")).toBeInTheDocument(), T);
    fail = null;
    await userEvent.click(screen.getByTestId("diagram-retry"));
    await waitFor(() => expect(screen.queryByTestId("diagram-error")).toBeNull(), T);
    await waitFor(() => expect(screen.getByTestId("pattern-canvas")).toBeInTheDocument(), T);
    expect(screen.getByTestId("dg-verification-steps")).toHaveAttribute("aria-pressed", "true");
  }, 60000);
});

describe("the workspace id the page keeps is one the server accepts (N3)", () => {
  it("the page's rule agrees with the server's on a table of ids", () => {
    const ids = ["default", "w-0123456789abcdef", "a", "g".repeat(40), "g".repeat(41), "", "A", "a b", "a_b", "deadbeef".repeat(4), "0123456789abcdef01234567", "0123456789abcdef0123456",
      "sk-abcdefghijklmnop", "sk-short", "task-abcdefghijklmnop", "my-sk-abcdefghijklmnop", "glpat-abcdefghijkl", "glpat-abcdefghijk", "xoxb-12345678", "xoxb-1234567", "xoxp-abcdefgh", "visitor-12"];
    for (const id of ids) expect(validWorkspaceId(id), JSON.stringify(id)).toBe(serverValid(id));
    expect(validWorkspaceId(undefined)).toBe(false); expect(validWorkspaceId(5)).toBe(false);
  });

  it("a saved id the server would refuse is not used; this lab's own key (fid.) is used; nothing is kept under the old prefix", () => {
    window.sessionStorage.setItem("fid.workspace", "deadbeef".repeat(4));
    const id = workspaceId(); expect(id).toMatch(/^w-[0-9a-f]{16}$/); expect(window.sessionStorage.getItem("fid.workspace")).toBe(id);
    forgetWorkspace(); window.sessionStorage.setItem("fid.workspace", "sk-abcdefghijklmnop"); expect(workspaceId()).not.toBe("sk-abcdefghijklmnop");
    forgetWorkspace(); window.sessionStorage.setItem("fid.workspace", "my-saved-id"); expect(workspaceId()).toBe("my-saved-id");
    for (let i = 0; i < window.sessionStorage.length; i++) expect(window.sessionStorage.key(i)).not.toMatch(/^agl\./);
    forgetWorkspace(); window.sessionStorage.clear(); window.sessionStorage.setItem("agl.workspace", "old-id"); expect(workspaceId()).not.toBe("old-id");
  });

  it("a 400 bad_workspace makes a new id and asks once more; any other answer, and a second refusal, are returned as they are", async () => {
    const calls = [];
    const make = (answers) => { let i = 0; globalThis.fetch = async (u, init) => { calls.push(init.headers["x-workspace"]); return answers[Math.min(i++, answers.length - 1)](); }; };
    const refuse = () => new Response(JSON.stringify({ error: "bad_workspace" }), { status: 400, headers: { "content-type": "application/json" } });
    const ok = () => new Response("{}", { status: 200 });
    try {
      make([refuse, ok]);
      const first = workspaceId();
      const r = await workspaceFetch("/api/state", { method: "POST", body: "{}" });
      expect(r.status).toBe(200); expect(calls).toHaveLength(2); expect(calls[0]).toBe(first); expect(calls[1]).not.toBe(first);
      expect(window.sessionStorage.getItem("fid.workspace")).toBe(calls[1]);
      calls.length = 0; make([refuse, refuse, ok]);
      const r2 = await workspaceFetch("/api/state"); expect(r2.status).toBe(400); expect(calls).toHaveLength(2); // one retry, never a loop
      calls.length = 0; make([() => new Response(JSON.stringify({ error: "bad_mode" }), { status: 400 }), ok]);
      const r3 = await workspaceFetch("/api/state"); expect(r3.status).toBe(400); expect(calls).toHaveLength(1); // another 400 is not retried
      calls.length = 0; make([() => new Response("not json", { status: 400 }), ok]);
      expect((await workspaceFetch("/api/state")).status).toBe(400); expect(calls).toHaveLength(1);
    } finally { globalThis.fetch = async (u, init = {}) => realFetch(typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u, { ...init, headers: { origin: base, ...(init.headers || {}) } }); }
  });
});

describe("the diagram opens with every box in view at phone width (N4)", () => {
  it("the fitted view never restricts itself to the first boxes, and its zoom floor is low enough for the whole drawing", () => {
    for (const narrow of [true, false]) { expect(fitFor(narrow).nodes).toBeUndefined(); expect(fitFor(narrow).padding).toBeGreaterThan(0); }
    expect(fitFor(true).minZoom).toBe(MIN_ZOOM); expect(MIN_ZOOM).toBeLessThanOrEqual(0.15);
    expect(fitFor(true).maxZoom).toBeLessThanOrEqual(1);
  });
});
