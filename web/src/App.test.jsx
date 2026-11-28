// These tests drive the real UI against the real Express app (started on a loopback port inside the test), so a green run means the pieces
// actually work together: the real story data, the real engine, the real RS256 signing and verification, the real Mock table.
import http from "node:http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { VERTICALS } from "../../server/src/cast.js";
import { createRunLog } from "../../server/src/runObs.js";
import App, { MODE_LINES, TABS } from "./App";
import { labelOffsets } from "./components/PatternDiagram";
import { setJsonView } from "./components/JsonPane";
import { decodeToken, tamper } from "./token";
import { visible } from "./safeText";
import { forgetWorkspace } from "./workspace";

const C = VERTICALS.finance;
let server; let base; const realFetch = globalThis.fetch; let seen = []; let gate = () => null; let consumed = [];
beforeAll(async () => {
  const health = createHealth({ demoId: "federated-identity-lab", demoName: "Federated Identity LAB", version: "0.1.0", runChecks: () => [], allPassed: () => true, intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json", runLog: createRunLog({ write: () => {} }) }) }));
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
beforeEach(async () => { cleanup(); forgetWorkspace(); setJsonView("form"); seen = []; gate = () => null; consumed = []; try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; // rule 19: the server holds the mode, so every test starts from mock
  await realFetch(`${base}/api/mode`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ source: "mock" }) }); });

const T = { timeout: 20000 };
const mount = async () => { render(<App />); await screen.findByTestId("identities", {}, T); };
const tab = (name) => userEvent.click(screen.getByRole("link", { name })); // the shell-bar nav pills
const click = (id) => userEvent.click(screen.getByTestId(id));
const pickMode = (value) => userEvent.selectOptions(screen.getByTestId("mode-select"), value);
const live = async () => { await pickMode("real"); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live")); await waitFor(() => expect(screen.getByTestId("revoke-fid-001")).toBeEnabled(), T); };
const setValue = (id, value) => fireEvent.change(screen.getByTestId(id), { target: { value } });
const pick = (id, value) => userEvent.selectOptions(screen.getByTestId(id), value);
const wholePageText = () => { const c = document.body.cloneNode(true); c.querySelectorAll("textarea,input").forEach((n) => n.remove()); return c.textContent; };
// Verify tab, Live: load a preset, mint, verify, wait for the verdict.
const verifyPreset = async (id, { service, tamperIt = false } = {}) => {
  await tab("Verify");
  await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
  await pick("preset", id);
  if (service) await pick("service", service);
  await click("mint");
  await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T);
  if (tamperIt) await click("tamper");
  await waitFor(() => expect(screen.getByTestId("verify")).toBeEnabled(), T);
  await click("verify");
  await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T);
  return screen.getByTestId("verdict-code").textContent;
};

describe("shell", () => {
  it("opens on a MOCK modal that says simulated and UNVERIFIED (no banner); every tab still tags its claims, in presenter mode too", async () => {
    await mount();
    const modal = screen.getByTestId("mode-modal");
    expect(modal).toHaveAttribute("data-mode", "mock");
    expect(modal).toHaveTextContent("MOCK");
    expect(modal).toHaveTextContent(/Simulated/); expect(modal).toHaveTextContent(/UNVERIFIED on our tenant/); expect(modal).toHaveTextContent(/release 2026-11-02/);
    expect(modal.textContent).toContain(MODE_LINES.mock);
    expect(screen.queryByTestId("banner")).toBeNull(); expect(document.querySelector(".banner")).toBeNull();
    expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock");
    await click("mode-modal-ok");
    expect(screen.queryByTestId("mode-modal")).toBeNull();
    for (const t of TABS) {
      await tab(t.label);
      expect((await screen.findAllByTestId("claim-tag", {}, T)).length).toBeGreaterThan(0);
    }
    await tab("Federated Identity");
    await userEvent.keyboard("p");
    expect(screen.getByTestId("presenter-say")).toBeInTheDocument();
    expect(screen.getByTestId("presenter")).toHaveTextContent("Exit present");
    for (const t of TABS.filter((x) => x.id !== "talk")) { await tab(t.label); expect(screen.getByTestId("presenter-say")).toBeInTheDocument(); expect((await screen.findAllByTestId("claim-tag", {}, T)).length).toBeGreaterThan(0); }
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByTestId("presenter-say")).toBeNull();
    expect(MODE_LINES.mock).toMatch(/UNVERIFIED/); expect(MODE_LINES.real).toMatch(/UNVERIFIED/); expect(MODE_LINES.unknown).toMatch(/UNVERIFIED/);
  });

  it("the modal line before the mode is known is honest in both modes: the engine is local, the gateway check is Real only and goes out only when configured", () => {
    expect(MODE_LINES.unknown).toMatch(/engine is loopback only/);
    expect(MODE_LINES.unknown).toMatch(/Privilege gateway check goes out only in Real mode, and only when run with a gateway configured/);
    expect(MODE_LINES.unknown).not.toMatch(/no outbound network|Nothing here calls|touching no/i);
    expect(MODE_LINES.real).toMatch(/real RS256 signing and verification on your tokens, loopback only/);
    expect(MODE_LINES.real).toMatch(/only the Privilege gateway check goes out, and only when run with a gateway configured/);
    expect(MODE_LINES.mock).not.toMatch(/goes out/);
  });

  it("until /api/info answers the modal says MOCK with the unknown-mode line; then it follows the server: MOCK stays, a Live server shows REAL", async () => {
    let release; const held = new Promise((r) => { release = r; });
    gate = (u) => (u.endsWith("/api/info") ? held : null);
    render(<App />);
    const first = await screen.findByTestId("mode-modal");
    expect(first).toHaveAttribute("data-mode", "mock"); expect(first.textContent).toContain(MODE_LINES.unknown);
    release();
    await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock"), T);
    expect(screen.getByTestId("mode-modal").textContent).toContain(MODE_LINES.mock);
    cleanup(); gate = () => null; await mount();
    await pickMode("real"); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live"));
    cleanup(); sessionStorage.clear();
    let release2; const held2 = new Promise((r) => { release2 = r; });
    gate = (u) => (u.endsWith("/api/info") ? held2 : null);
    render(<App />);
    expect((await screen.findByTestId("mode-modal"))).toHaveAttribute("data-mode", "mock");
    release2();
    await waitFor(() => expect(screen.getByTestId("mode-modal")).toHaveAttribute("data-mode", "real"), T);
    expect(screen.getByTestId("mode-modal").textContent).toContain(MODE_LINES.real);
    expect(screen.getByTestId("mode-modal")).toHaveTextContent("REAL");
  });

  it("the modal and the mode chip follow the toggle, in both directions, on every tab; Got it keeps the mode's modal closed for the session", async () => {
    await mount();
    for (const t of TABS) {
      await tab(t.label);
      await pickMode("real"); await waitFor(() => expect(screen.getByTestId("mode-modal")).toHaveAttribute("data-mode", "real")); expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live");
      await pickMode("mock"); await waitFor(() => expect(screen.getByTestId("mode-modal")).toHaveAttribute("data-mode", "mock")); expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock");
    }
    await click("mode-modal-ok");
    await pickMode("real"); await waitFor(() => expect(screen.getByTestId("mode-modal")).toHaveAttribute("data-mode", "real"));
    await click("mode-modal-ok");
    await pickMode("mock"); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock"));
    expect(screen.queryByTestId("mode-modal")).toBeNull();
  });

  it("rule 19: the mode is server-backed — each switch POSTs /api/mode with exactly {source}, the mode survives a reload, and storage is not needed", async () => {
    await mount();
    seen.length = 0;
    await pickMode("real");
    expect(seen.some((r) => r.url.endsWith("/api/mode") && r.body === JSON.stringify({ source: "real" }))).toBe(true);
    cleanup(); render(<App />); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live"), T);
    expect(window.localStorage.getItem("fid.mode")).toBeNull();
    // a bad body is refused 400
    const r = await fetch(`${base}/api/mode`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ source: "live" }) });
    expect(r.status).toBe(400);
    expect((await r.json()).error).toBe("bad_mode");
    // a blocked storage never breaks the page: the server holds the mode
    cleanup(); const desc = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", { configurable: true, get() { throw new Error("blocked"); } });
    try { render(<App />); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live"), T); await pickMode("mock"); await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock"), T); }
    finally { Object.defineProperty(window, "localStorage", desc); }
  });

  it("shell bar first, then main with no banner; the nav pills mark the current section and the URL hash follows; talks only to its own origin", async () => {
    await mount();
    const bar = document.querySelector("header.shell-bar");
    expect(bar).not.toBeNull(); expect(document.querySelectorAll("header")).toHaveLength(1);
    expect(bar.nextElementSibling).toBe(document.querySelector("main"));
    expect(screen.queryByTestId("banner")).toBeNull();
    expect(bar.querySelector(".shell-brand h1")).toHaveTextContent("Federated Identity LAB"); expect(document.querySelectorAll("h1")).toHaveLength(1);
    expect(bar.querySelector(".shell-brand [data-testid=mode]")).toHaveTextContent("Mode: mock");
    expect(bar.querySelector(".shell-right[data-testid=top-menu]")).not.toBeNull();
    expect(within(bar.querySelector("nav.shell-nav")).getAllByRole("link").map((a) => a.textContent)).toEqual(TABS.map((t) => t.label));
    expect(screen.getByRole("link", { name: "Federated Identity" })).toHaveAttribute("aria-current", "page");
    await tab("Verify");
    expect(screen.getByRole("link", { name: "Verify" })).toHaveAttribute("aria-current", "page"); expect(window.location.hash).toBe("#verify");
    expect(screen.getByRole("link", { name: "Federated Identity" })).not.toHaveAttribute("aria-current");
    window.location.hash = "#talk"; window.dispatchEvent(new HashChangeEvent("hashchange"));
    await waitFor(() => expect(screen.getByRole("link", { name: "Talk track" })).toHaveAttribute("aria-current", "page"));
    await tab("Diagram");
    for (const s of seen) expect(s.url.startsWith(base) || s.url.startsWith("/")).toBe(true);
  });
});

describe("Federated Identity tab", () => {
  it("names the renaming (Federated Identity, API still NonHumanIdentity, slide 57), the measured MCP nuance and the five identities", async () => {
    await mount();
    expect(screen.getByTestId("naming-note")).toHaveTextContent(/still.*NonHumanIdentity/); expect(screen.getByTestId("naming-note")).toHaveTextContent(/Slide 57/);
    expect(screen.getByTestId("mcp-note")).toHaveTextContent(/did not prove it/); expect(screen.getByTestId("mcp-note")).toHaveTextContent(/measured, our note/);
    for (const id of ["fid-001", "fid-002", "fid-003", "fid-004", "fid-005"]) expect(screen.getByTestId(`identity-${id}`)).toBeInTheDocument();
    expect(screen.getByTestId("identity-fid-002")).toHaveTextContent(`${C.castOrg}/${C.castRepo}`); expect(screen.getByTestId("identity-fid-002")).toHaveTextContent(/environment=production/);
    expect(screen.getByTestId("identity-fid-005")).toHaveTextContent(/pinned/);
    expect(screen.getAllByTestId("source-tag").length).toBeGreaterThan(3);
  });

  it("every write control is off in Mock, with a note", async () => {
    await mount();
    expect(screen.getByTestId("read-only-note")).toHaveTextContent(/Mock only reads tables/);
    for (const id of ["revoke-fid-001", "edit-fid-001", "remove-fid-001", "key-toggle-key-0001"]) expect(screen.getByTestId(id)).toBeDisabled();
  });

  it("create an identity (audience and subject are required by the engine), see it listed, edit its lifetime cap, revoke and remove it", async () => {
    await mount(); await live();
    setValue("i-name", "my new identity"); setValue("i-subject", "system:serviceaccount:x:y"); setValue("i-audience", "");
    await click("identity-add");
    await waitFor(() => expect(screen.getAllByTestId("outcome")[0]).toHaveTextContent(/audience_required/), T);
    setValue("i-audience", "https://gateway.example.example"); await click("identity-add");
    await waitFor(() => expect(screen.getByTestId("identity-fid-006")).toBeInTheDocument(), T);
    await click("edit-fid-006"); await screen.findByTestId("identity-edit", {}, T);
    setValue("i-cap", "600"); await click("identity-save");
    await waitFor(() => expect(screen.getByTestId("identity-fid-006")).toHaveTextContent(/600 s/), T);
    await click("revoke-fid-006"); await waitFor(() => expect(screen.getByTestId("identity-fid-006")).toHaveTextContent(/disabled/), T);
    await click("restore-fid-006"); await waitFor(() => expect(screen.getByTestId("identity-fid-006")).toHaveTextContent(/enabled/), T);
    await click("remove-fid-006"); await waitFor(() => expect(screen.queryByTestId("identity-fid-006")).toBeNull(), T);
  });

  it("a key owned by an identity versus a person: the two measured refusals, and the stored key stops when the person is inactive", async () => {
    await mount(); await live();
    expect(screen.getByTestId("principal-key-0001")).toHaveTextContent(/^identity /); expect(screen.getByTestId("principal-key-0006")).toHaveTextContent(new RegExp(`person ${C.castOwner} \\(borrowed\\)`));
    await click("key-both-federation");
    await waitFor(() => expect(screen.getAllByTestId("outcome").at(-1)).toHaveTextContent(/mutually_exclusive/), T);
    await click("key-both-person");
    await waitFor(() => expect(screen.getAllByTestId("outcome").at(-1)).toHaveTextContent(/principal_conflict/), T);
    await click("stored-key-0006-mcp"); await waitFor(() => expect(screen.getByTestId("stored-result")).toHaveTextContent(/ledger-mcp|ledger\.mcp/), T);
    await click(`person-${C.castOwner}`);
    await waitFor(() => expect(screen.getByTestId(`person-${C.castOwner}`)).toHaveTextContent(/inactive/), T);
    await click("stored-key-0006-mcp");
    await waitFor(() => expect(screen.getAllByTestId("outcome").at(-1)).toHaveTextContent(/owner_inactive/), T);
  });
});

describe("Verify: Mock scenarios, read-only", () => {
  it("shows a scripted scenario with its steps; the fork-PR scenario ends in subject_mismatch and shows all fifteen steps", async () => {
    await mount(); await tab("Verify");
    expect(await screen.findByTestId("scenarios", {}, T)).toBeInTheDocument();
    expect((await within(screen.getByTestId("scenarios")).findAllByRole("option")).length).toBe(15);
    expect(screen.queryByTestId("editor")).toBeNull();
    await pick("scenario-pick", "fork-pr");
    await waitFor(() => expect(screen.getByTestId("scenario-say")).toHaveTextContent(/pull request/), T);
    expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/subject_mismatch/);
    expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/required_claim_mismatch/);
    expect(within(screen.getAllByText("The fifteen steps")[1].closest("details")).getAllByTestId(/^step-/).length).toBe(15);
  });
});

describe("Verify: What Privilege did (Rule 25 gateway trace)", () => {
  it("Mock: every scripted verify step shows its request, response and fifteen checked decisions; the panel says the gateway is simulated", async () => {
    await mount(); await tab("Verify");
    const panel = await screen.findByTestId("gateway-trace", {}, T);
    expect(screen.getByTestId("gateway-trace-basis")).toHaveTextContent(/on this tab the lab never contacts a real Privilege gateway \(only the separate Real-mode gateway check does\)/);
    const first = within(panel).getByTestId("trace-1");
    expect(within(within(panel).getByTestId("trace-1-decisions")).getAllByRole("listitem").length).toBe(15);
    expect(first).toHaveTextContent(/POST https:\/\/gateway\.fabrikam\.example\/mcp/);
    expect(first).toHaveTextContent(/HTTP 200/);
    expect(panel).not.toHaveTextContent(/inferred from the outcome|observed in the response/);
    await pick("scenario-pick", "fork-pr");
    await waitFor(() => expect(screen.getByTestId("scenario-say")).toHaveTextContent(/pull request/), T);
    await waitFor(() => expect(within(screen.getByTestId("gateway-trace")).getAllByText(/refused at:/).length).toBeGreaterThan(0), T);
  });

  it("Live: Verify adds the panel under the verdict; a refusal shows the failing decision; the token text is not in it", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    const ok = screen.getByTestId("gateway-trace");
    expect(within(screen.getByTestId("trace-1-decisions")).getAllByRole("listitem").length).toBe(15);
    expect(ok).toHaveTextContent(/all 15 decisions passed/);
    const token = screen.getByTestId("token").value;
    expect(ok).toHaveTextContent(`Bearer <token, ${token.length} characters, kept on the server>`);
    expect(ok.textContent).not.toContain(token.split(".")[2]);
    expect(await verifyPreset("k8s-right", { tamperIt: true })).not.toBe("allowed");
    await waitFor(() => expect(within(screen.getByTestId("gateway-trace")).getByText(/refused at:/)).toBeInTheDocument(), T);
  });

  // A stub Privilege gateway on loopback plus the settings that point the lab's Real hop at it. run(KEY) gets the fake key the gateway echoes.
  const withRealGateway = async (run) => {
    const KEY = ["fake", "agent", "key"].join("-") + "Q".repeat(24);
    const gw = http.createServer((req, res) => {
      let raw = ""; req.on("data", (c) => { raw += c; });
      req.on("end", () => {
        if (req.method !== "POST") { res.writeHead(200).end(); return; }
        const m = JSON.parse(raw || "{}");
        const send = (status, body, headers = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body)); };
        if (m.method === "initialize") return send(200, { jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "stub-door" } } }, { "mcp-session-id": "sess-1234567890abcdef" });
        if (m.method === "notifications/initialized") { res.writeHead(202).end(); return; }
        if (m.method === "tools/list") return send(200, { jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "lookup", description: `echoes ${KEY}` }] } });
        return send(403, { error: "refused by policy" });
      });
    });
    await new Promise((r) => gw.listen(0, "127.0.0.1", r));
    const keep = ["FID_GW_URL", "FID_GW_APPS", "FID_GW_KEY_LAB", "STANDALONE_ENV"].map((k) => [k, process.env[k]]);
    Object.assign(process.env, { FID_GW_URL: `http://127.0.0.1:${gw.address().port}`, FID_GW_APPS: "door-a", FID_GW_KEY_LAB: KEY, STANDALONE_ENV: "/nonexistent/standalone.env" });
    // The server hop runs in this jsdom process, whose AbortSignal is not the one node's fetch accepts: the hop's timeout signal is dropped here only.
    const patched = globalThis.fetch;
    globalThis.fetch = (u, init) => patched(u, init?.signal ? { ...init, signal: undefined } : init);
    try {
      await run(KEY);
    } finally {
      globalThis.fetch = patched;
      for (const [k, v] of keep) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      await new Promise((r) => gw.close(r));
    }
  };
  const gatewayChecks = () => seen.filter((s) => s.url.endsWith("/api/gateway-check")).length;

  it("Real: the gateway card and \"Show what Privilege did\" appear only in Real; the panel is source real, shows observed or inferred decisions, never checked, and no key", () => withRealGateway(async (KEY) => {
    await mount();
    expect(screen.queryByTestId("privilege-check")).toBeNull();
    expect(screen.queryByTestId("gateway-check-trace")).toBeNull();
    await live();
    expect(screen.getByTestId("privilege-check")).toBeInTheDocument();
    // The trace is drawn from the card's own result, so the button is ready only once the card has finished its check.
    await waitFor(() => expect(screen.getByTestId("gateway-check-trace-run")).toBeEnabled(), T);
    await click("gateway-check-trace-run");
    const panel = await within(await screen.findByTestId("gateway-check-trace", {}, T)).findByTestId("gateway-trace", {}, T);
    expect(panel).toHaveTextContent(/tools\/list/);
    expect(panel).toHaveTextContent(/Refusal probe/);
    expect(panel).toHaveTextContent(/inferred from the outcome/);
    expect(panel).not.toHaveTextContent(/checked/i);
    expect(document.body.textContent).not.toContain(KEY);
  }));

  it("Real: the card's check runs once and showing the trace makes no further gateway call (the trace is the card's own result)", () => withRealGateway(async () => {
    await mount(); await live();
    await screen.findByText(/1 tools in \d+ ms/, {}, T); // the card finished its one check
    expect(gatewayChecks()).toBe(1);
    await waitFor(() => expect(screen.getByTestId("gateway-check-trace-run")).toBeEnabled(), T);
    await click("gateway-check-trace-run");
    const panel = await within(await screen.findByTestId("gateway-check-trace", {}, T)).findByTestId("gateway-trace", {}, T);
    expect(panel).toHaveTextContent(/tools\/list/);
    expect(panel).toHaveTextContent(/Refusal probe/);
    expect(gatewayChecks()).toBe(1);
  }));

  // Rule 27: "What each layer logged for this run". Mock: the scripted scenario on the Verify tab. Real: the run the gateway card's check made.
  const gateOn = (re) => { let open; const p = new Promise((r) => { open = r; }); gate = (u) => (re.test(u) ? p : null); return open; };
  const recordCalls = () => seen.filter((x) => /\/api\/run-observability\?runId=gw-/.test(x.url)).map((x) => x.url);

  it("Rule 27 Mock: the Verify tab shows the scripted scenario's rows (simulated, numbered by step); another scenario shows loading, never the previous record, until its own arrives; no other tab shows the panel", async () => {
    await mount(); await tab("Verify");
    const panel = await screen.findByTestId("run-observability", {}, T);
    expect(within(panel).getByTestId("ro-basis")).toHaveTextContent(/Simulated/);
    expect(within(panel).getByTestId("ro-coverage-gateway")).toHaveAttribute("data-coverage", "simulated");
    expect(within(panel).getByTestId("ro-coverage-resource")).toHaveAttribute("data-coverage", "not-logged");
    expect(panel).toHaveTextContent(/Step 4: The lab's simulated gateway turned away the workload token for llm/);
    const open = gateOn(/run-observability\?vertical=finance&scenario=fork-pr/);
    await pick("scenario-pick", "fork-pr");
    await waitFor(() => expect(screen.getByTestId("scenario-say")).toHaveTextContent(/pull request/), T);
    await waitFor(() => expect(screen.getByTestId("ro-loading")).toBeInTheDocument(), T);
    expect(screen.queryByTestId("run-observability")).toBeNull();
    open();
    const next = await screen.findByTestId("run-observability", {}, T);
    expect(next).toHaveTextContent(/check 12 of 15/);
    expect(next).not.toHaveTextContent(/for llm/);
    await tab("Audit");
    expect(screen.queryByTestId("run-observability")).toBeNull(); expect(screen.queryByTestId("ro-loading")).toBeNull();
  });

  it("Rule 27 Real: the panel sits under the gateway card, asks for the run that card's check made, shows the gateway's replies as response rows and no key; a second check shows loading, never the first run; Mock never shows a Real run", () => withRealGateway(async (KEY) => {
    await mount(); await live();
    const panel = await screen.findByTestId("run-observability", {}, T);
    expect(within(panel).getByTestId("ro-basis")).toHaveTextContent(/Real:/);
    expect(within(panel).getByTestId("ro-coverage-gateway")).toHaveAttribute("data-coverage", "response");
    expect(within(panel).getByTestId("ro-coverage-person")).toHaveAttribute("data-coverage", "not-logged");
    expect(panel).toHaveTextContent(/The gateway answered tools\/list with 1 tools for the agent key/);
    expect(panel).toHaveTextContent(/HTTP 403 while the lab was opening or making the refusal probe/);
    expect(screen.getByTestId("privilege-check").compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(recordCalls()).toHaveLength(1);
    const first = recordCalls()[0];
    // the next check: while its call is in flight the first run is not shown and nothing is asked; then the panel waits for the new run's own record
    let openCheck; let openRecord;
    const pCheck = new Promise((r) => { openCheck = r; }); const pRecord = new Promise((r) => { openRecord = r; });
    gate = (u) => (/\/api\/gateway-check/.test(u) ? pCheck : /run-observability\?runId=/.test(u) ? pRecord : null);
    await userEvent.click(screen.getByRole("button", { name: "Run the gateway check" }));
    await waitFor(() => expect(screen.getByTestId("ro-loading")).toBeInTheDocument(), T);
    expect(screen.queryByTestId("run-observability")).toBeNull();
    expect(recordCalls()).toHaveLength(1);
    openCheck();
    await waitFor(() => expect(recordCalls()).toHaveLength(2), T);
    expect(recordCalls()[1]).not.toBe(first);
    expect(screen.queryByTestId("run-observability")).toBeNull();
    const open = openRecord;
    gate = () => null;
    open();
    await screen.findByTestId("run-observability", {}, T);
    // Mock: no Real run on the page, and back in Real the panel waits for the new check's own run
    await pickMode("mock");
    await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock"), T);
    expect(screen.queryByTestId("run-observability")).toBeNull(); expect(screen.queryByTestId("ro-loading")).toBeNull();
    await live();
    await screen.findByTestId("run-observability", {}, T);
    expect(new Set(recordCalls()).size).toBe(3);
    expect(document.body.textContent).not.toContain(KEY);
  }));

  it("Rule 27 Real: with no gateway configured the check makes no run, so the panel says so and shows nothing older", async () => {
    const keep = process.env.STANDALONE_ENV; process.env.STANDALONE_ENV = "/nonexistent/standalone.env";
    try {
      await mount(); await live();
      const note = await screen.findByTestId("ro-no-run", {}, T);
      expect(note).toHaveTextContent(/did not complete, so there is no run to show \(and no older one is shown in its place\)/);
      expect(within(note).getByRole("alert")).toBeInTheDocument();
      expect(screen.queryByTestId("run-observability")).toBeNull(); expect(recordCalls()).toHaveLength(0);
    } finally { if (keep === undefined) delete process.env.STANDALONE_ENV; else process.env.STANDALONE_ENV = keep; }
  });
});

describe("Verify: the real engine in Live", () => {
  it("mint -> verify: the right token is allowed; fifteen steps pass; the backend gets a masked credential and not the token; the deployment is named", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    expect(screen.getByTestId("verdict")).toHaveAttribute("data-state", "ok");
    expect(within(screen.getByTestId("steps")).getAllByText("pass").length).toBe(15);
    expect(screen.getByTestId("forwarded-flag")).toHaveTextContent("false");
    expect(screen.getByTestId("forwarded")).toHaveTextContent(/\[masked: /);
    expect(screen.getByTestId("forwarded")).not.toHaveTextContent(screen.getByTestId("token").value.slice(0, 40));
    expect(screen.getByTestId("deployment")).toHaveTextContent(`${C.castNs}/${C.castAgent}`);
    expect(screen.getByTestId("decoded-times")).toHaveTextContent(/lifetime \(exp minus iat\) 3600 s/);
    expect(screen.getByTestId("mint-label")).toHaveTextContent(/lab-minted token/);
  });

  it("the JSON panes are the shared JsonPane: a Form | JSON toggle, one choice for every pane, the JSON text in the JSON view", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    const box = screen.getByTestId("forwarded-box");
    expect(within(box).getAllByRole("button").map((b) => b.textContent)).toEqual(["Form", "JSON"]);
    expect(box).toHaveAttribute("data-view", "form");
    expect(screen.getByTestId("forwarded").tagName).toBe("DIV");
    await userEvent.click(within(box).getByRole("button", { name: "JSON" }));
    expect(box).toHaveAttribute("data-view", "raw");
    const pre = screen.getByTestId("forwarded");
    expect(pre.tagName).toBe("PRE");
    expect(pre).toHaveTextContent(/"authorization"/);
    expect(pre).toHaveTextContent(/\[masked: /);
    const groups = screen.getAllByRole("group", { name: /view$/ }); expect(groups.length).toBeGreaterThan(1);
    for (const g of groups) expect(within(g).getByRole("button", { name: "JSON" })).toHaveAttribute("aria-pressed", "true");
  });

  it("the same identity reaches a peer agent, and the LLM provider is refused because the scope is not on the key (403)", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right", { service: "a2a" })).toBe("allowed");
    await pick("service", "llm"); await click("verify");
    await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("scope_not_on_key"), T);
    expect(screen.getByTestId("verdict")).toHaveTextContent(/403 Forbidden/); expect(screen.getByTestId("step-scope")).toHaveTextContent(/fail/); expect(screen.getByTestId("verdict")).toHaveTextContent(/key not scoped for llm access/);
  });

  it("a pull request from a fork is refused at the subject step; the other steps before it passed and the ones after were never reached", async () => {
    await mount(); await live();
    expect(await verifyPreset("gh-fork-pr")).toBe("subject_mismatch");
    expect(screen.getByTestId("step-subject")).toHaveTextContent("fail"); expect(screen.getByTestId("step-claims")).toHaveTextContent("not reached"); expect(screen.getByTestId("step-signature")).toHaveTextContent("pass");
    expect(screen.queryByTestId("allowed-detail")).toBeNull();
  });

  it("a tampered token is refused at the signature; alg none and HS256 are refused before any key; an attacker's key under the issuer's kid fails", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right", { tamperIt: true })).toBe("bad_signature");
    expect(screen.getByTestId("step-signature")).toHaveTextContent("fail");
    expect(await verifyPreset("alg-none")).toBe("alg_none");
    expect(await verifyPreset("alg-hs256")).toBe("alg_symmetric");
    expect(await verifyPreset("attacker-forged-kid")).toBe("bad_signature");
  });

  it("lifetimes: expired, minted to live two hours, no expiry and a future iat are each refused with their own reason", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-expired")).toBe("expired");
    expect(await verifyPreset("k8s-long-lived")).toBe("lifetime_exceeds_cap");
    expect(screen.getByTestId("step-expiry")).toHaveTextContent("pass");
    expect(await verifyPreset("k8s-no-exp")).toBe("exp_missing");
    expect(await verifyPreset("k8s-future-iat")).toBe("iat_in_future");
  });

  it("editing a claim by hand: a typed subject changes the result; an omitted audience is refused", async () => {
    await mount(); await live(); await tab("Verify");
    await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    setValue("f-sub", `${C.castAgent}-other`); await click("mint"); await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T);
    expect(decodeToken(screen.getByTestId("token").value).payload.sub).toBe(`${C.castAgent}-other`);
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("subject_mismatch"), T);
    setValue("f-sub", `system:serviceaccount:${C.castNs}:${C.castAgent}`); setValue("f-aud", ""); await click("mint");
    await waitFor(() => expect(decodeToken(screen.getByTestId("token").value).payload.aud).toBeUndefined(), T);
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("aud_missing"), T);
  });

  it("the gateway can find the identity by issuer and subject when none is named; a made-up one is refused", async () => {
    await mount(); await live(); await tab("Verify");
    await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    await pick("identity-under-test", ""); await click("mint"); await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T);
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("allowed"), T);
    expect(screen.getByTestId("result")).toHaveTextContent(/fid-001|agent-runner/);
    setValue("f-sub", "nobody"); await click("mint"); await waitFor(() => expect(decodeToken(screen.getByTestId("token").value).payload.sub).toBe("nobody"), T);
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("no_matching_identity"), T);
  });

  it("text that is not a token decodes to nothing and is refused at parse", async () => {
    await mount(); await live(); await tab("Verify");
    await waitFor(() => expect(screen.getByTestId("verify")).toBeDisabled(), T);
    setValue("token", "not a token"); expect(screen.getByTestId("not-decodable")).toBeInTheDocument();
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("malformed_token"), T);
    expect(screen.getByTestId("step-parse")).toHaveTextContent("fail");
  });

  it("the browser helpers: decode and tamper agree with the server's view of a token", () => {
    const t = `${btoa(JSON.stringify({ alg: "RS256" })).replace(/=+$/, "")}.${btoa(JSON.stringify({ sub: "a" })).replace(/=+$/, "")}.sig`;
    expect(decodeToken(t).payload.sub).toBe("a"); expect(decodeToken(tamper(t)).payload.sub).toBe("ax"); expect(tamper(t).split(".")[2]).toBe("sig"); expect(decodeToken("x.y")).toBeNull(); expect(tamper("junk")).toBe("junk");
  });
});

describe("Issuers and keys", () => {
  it("rotating the issuer makes the next token carry an unknown kid; the gateway refreshes on sight of it and the token verifies", async () => {
    await mount(); await live(); await tab("Issuers and keys");
    await waitFor(() => expect(screen.getByTestId("rotate-kube")).toBeEnabled(), T);
    expect(screen.getByTestId("held-fid-001")).toHaveTextContent("kube-key-1");
    await click("rotate-kube"); await waitFor(() => expect(screen.getByTestId("kid-kube")).toHaveTextContent("kube-key-2"), T);
    expect(screen.getByTestId("held-fid-001")).toHaveTextContent("kube-key-1");
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    expect(screen.getByTestId("refresh-note")).toHaveTextContent(/refreshed on an unknown kid: the issuer answered/);
    await tab("Issuers and keys"); await waitFor(() => expect(screen.getByTestId("held-fid-001")).toHaveTextContent("kube-key-2"), T);
  });

  it("issuer outage: the last known good key set still verifies; an unknown kid cannot be resolved; bringing it back resolves it", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    const old = screen.getByTestId("token").value;
    await tab("Issuers and keys"); await click("down-kube"); await waitFor(() => expect(screen.getByTestId("up-kube")).toBeInTheDocument(), T);
    await click("rotate-kube"); await waitFor(() => expect(screen.getByTestId("kid-kube")).toHaveTextContent("kube-key-2"), T);
    await tab("Verify"); setValue("token", old); await click("verify");
    await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("allowed"), T);
    expect(await verifyPreset("k8s-right")).toBe("unknown_kid");
    expect(screen.getByTestId("refresh-note")).toHaveTextContent(/did not answer, the last known good set was kept/);
    await tab("Issuers and keys"); await click("up-kube"); await waitFor(() => expect(screen.getByTestId("down-kube")).toBeInTheDocument(), T);
    await click("advance-1"); await waitFor(() => expect(screen.getByTestId("clock-now")).toHaveTextContent(/09:01:00 UTC/), T); // the unknown-kid refresh cooldown is one lab minute
    expect(await verifyPreset("k8s-right")).toBe("allowed");
  });

  it("the lab clock moves forward in capped steps: a token expires, and the key set refreshes every fifteen minutes", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    await tab("Issuers and keys"); await waitFor(() => expect(screen.getByTestId("advance-60")).toBeEnabled(), T);
    await click("advance-15"); await waitFor(() => expect(screen.getByTestId("clock-now")).toHaveTextContent(/09:15:00 UTC/), T);
    expect(screen.getByTestId("keyset-fid-001")).toHaveTextContent(/scheduled \(every 15 lab minutes\)/);
    await click("advance-60"); await waitFor(() => expect(screen.getByTestId("clock-now")).toHaveTextContent(/10:15:00 UTC/), T);
    await tab("Verify"); await click("verify");
    await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("expired"), T);
  });

  it("a pinned private issuer: after it rotates, the pinned set has no such key; pinning again fixes it", async () => {
    await mount(); await live();
    expect(await verifyPreset("private-right")).toBe("allowed");
    await tab("Issuers and keys"); await click("rotate-private"); await waitFor(() => expect(screen.getByTestId("kid-private")).toHaveTextContent("private-key-2"), T);
    expect(await verifyPreset("private-right")).toBe("unknown_kid");
    expect(screen.getByTestId("step-keyset")).toHaveTextContent(/pins its keys/);
    await tab("Issuers and keys"); await click("repin-fid-005"); await waitFor(() => expect(screen.getByTestId("held-fid-005")).toHaveTextContent("private-key-2"), T);
    await tab("Verify"); await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("allowed"), T);
  });
});

describe("revocation and audit", () => {
  it("revoke the identity, and the very next request is refused; the audit log says why and names the deployment of the earlier request", async () => {
    await mount(); await live();
    expect(await verifyPreset("k8s-right")).toBe("allowed");
    await tab("Audit");
    await waitFor(() => expect(screen.getByTestId("audit-revoke-fid-001")).toBeEnabled(), T);
    await click("audit-revoke-fid-001");
    await waitFor(() => expect(screen.getByTestId("audit-restore-fid-001")).toBeInTheDocument(), T);
    await tab("Verify"); await click("verify");
    await waitFor(() => expect(screen.getByTestId("verdict-code")).toHaveTextContent("identity_disabled"), T);
    await tab("Audit");
    expect(screen.getByTestId("by-deployment")).toHaveTextContent(`${C.castNs}/${C.castAgent}`);
    const rows = screen.getAllByTestId("audit-row").map((r) => r.textContent);
    expect(rows.some((r) => /verify/.test(r) && /refused/.test(r) && /identity_disabled/.test(r))).toBe(true);
    expect(rows.some((r) => /identity\.revoked/.test(r))).toBe(true);
    await pick("audit-outcome", "refused"); expect(screen.getAllByTestId("audit-row").every((r) => /refused/.test(r.textContent))).toBe(true);
    expect(screen.getByTestId("audit-count")).toHaveTextContent(/three rings/); expect(screen.getByTestId("audit-count")).toHaveTextContent(/0 changes, 0 allowed requests, 0 refusals dropped so far/);
  });
});

describe("Deployment models", () => {
  it("shows the five models; sidecar injection is in development with no behaviour claimed; Try opens Verify with that preset", async () => {
    await mount(); await tab("Deployment models");
    for (const id of ["direct-read", "per-job", "spiffe", "stored-key", "sidecar"]) expect(screen.getByTestId(`model-${id}`)).toBeInTheDocument();
    expect(screen.getByTestId("model-sidecar")).toHaveTextContent(/in development/); expect(screen.getByTestId("model-sidecar")).toHaveTextContent(/No behaviour is claimed/);
    expect(screen.getByTestId("token-pass-note")).toHaveTextContent(/never forwarded/);
    await click("try-per-job");
    await waitFor(() => expect(screen.getByRole("link", { name: "Verify" })).toHaveAttribute("aria-current", "page"), T);
    await waitFor(() => expect(screen.getByTestId("scenarios")).toBeInTheDocument(), T);
    await pickMode("real"); await waitFor(() => expect(screen.getByTestId("preset")).toBeInTheDocument(), T);
  });
});

describe("Self-Hosted Agents", () => {
  const enrol = async () => { await tab("Self-Hosted Agents"); await waitFor(() => expect(screen.getByTestId("enrol")).toBeEnabled(), T); await click("enrol"); await waitFor(() => expect(screen.getByTestId("sensor-fid-006")).toBeInTheDocument(), T); };
  const send = async () => { await waitFor(() => expect(screen.getByTestId("r-send")).toBeEnabled(), T); await click("r-send"); await waitFor(() => expect(screen.getByTestId("report-result")).toBeInTheDocument(), T); };

  it("enrol: a generated audience; a report with the sensor's own token is accepted; the node comes from the token and the body's forged node is ignored", async () => {
    await mount(); await live(); await enrol();
    expect(screen.getByTestId("audience-fid-006")).toHaveTextContent(/^priv-nhi-[0-9a-f]{16}$/);
    setValue("r-forged", C.castNode3); await send();
    expect(screen.getByTestId("verdict-code")).toHaveTextContent("allowed");
    expect(screen.getByTestId("report-node")).toHaveTextContent(C.castNode1);
    expect(screen.getByTestId("body-node-ignored")).toHaveTextContent(new RegExp(`${C.castNode3}.*ignored.*differed`));
    await waitFor(() => expect(screen.getByTestId("findings")).toHaveTextContent(C.castNode1), T);
    expect(screen.getByTestId("findings")).not.toHaveTextContent(C.castNode3);
  });

  it("a token minted for another audience is refused; revoking the identity cuts the sensor off while its findings stay attributed", async () => {
    await mount(); await live(); await enrol(); await send();
    setValue("r-token", "gateway-audience"); await click("r-send");
    await waitFor(() => expect(screen.getByTestId("report-result")).toHaveTextContent(/aud_mismatch/), T);
    setValue("r-token", "projected"); await click("revoke-fid-006");
    await waitFor(() => expect(screen.getByTestId("sensor-fid-006")).toHaveTextContent(/disabled/), T);
    await click("r-send"); await waitFor(() => expect(screen.getByTestId("report-result")).toHaveTextContent(/identity_disabled/), T);
    expect(within(screen.getByTestId("findings")).getAllByTestId(/^finding-row-/).length).toBe(1);
    expect(screen.getByTestId("findings")).toHaveTextContent(C.castNode1);
  });

  it("audit mode records would-have-blocked and blocks nothing; enforce blocks the same finding; a namespace outside the scope is not evaluated", async () => {
    await mount(); await live(); await enrol();
    await click("mode-audit"); await click("policy-save");
    await waitFor(() => expect(screen.getByTestId("sensor-fid-006")).toBeInTheDocument(), T);
    await send();
    await waitFor(() => expect(screen.getAllByTestId("effect")[0]).toHaveTextContent(/would have blocked \(audit\)/), T);
    expect(screen.getByTestId("findings")).not.toHaveTextContent(/\bblocked\b(?! \(audit\))/);
    await click("mode-enforce"); await click("policy-save");
    await waitFor(() => expect(screen.getByTestId("policy-form")).toBeInTheDocument(), T);
    await send();
    await waitFor(() => expect(screen.getAllByTestId("effect").some((e) => e.textContent === "blocked")).toBe(true), T);
    await pick("f-ns-0", C.castNs3); await click("r-send");
    await waitFor(() => expect(screen.getAllByTestId("effect").some((e) => e.textContent === "out of scope")).toBe(true), T);
  }, 60000);
});

describe("Diagram", () => {
  it("the three diagrams load from data, Simulate walks the arrows, Reset restores", async () => {
    await mount(); await tab("Diagram");
    await screen.findByTestId("pattern-canvas", {}, T);
    expect(screen.getByRole("heading", { name: /one platform-issued credential, three services/ })).toBeInTheDocument();
    expect(screen.getByTestId("pattern-step-bar")).toHaveTextContent(/Simulate walks the 6 arrows/);
    await click("simulate"); await waitFor(() => expect(screen.getByTestId("pattern-now")).toHaveTextContent(/Step 1/), T);
    await click("dg-verification-steps"); await waitFor(() => expect(screen.getByTestId("pattern-step-bar")).toHaveTextContent(/Simulate walks the 7 arrows/), T);
    await click("dg-self-hosted-agent"); await waitFor(() => expect(screen.getByRole("heading", { name: /a sensor verified, not vouched/ })).toBeInTheDocument(), T);
    await click("simulate"); await waitFor(() => expect(screen.getByTestId("pattern-now")).toBeInTheDocument(), T);
    await click("pattern-reset"); await waitFor(() => expect(screen.queryByTestId("pattern-now")).toBeNull(), T);
    expect(screen.getByTestId("speed")).toBeInTheDocument();
  });
  it("the edge-label offsets nudge a reply apart from the arrow it answers", () => {
    expect(labelOffsets([{ from: "a", to: "b" }, { from: "b", to: "a" }, { from: "a", to: "c" }])).toEqual([-16, 16, 0]);
  });
  it("Reset also restores the diagram box positions", async () => {
    await mount(); await tab("Diagram");
    await screen.findByTestId("pattern-canvas", {}, T);
    expect(await screen.findByText(/Moved: 0 box/, {}, T)).toBeInTheDocument();
    await click("reset");
    expect(await screen.findByText(/Moved: 0 box/, {}, T)).toBeInTheDocument();
  });
});

describe("Talk track", () => {
  it("has both Why it matters entries marked as Ping claims, every discrepancy, and what we measured", async () => {
    await mount(); await tab("Talk track");
    const t = await screen.findByTestId("talk-track", {}, T);
    expect(t).toHaveTextContent(/Why it matters: Federated Identity/); expect(t).toHaveTextContent(/Why it matters: Self-Hosted Agents/); expect(t).toHaveTextContent(/Challenge:/); expect(t).toHaveTextContent(/Technical:/); expect(t).toHaveTextContent(/Business:/); expect(t).toHaveTextContent(/Ping claims, unverified on our tenant/);
    for (const id of ["naming", "mcp-acceptance", "token-pass", "modes-actions", "scopes", "revocation-speed", "ga-tag"]) expect(screen.getByTestId(`disc-${id}`)).toBeInTheDocument();
    expect(screen.getByTestId("disc-mcp-acceptance")).toHaveTextContent(/Not re-tested on the release/);
    expect(screen.getByTestId("measured")).toHaveTextContent(/Measured \(our note/);
    expect(screen.getByTestId("availability")).toHaveTextContent(/Sidecar injection[\s\S]*in development/);
  });
  it("the vertical switch reloads the cast: names change in the story and the identities", async () => {
    await mount(); expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(C.castAgent);
    await pick("vertical-select", "health");
    await waitFor(() => expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(VERTICALS.health.castAgent), T);
    expect(screen.getByTestId("identity-fid-001")).not.toHaveTextContent(C.castAgent);
  });
});

describe("Reset and stale answers", () => {
  it("Reset clears this workspace in Live (the clock, the audit log, revocations); another workspace is not touched", async () => {
    await mount(); await live();
    await click("revoke-fid-001"); await waitFor(() => expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(/disabled/), T);
    const other = await realFetch(`${base}/api/clock`, { method: "POST", headers: { "content-type": "application/json", origin: base, "x-workspace": "w-other-ws" }, body: JSON.stringify({ mode: "live", vertical: "finance", clock: { minutes: 5 } }) });
    expect(other.status).toBe(200);
    await click("reset");
    await waitFor(() => expect(screen.getByTestId("identity-fid-001")).toHaveTextContent(/enabled/), T);
    const st = await (await realFetch(`${base}/api/state?mode=live`, { headers: { "x-workspace": "w-other-ws" } })).json();
    expect(st.state.clock.advancedMin).toBe(5);
  }, 60000);

  it("a late scenario answer never overwrites the scenario picked after it (stale-response guard), decided by releasing the held request", async () => {
    await mount(); await tab("Verify"); await screen.findByTestId("scenarios", {}, T);
    let release; const held = new Promise((r) => { release = r; });
    gate = (u) => (u.includes("scenario=lifetimes") ? held : null);
    await pick("scenario-pick", "lifetimes"); await pick("scenario-pick", "sensor");
    await waitFor(() => expect(screen.getByTestId("scenario-say")).toHaveTextContent(/Enrol a sensor/), T);
    release();
    await waitFor(() => expect(consumed.some((u) => u.includes("scenario=lifetimes"))).toBe(true), T);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByTestId("scenario-say")).toHaveTextContent(/Enrol a sensor/); expect(screen.getByTestId("scenario-say")).not.toHaveTextContent(/Expired/);
  }, 60000);

  it("a write answer for a mode the visitor has already left is not shown (stale write guard), decided by releasing the held request", async () => {
    await mount(); await live(); await tab("Issuers and keys");
    await waitFor(() => expect(screen.getByTestId("advance-5")).toBeEnabled(), T);
    let release; const held = new Promise((r) => { release = r; });
    gate = (u) => (u.includes("/api/clock") ? held : null);
    await click("advance-5"); await pickMode("mock");
    await waitFor(() => expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock"), T);
    await waitFor(() => expect(screen.getByTestId("clock-now")).toHaveTextContent(/09:00:00 UTC/), T);
    release();
    await waitFor(() => expect(consumed.some((u) => u.includes("/api/clock"))).toBe(true), T);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByTestId("clock-now")).toHaveTextContent(/09:00:00 UTC/); expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock");
  }, 60000);
});

describe("hostile text is shown inert and credentials are masked", () => {
  it("control and bidi characters become visible escapes, markup stays text", () => {
    expect(visible("a‮b\u0000c")).toBe("a\\u202eb\\u0000c");
    expect(visible("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  });

  it("a credential typed as a claim is REFUSED (never signed, never shown); markup in an ordinary claim is signed as typed and shown as text", async () => {
    await mount(); await live(); await tab("Verify");
    await waitFor(() => expect(screen.getByTestId("mint")).toBeEnabled(), T);
    const secret = ["gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("");
    setValue("f-sub", `x ${secret}`); setValue("f-extra", `note=my password is hunter2hunter2`);
    await click("mint"); await waitFor(() => expect(screen.getByTestId("mint-error")).toHaveTextContent(/credential_shaped/), T);
    expect(screen.getByTestId("token").value).toBe("");
    setValue("f-sub", "<img src=x onerror=alert(1)> plain"); setValue("f-extra", "pod=p-0");
    await click("mint"); await waitFor(() => expect(screen.getByTestId("token").value).toMatch(/^eyJ/), T);
    expect(decodeToken(screen.getByTestId("token").value).payload.sub).toBe("<img src=x onerror=alert(1)> plain");
    await click("verify"); await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument(), T);
    await tab("Audit");
    const text = wholePageText();
    expect(text).not.toContain(secret); expect(text).not.toContain("hunter2hunter2");
    expect(document.querySelector("img[src='x']")).toBeNull();
  });
});
