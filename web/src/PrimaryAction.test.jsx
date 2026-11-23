// One primary action per view state (ui-patterns P9), in Live mode, where the gateway card is on the page.
// The card's button is primary only when App passes primaryRetry; a tab with its own primary keeps it.
// Real App, real Express app on a loopback port (same harness as App.test.jsx), no network beyond loopback.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { createRunLog } from "../../server/src/runObs.js";
import App from "./App";
import { forgetWorkspace } from "./workspace";

let server; let base; const realFetch = globalThis.fetch;
beforeAll(async () => {
  const health = createHealth({ demoId: "federated-identity-lab", demoName: "Federated Identity LAB", version: "0.1.0", runChecks: () => [], allPassed: () => true, intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json", runLog: createRunLog({ write: () => {} }) }) }));
  base = base.replace(/\/$/, "");
  globalThis.fetch = async (u, init = {}) => {
    const url = typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u;
    return realFetch(url, { ...init, headers: { origin: base, ...(init.headers || {}) } });
  };
});
afterAll(async () => { globalThis.fetch = realFetch; await new Promise((r) => server.close(r)); });
beforeEach(async () => {
  cleanup(); forgetWorkspace(); window.location.hash = "";
  await realFetch(`${base}/api/mode`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ source: "mock" }) });
});

const T = { timeout: 20000 };
const LINKS = {
  identities: "Federated Identity", verify: "Verify", issuers: "Issuers and keys", models: "Deployment models",
  sensors: "Self-Hosted Agents", audit: "Audit", diagram: "Diagram", talk: "Talk track",
};
const TABS = Object.keys(LINKS);

// Live mode, then one tab, then wait until that tab has drawn (the card and the tab panel are both on the page).
async function openLiveTab(name) {
  render(<App />);
  await screen.findByTestId("identities", {}, T);
  await userEvent.selectOptions(screen.getByTestId("mode-select"), "real");
  await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/), T);
  await userEvent.click(screen.getByRole("link", { name: LINKS[name] }));
  await waitFor(() => expect(screen.getByTestId("privilege-check")).toBeInTheDocument(), T);
  await waitFor(() => expect(document.querySelector(`#panel-${name}`)).not.toBeNull(), T);
  await waitFor(() => expect(screen.queryByTestId("settling")).toBeNull(), T);
}

// The primary buttons on the page: the card's button and each tab's own, counted where they are drawn.
const primaries = (scope = document) => [...scope.querySelectorAll(".primary")];

describe("P9: exactly one primary action per view state, in Live mode", () => {
  it.each(TABS)("%s: exactly one primary button on the whole page (card included)", async (name) => {
    await openLiveTab(name);
    expect(primaries().map((b) => b.textContent)).toHaveLength(1);
  }, 60000);

  it("identities: its own content has exactly one primary (the form and the key panel both drew one)", async () => {
    await openLiveTab("identities");
    expect(primaries(document.querySelector("#panel-identities")).map((b) => b.textContent)).toHaveLength(1);
  }, 60000);

  it("sensors: its own content has exactly one primary (policy, report and enrol each drew one)", async () => {
    await openLiveTab("sensors");
    expect(primaries(document.querySelector("#panel-sensors")).map((b) => b.textContent)).toHaveLength(1);
  }, 60000);

  it("verify: the card's button is not primary when the tab has its own Verify button", async () => {
    await openLiveTab("verify");
    expect(screen.getByTestId("privilege-check").querySelector(".primary")).toBeNull();
    expect(primaries(document.querySelector("#panel-verify")).map((b) => b.textContent)).toEqual(["Verify"]);
  }, 60000);

  it("diagram: the card's button is not primary when the tab has its own Simulate button", async () => {
    await openLiveTab("diagram");
    await waitFor(() => expect(screen.getByTestId("simulate")).toBeInTheDocument(), T);
    expect(screen.getByTestId("privilege-check").querySelector(".primary")).toBeNull();
    expect(primaries(document.querySelector("#panel-diagram"))).toHaveLength(1);
  }, 60000);
});
