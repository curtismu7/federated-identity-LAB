// The lab's own states around the shared panel: loading (never the previous record), empty, an alert for any answer that is not a record, the mode
// the record was made in, and no request when nothing changed. fetch is replaced by a script; the real route is exercised by the server tests and App.test.jsx.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import RunObs, { NOTE } from "./RunObs";
import { setJsonView } from "./JsonPane.jsx";
import { mockRecord, realRecord } from "../run-observability/fixtures";

const realFetch = globalThis.fetch;
let calls = [];
let answers = {};
const ok = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
beforeEach(() => {
  setJsonView("raw"); calls = []; answers = {};
  globalThis.fetch = vi.fn(async (url) => {
    calls.push(String(url));
    const a = answers[String(url)] ?? answers["*"];
    if (typeof a === "function") return a();
    if (a instanceof Error) throw a;
    return a ?? ok({ record: null, message: "no answer scripted" });
  });
});
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });

const MOCK_URL = "/api/run-observability?vertical=finance&scenario=one-credential";
const gate = () => { let open; const p = new Promise((r) => { open = r; }); return { p, open }; };
const mockPanel = (props = {}) => <RunObs source="mock" vertical="finance" scenarioId="one-credential" {...props} />;
const realPanel = (check, props = {}) => <RunObs source="real" vertical="finance" check={check} {...props} />;

describe("Mock", () => {
  it("shows the panel for the recorded scenario, says what the lanes hold and what a count is, and asks once", async () => {
    answers[MOCK_URL] = ok({ record: mockRecord });
    const { rerender } = render(mockPanel());
    expect(screen.getByTestId("ro-loading")).toHaveTextContent("Collecting this run's logs");
    await screen.findByTestId("run-observability");
    expect(screen.getByTestId("ro-basis")).toHaveTextContent(/Simulated/);
    const note = screen.getByTestId("ro-lab-note");
    expect(note).toHaveTextContent(/lab clock.*each starts with the number of the scripted step/s);
    expect(note).toHaveTextContent(/counts are rows: one step can give several/);
    expect(note).toHaveTextContent(/lab has no sign-in.*no OBO token.*lab's own Federated Identity model and sensor policy, not PingOne Privilege.*lab's own simulated gateway.*no resource server/s);
    expect(note).toHaveTextContent(/A request the lab turned away before any decision/);
    expect(screen.getByTestId("ro-streams")).toHaveTextContent(/Mock reads recorded tables and writes none/);
    expect(screen.queryByText(/Re-read/)).toBeNull();
    // a re-render with the same run (a state refresh) asks nothing new
    rerender(mockPanel({ check: { phase: "done", runId: "gw-1" } }));
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toEqual([MOCK_URL]);
  });

  it("waits for the scenario instead of asking for none, and never shows the previous scenario while the next one loads (a delayed answer)", async () => {
    answers[MOCK_URL] = ok({ record: mockRecord });
    const second = gate();
    answers["/api/run-observability?vertical=finance&scenario=sensor"] = () => second.p.then(() => ok({ record: { ...mockRecord, runId: "table-finance-sensor" } }));
    const { rerender } = render(mockPanel({ scenarioId: undefined }));
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(calls).toEqual([]);
    rerender(mockPanel());
    await screen.findByTestId("run-observability");
    rerender(mockPanel({ scenarioId: "sensor" }));
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    await new Promise((r) => setTimeout(r, 50)); // still waiting: the old record does not come back while the new one is slow
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    second.open();
    await screen.findByTestId("run-observability");
    expect(calls).toHaveLength(2);
  });

  it("a route answer that is not a record is an alert, for every shape: an HTTP error, HTML, null, empty, an array, a string, {}, a record that is no record, a body that throws, an unreachable lab", async () => {
    const bad = (json) => ({ ok: true, status: 200, json });
    for (const [a, text] of [
      [ok({ error: "unknown_scenario", message: "there is no such scenario in this pack" }, 404), /there is no such scenario in this pack/],
      [{ ok: false, status: 502, json: async () => { throw new Error("html"); } }, /The lab answered 502/],
      [bad(async () => { throw new SyntaxError("<html>"); }), /not a run record/],
      [bad(async () => null), /not a run record/],
      [bad(async () => { throw new SyntaxError("empty body"); }), /not a run record/],
      [bad(async () => []), /not a run record/],
      [bad(async () => "a string"), /not a run record/],
      [bad(async () => ({})), /not a run record/],
      [bad(async () => ({ record: "x" })), /not a run record/],
      [bad(async () => ({ record: {} })), /not a run record/],
      [bad(async () => ({ get record() { throw new TypeError("boom"); } })), /could not be read as a run record/],
      [new TypeError("fetch failed"), /Could not reach the lab \(fetch failed\)/],
    ]) {
      answers[MOCK_URL] = a;
      const { unmount } = render(mockPanel());
      expect(await screen.findByRole("alert")).toHaveTextContent(text);
      expect(screen.queryByTestId("ro-table")).toBeNull(); expect(screen.queryByTestId("ro-loading")).toBeNull(); expect(screen.queryByTestId("ro-empty")).toBeNull();
      unmount();
    }
  });

  it("a record made in the other mode is refused on screen (the server's mode and the page's differ)", async () => {
    answers[MOCK_URL] = ok({ record: realRecord });
    render(mockPanel());
    expect(await screen.findByTestId("ro-mismatch")).toHaveTextContent(/real mode but the page is in mock mode/);
  });
});

describe("Real", () => {
  it("folds the Real record in a disclosure that starts closed, so the gateway card stays the first thing on the page and the record is one click away", async () => {
    answers["/api/run-observability?runId=gw-1"] = ok({ record: { ...realRecord, runId: "gw-1" } });
    render(realPanel({ phase: "done", runId: "gw-1" }));
    const fold = await screen.findByTestId("ro-fold");
    expect(fold.tagName).toBe("DETAILS"); expect(fold.open).toBe(false);
    expect(fold.querySelector("summary")).toHaveTextContent(/What each layer logged for this run/);
    expect(within(fold).getByTestId("run-observability")).toBeInTheDocument();
    expect(within(fold).getByTestId("ro-lab-note")).toBeInTheDocument();
  });

  it("waits for the page's gateway check: nothing is asked and nothing older is shown while it runs", async () => {
    render(realPanel({ phase: "checking" }));
    expect(screen.getByTestId("ro-loading")).toHaveTextContent("Collecting this run's logs");
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toEqual([]);
  });

  it("asks for THAT check's run, shows it as real with the lab's note, and shows loading (not the old record) when the next check has a new run id, even if its answer is slow", async () => {
    answers["/api/run-observability?runId=gw-1"] = ok({ record: { ...realRecord, runId: "gw-1" } });
    const next = gate();
    answers["/api/run-observability?runId=gw-2"] = () => next.p.then(() => ok({ record: { ...realRecord, runId: "gw-2" } }));
    const { rerender } = render(realPanel({ phase: "done", runId: "gw-1" }));
    await screen.findByTestId("run-observability");
    expect(screen.getByTestId("ro-basis")).toHaveTextContent(/Real:/);
    expect(screen.getByTestId("ro-lab-note")).toHaveTextContent(NOTE.real);
    expect(screen.getByTestId("ro-lab-note")).toHaveTextContent(/only the hop to the Privilege gateway.*not a log line.*Verify, Issuers and Self-Hosted Agents tabs in Real are the lab's own local engine/s);
    expect(screen.queryByText(/Re-read/)).toBeNull();
    rerender(realPanel({ phase: "checking" }));
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    rerender(realPanel({ phase: "done", runId: "gw-2" }));
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("run-observability")).toBeNull();
    next.open();
    await screen.findByTestId("run-observability");
    expect(calls).toEqual(["/api/run-observability?runId=gw-1", "/api/run-observability?runId=gw-2"]);
  });

  it("a check that never reached the gateway made no run: it says so, asks nothing, and shows no older record", async () => {
    answers["/api/run-observability?runId=gw-1"] = ok({ record: { ...realRecord, runId: "gw-1" } });
    const { rerender } = render(realPanel({ phase: "done", runId: "gw-1" }));
    await screen.findByTestId("run-observability");
    rerender(realPanel({ phase: "error", reason: "the lab answered 409" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/did not complete.*no older one is shown in its place.*409/s);
    expect(screen.queryByTestId("run-observability")).toBeNull();
    rerender(realPanel({ phase: "not-configured", reason: "Real needs the gateway settings." }));
    expect(screen.getByTestId("ro-no-run")).toHaveTextContent(/No gateway call was made.*Real needs the gateway settings/s);
    rerender(realPanel({ phase: "done", runId: null }));
    expect(screen.getByRole("alert")).toHaveTextContent(/did not keep a record/);
    expect(calls).toHaveLength(1);
  });

  it("a run the lab no longer keeps is a note, not a record; a route answer that is not a record is an alert", async () => {
    answers["/api/run-observability?runId=gw-9"] = ok({ record: null, message: "That gateway check is no longer kept (the lab keeps the last few)." });
    const { unmount } = render(realPanel({ phase: "done", runId: "gw-9" }));
    expect(await screen.findByTestId("ro-no-run")).toHaveTextContent(/no longer kept/);
    await waitFor(() => expect(calls).toHaveLength(1));
    unmount();
    answers["/api/run-observability?runId=gw-9"] = ok([]);
    render(realPanel({ phase: "done", runId: "gw-9" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not a run record/);
  });
});
