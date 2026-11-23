// Rule 27: the shared run-observability panel for this lab, with the lab's own states around it.
// Mock: the recorded scenario's record (built on the server from the steps the table holds).
// Real: what the lab received on the page's own gateway check (the card above), asked for by that check's run id. A check that never reached the gateway
// made no run, so the panel says so and never shows an older record. Nothing is re-read on a timer: this lab reads no logs, so a re-read could find nothing new.
// The Verify, Issuers and Self-Hosted Agents tabs in Real are the lab's own local engine: they write stdout lines but are not part of a Real record.
import { useEffect, useState } from "react";
import RunObservability from "../run-observability/RunObservability.jsx";

// Where this lab's run leaves logs and where they can stream (the README says the same).
export const LOG_STREAMS = [
  { product: "Federated Identity LAB (this lab's container)", lives: "its stdout. In Live, one line per decision the lab's own engine makes (the gateway's verdict on a token or a stored key, the sensor policy's effect on a finding, a change to its Federated Identity model) and one per answer received from the Privilege gateway in Real: an id the lab wrote, a step, a result and a run id, never a credential, a claim, a name you typed or a gateway address. Mock reads recorded tables and writes none", streams: "nowhere today: the family log collector's source list does not name this container, so it would need an entry first. The SIEM time would then be Docker's wall-clock time for the line; the lab clock stays inside the line as labtime" },
  { product: "Privilege agent gateway (Real)", lives: "its own log (a log volume for a local gateway; the SIEM index for the hosted one)", streams: "the Privilege SIEM export. This lab does not read it, so the Real record holds only what the lab received" },
];

const TITLE = "What each layer logged for this run";
const Note = ({ testId, role, children }) => (
  <div className="obs">
    <section className="ro" data-testid={testId} aria-label={TITLE}>
      <h2>{TITLE}</h2>
      <p className="ro-muted" role={role}>{children}</p>
    </section>
  </div>
);

export const NOTE = {
  mock: "Times are the lab clock: it starts at 2026-11-02 09:00 UTC and moves only when a step moves it, so the steps of one scenario can share a time (their order is kept). These rows come from the recorded scenario's results, not from a product log, and each starts with the number of the scripted step it came from. The counts are rows: one step can give several (a verification gives an Agent row and an Agent gateway row). Person appears only as the custodian of a stored key: the lab has no sign-in. Agent is the Federated Identity the lab's gateway matched, or a mock issuer signing a token: there is no OBO token. Privilege holds the lab's own Federated Identity model and sensor policy, not PingOne Privilege. Agent gateway is the lab's own simulated gateway: its verdict is its fifteen checks, not the Privilege gateway's. There is no resource server: the gateway's outbound request is modelled and nothing answers it. A request the lab turned away before any decision (a bad field, an unknown id, a cap) and a clock move, an issuer's key rotation or a key-set refresh have no row.",
  real: "Real is only the hop to the Privilege gateway: each row is a reply the lab received, not a log line. The Verify, Issuers and Self-Hosted Agents tabs in Real are the lab's own local engine (simulated, loopback): they write one stdout line per decision, which this panel does not read, so they are not part of this record. No person signs in and there is no OBO token: the caller is an agent access key. The key and the gateway address are never part of a row. The counts are rows.",
};

// null = a request is needed; otherwise what to show instead (nothing is fetched and no older record is shown).
function waiting(real, check, scenarioId) {
  if (real) {
    if (check.phase === "done") return check.runId ? null : { id: "ro-no-run", role: "alert", text: "The gateway check ran, but the lab did not keep a record of it (the server log says why)." };
    if (check.phase === "not-configured") return { id: "ro-no-run", text: `No gateway call was made, so there is no run to show. ${check.reason || "Real is not configured."}` };
    if (check.phase === "error") return { id: "ro-no-run", role: "alert", text: `The gateway check did not complete, so there is no run to show (and no older one is shown in its place). ${check.reason || ""}`.trim() };
    return { id: "ro-loading", text: "Collecting this run's logs…" };
  }
  return scenarioId ? null : { id: "ro-loading", text: "Collecting this run's logs…" };
}

// What a route answer is: a run record (an object with its rows) or null with a message; anything else is not a run record.
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isRecordAnswer = (b) => isObject(b) && "record" in b && (b.record === null || (isObject(b.record) && Array.isArray(b.record.rows)));

export default function RunObs({ source, vertical, scenarioId, check }) {
  const real = source === "real";
  const wait = waiting(real, check || { phase: "checking" }, scenarioId);
  const key = real ? `real|${check?.runId}` : `mock|${vertical}|${scenarioId}`;
  const [answer, setAnswer] = useState(null); // { key, record, message }: the answer to the request for `key`
  const url = real ? `/api/run-observability?runId=${encodeURIComponent(check?.runId ?? "")}` : `/api/run-observability?vertical=${encodeURIComponent(vertical)}&scenario=${encodeURIComponent(scenarioId ?? "")}`;
  useEffect(() => {
    if (wait) return undefined;
    let live = true;
    // The handler catches its own errors: a body that is not what was expected is an alert, never a stuck "Collecting" note.
    const done = (a) => { if (live) setAnswer({ key, ...a }); };
    const notRecord = (message) => done({ record: { error: "bad_answer", message } });
    fetch(url, { headers: { accept: "application/json" } }).then(
      async (r) => {
        try {
          const body = await r.json().catch(() => null);
          if (!r.ok) return done({ record: { error: body?.error || `http_${r.status}`, message: body?.message || `The lab answered ${r.status}.` } });
          if (isRecordAnswer(body)) return done({ record: body.record, message: body.message });
          return notRecord("The lab's answer was not a run record.");
        } catch { return notRecord("The lab's answer could not be read as a run record."); }
      },
      (e) => done({ record: { error: "unreachable", message: `Could not reach the lab (${String(e?.message || e).slice(0, 120)}).` } }),
    );
    return () => { live = false; };
  }, [key, url, wait === null]); // eslint-disable-line react-hooks/exhaustive-deps -- a new run, scenario or mode asks again; nothing else does

  if (wait) return <Note testId={wait.id} role={wait.role}>{wait.text}</Note>;
  if (!answer || answer.key !== key) return <Note testId="ro-loading">Collecting this run's logs…</Note>; // never the previous record
  if (answer.record === null) return <Note testId="ro-no-run">{answer.message || "There is no run to show."}</Note>;
  return (
    <div className="obs">
      <RunObservability record={answer.record} source={source} streams={LOG_STREAMS} />
      <p className="ro-muted" data-testid="ro-lab-note">{NOTE[real ? "real" : "mock"]}</p>
    </div>
  );
}
