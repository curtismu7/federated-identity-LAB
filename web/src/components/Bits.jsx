import { useRef } from "react";
import { visible } from "../safeText";

// Raw JSON or text, rendered as text only (never markup). Control and bidi characters are shown as visible escapes.
export function Json({ value, label, testId }) {
  return <pre className="json" tabIndex={0} aria-label={label} data-testid={testId}>{visible(typeof value === "string" ? value : JSON.stringify(value, null, 2))}</pre>;
}

// Every product claim carries this tag. It is on every tab, and in presenter mode too.
export function ClaimTag({ label }) {
  return <span className="tag" data-state="warn" data-testid="claim-tag">{label || "Ping release claim, UNVERIFIED on our tenant"}</span>;
}

// Where a field comes from: the deck, the console swagger (a name only), the lab's reading of it, or the lab's own invention.
const SRC = { deck: ["deck claim", "ok"], swagger: ["console swagger name (schema only)", "ok"], reading: ["lab reading", "warn"], invented: ["lab-invented", "none"], measured: ["measured (our note)", "ok"] };
export function SourceTag({ source, label }) {
  const [text, state] = SRC[source] || [source, "none"];
  return <span className="tag" data-state={state} data-testid="source-tag">{label || text}</span>;
}

// Availability from slide 21: GA, Roadmap (Q4 2026), Planned, or "described in the deck, availability not stated".
export function AvailTag({ value }) {
  const state = value === "GA" ? "ok" : value === "Planned" || value.startsWith("Roadmap") ? "bad" : "warn";
  return <span className="tag" data-state={state} data-testid="avail-tag">{value}</span>;
}

// status words with a state, so meaning never rests on colour alone
const GOOD = new Set(["pass", "ok", "allowed", "enabled", "up", "active", "blocked", "monitored", "warned"]);
const BAD = new Set(["fail", "refused", "revoked", "disabled", "down", "inactive", "failed", "would-have-blocked"]);
export const StatusTag = ({ status }) => <span className="tag" data-state={GOOD.has(status) ? "ok" : BAD.has(status) ? "bad" : "warn"} data-testid="status">{status}</span>;

export function Hops({ hops, traceId, truncated }) {
  return (
    <details className="hops" data-testid="hops">
      <summary>Raw hops with traceparent{traceId ? ` (trace ${traceId.slice(0, 8)}...)` : ""} ({hops.length})</summary>
      {truncated && <p className="muted">Only the first hops are shown.</p>}
      {hops.map((h) => (
        <div key={h.n}>
          <h4 className="hops__title">{h.n}. {h.label}</h4>
          <Json value={h.request} label={`hop ${h.n} request`} />
          <Json value={h.response} label={`hop ${h.n} response`} />
        </div>
      ))}
    </details>
  );
}

// The per-field source table, so every claim is tagged deck claim, swagger name, lab reading or lab-invented.
export function FieldSources({ fields }) {
  return (
    <details data-testid="field-sources">
      <summary>Where each field comes from ({fields.length})</summary>
      <div className="scroll"><table className="tbl tbl--wide">
        <thead><tr><th>Field</th><th>Source</th><th>Note</th></tr></thead>
        <tbody>{fields.map((f) => <tr key={f.field}><td><code>{f.field}</code></td><td><SourceTag source={f.source} /></td><td>{visible(f.note)}</td></tr>)}</tbody>
      </table></div>
    </details>
  );
}

// Stale-response guard: run() returns a function that says whether a newer request has started since.
export function useSeq() {
  const seq = useRef(0);
  return () => { const mine = ++seq.current; return () => mine === seq.current; };
}

// A refusal or a success message under a control, as text.
export function Outcome({ last, prefix }) {
  if (!last || (prefix && !last.route.includes(prefix))) return null;
  return last.ok ? <p className="muted" role="status" data-testid="outcome">Done.</p> : <p className="field-error" role="alert" data-testid="outcome">Refused ({last.error}): {visible(last.detail || "")}</p>;
}

// The fifteen verification steps, in order: passed, the one that failed, and the ones never reached.
export function VerifySteps({ steps }) {
  return (
    <div className="scroll"><table className="tbl tbl--wide" data-testid="steps">
      <thead><tr><th>#</th><th>Step</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>{steps.map((s, i) => <tr key={s.id} data-testid={`step-${s.id}`}><td>{i + 1}</td><td>{s.title}</td><td><StatusTag status={s.status === "skip" ? "not reached" : s.status} /></td><td>{visible(s.detail)}</td></tr>)}</tbody>
    </table></div>
  );
}

// The verdict line: allowed or refused, the exact code, and what a caller would see (a real gateway's refusal is thin: measured, our note).
export function Verdict({ r }) {
  if (!r) return null;
  return (
    <p className={r.ok ? "verdict verdict--ok" : "verdict verdict--bad"} role="status" data-testid="verdict" data-state={r.ok ? "ok" : "bad"}>
      <strong>{r.ok ? "ALLOWED" : "REFUSED"}</strong> <code data-testid="verdict-code">{r.code}</code>: {visible(r.detail || "")}. The caller would see only <strong>{r.callerSees || r.status}</strong>; the lab names the reason so you can learn from it.
    </p>
  );
}
