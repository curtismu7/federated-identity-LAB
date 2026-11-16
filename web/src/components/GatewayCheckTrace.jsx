import { useState } from "react";
import GatewayTrace from "../gateway-trace/GatewayTrace";
import { postJson } from "../api";

// "What Privilege did" (Rule 25) for the Real gateway check. The shared card above makes its own call and does not hand its answer on, so
// this runs the same check once more when asked (never on load) and draws the two exchanges the server captured: tools/list, then the
// refusal probe. Real traces carry only observed or inferred decisions: the gateway reports no per-check detail.
export default function GatewayCheckTrace() {
  const [s, setS] = useState({ phase: "idle" });
  const run = async () => {
    setS({ phase: "running" });
    try {
      const r = await postJson("/api/gateway-check", {});
      if (!r.ok) { setS({ phase: "error", reason: r.body?.message || r.body?.detail || `the lab answered ${r.status}` }); return; }
      setS({ phase: "done", trace: r.body.trace });
    } catch (e) { setS({ phase: "error", reason: String(e?.message || e).slice(0, 200) }); }
  };
  const exchanges = s.phase === "done"
    ? [["tools/list", s.trace?.listing], ["Refusal probe: tools/call", s.trace?.refusal]].filter(([, t]) => t)
      .map(([title, trace], i) => ({ step: i + 1, title, status: trace.response?.status ?? null, trace }))
    : [];
  return (
    <section className="pcard" data-testid="gateway-check-trace" aria-label="What Privilege did">
      <button type="button" className="pcard__retry" onClick={run} disabled={s.phase === "running"} data-testid="gateway-check-trace-run">
        {s.phase === "running" ? "Calling the gateway..." : "Show what Privilege did"}
      </button>
      {s.phase === "error" && <p className="pcard__note pcard__note--error" role="alert">{s.reason}</p>}
      {exchanges.length > 0 && <GatewayTrace source="real" exchanges={exchanges} />}
    </section>
  );
}
