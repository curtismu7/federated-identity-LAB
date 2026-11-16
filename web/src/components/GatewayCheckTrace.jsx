import { useState } from "react";
import GatewayTrace from "../gateway-trace/GatewayTrace";

// "What Privilege did" (Rule 25) for the Real gateway check. It draws the two exchanges the server captured for the shared card's own
// check (tools/list, then the refusal probe), handed over by the card's onResult: showing it makes no further gateway call. Real traces
// carry only observed or inferred decisions: the gateway reports no per-check detail.
export default function GatewayCheckTrace({ result }) {
  const [shown, setShown] = useState(false);
  const trace = result?.phase === "done" ? result.trace : null;
  const exchanges = trace
    ? [["tools/list", trace.listing], ["Refusal probe: tools/call", trace.refusal]].filter(([, t]) => t)
      .map(([title, t], i) => ({ step: i + 1, title, status: t.response?.status ?? null, trace: t }))
    : [];
  return (
    <section className="pcard" data-testid="gateway-check-trace" aria-label="What Privilege did">
      <button type="button" className="pcard__retry" onClick={() => setShown(true)} disabled={exchanges.length === 0 || shown} data-testid="gateway-check-trace-run">
        Show what Privilege did
      </button>
      {shown && exchanges.length > 0 && <GatewayTrace source="real" exchanges={exchanges} />}
    </section>
  );
}
