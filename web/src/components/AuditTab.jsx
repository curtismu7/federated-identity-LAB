import { useMemo, useState } from "react";
import { visible } from "../safeText";
import { ClaimTag, FieldSources, SourceTag, StatusTag } from "./Bits";

const time = (iso) => String(iso).slice(11, 19);

// Audit: every request attributed to a specific deployment, every refusal with its code, and revocation one click away.
export default function AuditTab({ story, lab }) {
  const s = lab.state; const ro = lab.readOnly;
  const [outcome, setOutcome] = useState("all");
  const [kind, setKind] = useState("all");
  const kinds = useMemo(() => [...new Set(s.audit.map((a) => a.kind))], [s.audit]);
  const rows = s.audit.filter((a) => (outcome === "all" || a.outcome === outcome) && (kind === "all" || a.kind === kind)).slice().reverse();
  const byDeployment = useMemo(() => {
    const m = new Map();
    for (const a of s.audit) if (a.outcome === "allowed" && a.deployment) { const k = `${a.principal} | ${a.deployment}`; m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()];
  }, [s.audit]);
  return (
    <div className="stack">
      <section className="panel" data-testid="by-deployment">
        <h2 className="panel__title">Requests by deployment <ClaimTag /> <SourceTag source="deck" label="deck claim: every request is attributed to a specific deployment" /></h2>
        <p className="muted">How a deployment is named (namespace and service account and pod, or repository and ref and run) is the lab's reading. Only verified requests are attributed; a refused one is recorded with the subject it <em>claimed</em>, marked unverified.</p>
        <div className="scroll"><table className="tbl tbl--wide"><thead><tr><th>Principal</th><th>Deployment</th><th>Allowed requests</th></tr></thead>
          <tbody>{byDeployment.length === 0 ? <tr><td colSpan={3} className="muted">No allowed request yet.</td></tr> : byDeployment.map(([k, n]) => { const [p, d] = k.split(" | "); return <tr key={k} data-testid="deployment-row"><td>{visible(p)}</td><td>{visible(d)}</td><td>{n}</td></tr>; })}</tbody></table></div>
      </section>
      <section className="panel" data-testid="revocation">
        <h2 className="panel__title">Revocation <ClaimTag /></h2>
        <p className="muted">Revoke an identity here, then send the next request from the Verify tab: it is refused, and the audit log below says why. Removing the identity does the same.</p>
        <div className="toggles">{s.identities.map((i) => i.enabled
          ? <button key={i.id} type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${i.id}`, { identity: { enabled: false } })} data-testid={`audit-revoke-${i.id}`}>Revoke {visible(i.name)}</button>
          : <button key={i.id} type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${i.id}`, { identity: { enabled: true } })} data-testid={`audit-restore-${i.id}`}>Restore {visible(i.name)} (revoked)</button>)}</div>
      </section>
      <section className="panel" data-testid="audit">
        <h2 className="panel__title">Audit log</h2>
        <div className="filters">
          <label>Outcome<select value={outcome} onChange={(e) => setOutcome(e.target.value)} data-testid="audit-outcome"><option value="all">all</option><option value="allowed">allowed</option><option value="refused">refused</option></select></label>
          <label>Kind<select value={kind} onChange={(e) => setKind(e.target.value)} data-testid="audit-kind"><option value="all">all</option>{kinds.map((k) => <option key={k} value={k}>{k}</option>)}</select></label>
        </div>
        <p className="muted" data-testid="audit-count">{rows.length} shown of {s.audit.length} kept (a ring of {s.limits.audit}; {s.auditDropped} older entr{s.auditDropped === 1 ? "y was" : "ies were"} dropped). Times are the lab clock (UTC).</p>
        <div className="scroll"><table className="tbl tbl--wide">
          <thead><tr><th>#</th><th>Lab time</th><th>Event</th><th>Outcome</th><th>Principal and deployment</th><th>Service</th><th>Note</th></tr></thead>
          <tbody>{rows.map((a) => (
            <tr key={a.n} data-testid="audit-row">
              <td>{a.n}</td><td>{time(a.at)}</td><td>{visible(a.kind)}</td>
              <td>{a.outcome ? <StatusTag status={a.outcome} /> : ""} {a.code && <code>{a.code}</code>}</td>
              <td>{a.principal ? visible(a.principal) : ""}{a.deployment ? <div>{visible(a.deployment)}</div> : ""}{a.claimed ? <div className="muted">claimed (unverified): {visible(a.claimed)}</div> : ""}{a.node ? <div>node {visible(a.node)}</div> : ""}</td>
              <td>{a.service || ""}</td><td>{visible([a.identityId, a.keyId, a.issuer, a.note].filter(Boolean).join(" "))}</td>
            </tr>))}
          </tbody>
        </table></div>
      </section>
      <FieldSources fields={story.fieldSources.filter((x) => /Revoking the identity|Gateway refusal/.test(x.field))} />
    </div>
  );
}
