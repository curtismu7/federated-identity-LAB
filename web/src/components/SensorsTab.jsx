import { useState } from "react";
import { visible } from "../safeText";
import { AvailTag, ClaimTag, FieldSources, Hops, Json, Outcome, SourceTag, StatusTag, VerifySteps, Verdict } from "./Bits";

const EFFECT_STATE = { "would-have-blocked": "would have blocked (audit)", blocked: "blocked", warned: "warned", monitored: "monitored", allowed: "allowed", "out-of-scope": "out of scope", off: "policy off", "no-policy": "no policy" };
const newFinding = (s) => ({ kind: "model-server", name: "vllm-server", namespace: s.namespaces[0], pod: "vllm-0" });

function PolicyForm({ story, lab, sensor }) {
  const p = sensor.policy;
  const [mode, setMode] = useState(p?.mode || "audit");
  const [all, setAll] = useState(p ? p.scope.all : false);
  const [ns, setNs] = useState(p ? p.scope.namespaces : [lab.state.namespaces[0]]);
  const [actions, setActions] = useState(p?.actions || { "ai-agent": "monitor", "mcp-server": "warn", "model-server": "deny" });
  const toggle = (n) => setNs((x) => (x.includes(n) ? x.filter((y) => y !== n) : [...x, n]));
  const save = () => lab.act("PUT", `/api/sensors/${sensor.identityId}/policy`, { policy: { mode, scope: all ? { all: true } : { namespaces: ns }, actions } });
  return (
    <section className="panel" data-testid="policy-form">
      <h3 className="panel__sub">Enforcement policy bound to this identity <SourceTag source="deck" /></h3>
      <div className="seg" role="group" aria-label="Policy mode">{story.policyModes.map((m) => <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)} data-testid={`mode-${m}`}>{m}</button>)}</div>
      <fieldset className="fieldset"><legend>Scope</legend>
        <label className="check"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} data-testid="scope-all" /> The whole cluster</label>
        {lab.state.namespaces.map((n) => <label key={n} className="check"><input type="checkbox" disabled={all} checked={!all && ns.includes(n)} onChange={() => toggle(n)} data-testid={`scope-ns-${n}`} /> namespace {visible(n)}</label>)}
      </fieldset>
      <div className="filters">{story.findingKinds.map((k) => <label key={k}>{k}<select value={actions[k]} onChange={(e) => setActions((a) => ({ ...a, [k]: e.target.value }))} data-testid={`action-${k}`}>{story.policyActions.map((a) => <option key={a} value={a}>{a}</option>)}</select></label>)}</div>
      <p><button type="button" className="primary" disabled={lab.readOnly || lab.busy} onClick={save} data-testid="policy-save">Save policy</button></p>
      <p className="muted">Audit mode records every decision that would have blocked, without blocking. Nothing is terminated in the lab: "blocked" is a recorded outcome. The console swagger names seven actions (including RequireApproval, Enforce, Exempt) and a Disabled flag; the lab follows the deck's modes and four actions.</p>
      <Outcome last={lab.last} prefix="/policy" />
    </section>
  );
}

function ReportForm({ story, lab, sensor }) {
  const s = lab.state;
  const [node, setNode] = useState(s.nodes[0]);
  const [forged, setForged] = useState("");
  const [tokenFrom, setTokenFrom] = useState("projected");
  const [findings, setFindings] = useState([newFinding(s)]);
  const [result, setResult] = useState(null);
  const upd = (i, k, v) => setFindings((fs) => fs.map((f, n) => (n === i ? { ...f, [k]: v } : f)));
  const send = async () => {
    const body = { findings }; if (forged) body.node = forged;
    const r = await lab.act("POST", `/api/sensors/${sensor.identityId}/reports`, { report: { node, tokenFrom, body } });
    const b = r.body || {};
    setResult(b.result ? { ...b.result, hops: b.hops, traceId: b.traceId } : { ok: false, code: b.error, detail: b.detail, status: r.status, steps: null });
  };
  return (
    <section className="panel" data-testid="report-form">
      <h3 className="panel__sub">Simulate a sensor report <SourceTag source="invented" label="the lab runs no eBPF: the report is simulated" /></h3>
      <div className="filters">
        <label>The sensor on node<select value={node} onChange={(e) => setNode(e.target.value)} data-testid="r-node">{s.nodes.map((n) => <option key={n} value={n}>{n}</option>)}</select></label>
        <label>A node named in the BODY (a forgery to be ignored; blank = none)<select value={forged} onChange={(e) => setForged(e.target.value)} data-testid="r-forged"><option value="">none</option>{s.nodes.map((n) => <option key={n} value={n}>{n}</option>)}</select></label>
        <label>Token<select value={tokenFrom} onChange={(e) => setTokenFrom(e.target.value)} data-testid="r-token"><option value="projected">the sensor's own projected token (generated audience)</option><option value="gateway-audience">a token minted for the gateway's audience (replay)</option></select></label>
      </div>
      {findings.map((f, i) => (
        <div className="filters" key={i} data-testid={`finding-${i}`}>
          <label>Kind<select value={f.kind} onChange={(e) => upd(i, "kind", e.target.value)} data-testid={`f-kind-${i}`}>{story.findingKinds.map((k) => <option key={k} value={k}>{k}</option>)}</select></label>
          <label>Namespace<select value={f.namespace} onChange={(e) => upd(i, "namespace", e.target.value)} data-testid={`f-ns-${i}`}>{s.namespaces.map((n) => <option key={n} value={n}>{n}</option>)}</select></label>
          <label>Name<input value={f.name} onChange={(e) => upd(i, "name", e.target.value)} data-testid={`f-name-${i}`} /></label>
          <label>Owning pod<input value={f.pod} onChange={(e) => upd(i, "pod", e.target.value)} data-testid={`f-pod-${i}`} /></label>
        </div>
      ))}
      <p className="toggles">
        <button type="button" disabled={findings.length >= s.limits.findingsPerReport} onClick={() => setFindings((fs) => [...fs, { ...newFinding(s), kind: "mcp-server", name: "ledger-tools", pod: "tools-0", namespace: s.namespaces[1] }])} data-testid="r-add">Add a finding</button>
        <button type="button" disabled={findings.length < 2} onClick={() => setFindings((fs) => fs.slice(0, -1))}>Remove the last</button>
        <button type="button" className="primary" disabled={lab.readOnly || lab.busy} onClick={send} data-testid="r-send">Send the report</button>
      </p>
      {result && (
        <div data-testid="report-result">
          <Verdict r={result} />
          {result.steps && <VerifySteps steps={result.steps} />}
          {result.ok && result.report && (
            <p data-testid="report-attribution">Attributed to node <strong data-testid="report-node">{visible(result.report.node)}</strong> (source: {result.report.nodeSource}).{" "}
              {result.report.bodyNodeIgnored ? <span data-testid="body-node-ignored">The body's node field (<code>{visible(result.report.bodyNode)}</code>) was <strong>ignored</strong>{result.report.bodyNodeDiffers ? " and it differed from the token" : ""}.</span> : "The body named no node."}</p>
          )}
          {result.hops && <Hops hops={result.hops} traceId={result.traceId} />}
        </div>
      )}
    </section>
  );
}

export default function SensorsTab({ story, lab }) {
  const s = lab.state; const ro = lab.readOnly;
  const [name, setName] = useState("Kubernetes sensor");
  const [pick, setPick] = useState("");
  const sensors = s.sensors;
  const sensor = sensors.find((x) => x.identityId === pick) || sensors[0] || null;
  const enrol = async () => { const r = await lab.act("POST", "/api/sensors", { sensor: { name } }); if (r.body?.ok) setPick(r.body.result.identityId); };
  return (
    <div className="stack">
      {ro && <p className="muted" data-testid="read-only-note">Mock only reads tables: switch to Live to enrol a sensor, send reports and set a policy.</p>}
      <section className="panel">
        <h2 className="panel__title">Self-Hosted Agents <ClaimTag /> <AvailTag value="GA (slide tag)" /></h2>
        <p className="lesson">A platform component acting as its <strong>own non-human principal</strong>. It holds an identity the platform issued, authenticates every operation with a short-lived token minted for a <strong>Privilege-generated audience</strong>, and the controller verifies <strong>issuer, subject, audience and scope on every report</strong>. The reporting node comes from the <strong>token's claims, not the sender's word</strong>. The first self-hosted agent is the Kubernetes sensor (eBPF discovery of AI agents, MCP servers and self-hosted model servers in pods); the lab runs no eBPF and no sensor, it simulates the reports.</p>
        <p className="muted">Self-Hosted Agents is the new name of "NHI Agents Discovery and Enforcement" (slide 35). Its identity is a Federated Identity: the console object is still <code>NonHumanIdentity</code>.</p>
        <div className="filters"><label>Sensor name<input value={name} onChange={(e) => setName(e.target.value)} data-testid="s-name" /></label></div>
        <p><button type="button" className="primary" disabled={ro || lab.busy} onClick={enrol} data-testid="enrol">Enrol a sensor</button></p>
        <Outcome last={lab.last} prefix="/api/sensors" />
        {sensors.length > 0 && (
          <div className="scroll"><table className="tbl tbl--wide" data-testid="sensors">
            <thead><tr><th>Sensor</th><th>State</th><th>Subject (exact)</th><th>Generated audience</th><th>Findings</th><th>Actions</th></tr></thead>
            <tbody>{sensors.map((x) => (
              <tr key={x.identityId} data-testid={`sensor-${x.identityId}`}>
                <td>{visible(x.name)}<br /><code>{x.identityId}</code></td><td><StatusTag status={x.enabled ? "enabled" : "disabled"} /></td>
                <td><code>{visible(x.subject)}</code></td><td><code data-testid={`audience-${x.identityId}`}>{visible(x.audience)}</code></td><td>{x.findings}</td>
                <td className="toggles">
                  <button type="button" aria-pressed={sensor?.identityId === x.identityId} onClick={() => setPick(x.identityId)} data-testid={`pick-${x.identityId}`}>Use</button>
                  {x.enabled ? <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${x.identityId}`, { identity: { enabled: false } })} data-testid={`revoke-${x.identityId}`}>Revoke identity</button>
                    : <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${x.identityId}`, { identity: { enabled: true } })} data-testid={`restore-${x.identityId}`}>Restore</button>}
                  <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", `/api/identities/${x.identityId}/remove`, { remove: {} })} data-testid={`remove-${x.identityId}`}>Remove identity</button>
                </td>
              </tr>))}
            </tbody>
          </table></div>
        )}
        <p className="muted">The audience is generated at enrolment and projected into the pod, so no standing secret sits on the node. The format (<code>priv-nhi-</code> then random characters) and the sensor scopes <code>shadowai:write</code> and <code>policy:read</code> were seen on our tenant (measured, our note); the value here is the lab's own random.</p>
      </section>

      {!ro && sensor && <ReportForm key={`r-${sensor.identityId}`} story={story} lab={lab} sensor={sensor} />}
      {!ro && sensor && <PolicyForm key={`p-${sensor.identityId}-${JSON.stringify(sensor.policy)}`} story={story} lab={lab} sensor={sensor} />}
      {ro && sensors[0]?.policy && <section className="panel"><h3 className="panel__sub">Policy</h3><Json value={sensors[0].policy} label="policy" /></section>}

      <section className="panel" data-testid="findings-panel">
        <h2 className="panel__title">Findings, attributed to the node in the token <ClaimTag /></h2>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="findings">
          <thead><tr><th>Finding</th><th>Kind</th><th>Namespace and pod</th><th>Node (from the token)</th><th>Reported by</th><th>Decision</th></tr></thead>
          <tbody>{s.findings.length === 0 ? <tr><td colSpan={6} className="muted">No findings yet.</td></tr> : s.findings.map((f) => (
            <tr key={f.id} data-testid={`finding-row-${f.id}`}><td>{visible(f.name)}</td><td>{f.kind}</td><td>{visible(f.namespace)} / {visible(f.pod)}</td><td>{visible(f.node)} <span className="tag" data-state="ok">{f.nodeSource}</span></td><td>{visible(f.identityName)}</td>
              <td><span className="tag" data-state={f.effect === "blocked" || f.effect === "would-have-blocked" ? "bad" : f.effect === "warned" ? "warn" : "none"} data-testid="effect">{EFFECT_STATE[f.effect] || f.effect}</span>{f.action && <span className="muted"> action {f.action}</span>}</td></tr>))}
          </tbody>
        </table></div>
        <details><summary>Reports ({s.reports.length})</summary>
          <ul className="plain" data-testid="reports">{s.reports.map((r) => <li key={r.id}>{r.id} from node {visible(r.node)}: {r.findings} finding(s); body node {r.bodyNodeIgnored ? `"${visible(r.bodyNode)}" ignored${r.bodyNodeDiffers ? " (differed)" : ""}` : "none"}; would have blocked {r.wouldHaveBlocked}, blocked {r.blocked}</li>)}</ul>
        </details>
        <p className="muted">Revoking the identity cuts the sensor off at once, and every finding stays attributable to the node that reported it.</p>
      </section>
      <FieldSources fields={story.fieldSources.filter((x) => /Self-hosted agent|Node taken|Findings:|Policy:|Audit mode|Scopes shadowai/.test(x.field))} />
    </div>
  );
}
