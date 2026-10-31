import { useState } from "react";
import { visible } from "../safeText";
import { AvailTag, ClaimTag, FieldSources, Hops, Json, Outcome, SourceTag, StatusTag } from "./Bits";

const parseClaims = (text) => {
  const out = {};
  for (const line of text.split("\n")) { const i = line.indexOf("="); if (i > 0) { const v = line.slice(i + 1).trim(); out[line.slice(0, i).trim()] = v === "true" ? true : v === "false" ? false : v !== "" && Number.isFinite(Number(v)) ? Number(v) : v; } }
  return out;
};
const claimsText = (rc) => Object.entries(rc || {}).map(([k, v]) => `${k}=${v}`).join("\n");

const blank = () => ({ name: "", description: "", platform: "kubernetes", issuerId: "kube", subject: "", audience: "", scopes: ["mcp"], cap: "0", claims: "", anySubject: false, notAfter: "", pin: false });

function IdentityForm({ story, lab, edit, onDone }) {
  const [f, setF] = useState(() => {
    if (!edit) return blank();
    const iss = story.issuers.find((i) => i.url === edit.federation.issuer);
    return { name: edit.name, description: edit.description, platform: edit.platform, issuerId: iss?.id || "kube", subject: edit.federation.subject, audience: edit.federation.audience, scopes: [...edit.scopes], cap: String(edit.federation.maxTokenLifetimeSec), claims: claimsText(edit.federation.requiredClaims), anySubject: edit.federation.allowAnySubject, notAfter: edit.notAfter, pin: !edit.federation.jwksUri };
  });
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));
  const issuer = story.issuers.find((i) => i.id === f.issuerId);
  const toggleScope = (sc) => setF((x) => ({ ...x, scopes: x.scopes.includes(sc) ? x.scopes.filter((y) => y !== sc) : [...x.scopes, sc] }));
  const submit = async () => {
    const pinned = f.pin || !issuer.jwksUri;
    const federation = { issuer: issuer.url, subject: f.subject, audience: f.audience, maxTokenLifetimeSec: Number(f.cap), requiredClaims: parseClaims(f.claims), allowAnySubject: f.anySubject, ...(pinned ? { pinFromIssuer: issuer.id } : { jwksUri: issuer.jwksUri }) };
    if (f.anySubject && f.subject === "") delete federation.subject;
    const identity = { name: f.name, description: f.description, platform: f.platform, scopes: f.scopes, notAfter: f.notAfter, federation };
    const r = edit ? await lab.act("PUT", `/api/identities/${edit.id}`, { identity }) : await lab.act("POST", "/api/identities", { identity });
    if (r.body?.ok) onDone?.();
  };
  return (
    <section className="panel" data-testid={edit ? "identity-edit" : "identity-create"}>
      <h3 className="panel__sub">{edit ? `Edit ${visible(edit.name)}` : "Create a Federated Identity"} <SourceTag source="swagger" label="fields: console swagger names (schema only)" /></h3>
      <div className="filters">
        <label>Name<input value={f.name} onChange={set("name")} data-testid="i-name" /></label>
        <label>Platform (a UI hint)<select value={f.platform} onChange={set("platform")} data-testid="i-platform">{story.platforms.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
        <label>Issuer<select value={f.issuerId} onChange={set("issuerId")} data-testid="i-issuer">{story.issuers.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}</select></label>
        <label>Subject (exact){f.anySubject ? " (ignored: any subject)" : ""}<input value={f.subject} onChange={set("subject")} data-testid="i-subject" /></label>
        <label>Audience (mandatory, exact)<input value={f.audience} onChange={set("audience")} data-testid="i-audience" /></label>
        <label>Lifetime cap, seconds (0 = default 3600)<input value={f.cap} onChange={set("cap")} inputMode="numeric" data-testid="i-cap" /></label>
        <label>Not after (UTC, blank = no expiry)<input value={f.notAfter} onChange={set("notAfter")} placeholder="2026-11-03T09:00:00Z" data-testid="i-notafter" /></label>
        <label>Description<input value={f.description} onChange={set("description")} data-testid="i-description" /></label>
      </div>
      <fieldset className="fieldset"><legend>Scopes</legend>
        {story.scopes.map((sc) => <label key={sc} className="check"><input type="checkbox" checked={f.scopes.includes(sc)} onChange={() => toggleScope(sc)} data-testid={`i-scope-${sc}`} /> {sc}</label>)}
      </fieldset>
      <label>Pinned claims (one name=value per line)<textarea rows={3} value={f.claims} onChange={set("claims")} data-testid="i-claims" /></label>
      <label className="check"><input type="checkbox" checked={f.anySubject} onChange={set("anySubject")} data-testid="i-anysubject" /> AllowAnySubject (explicit opt-in; the deck describes exact binding only)</label>
      <label className="check"><input type="checkbox" checked={f.pin || !issuer?.jwksUri} disabled={!issuer?.jwksUri} onChange={set("pin")} data-testid="i-pin" /> Pin the issuer's current public keys instead of fetching them{!issuer?.jwksUri ? " (this issuer has no key-set address)" : ""}</label>
      <p><button type="button" className="primary" disabled={lab.busy} onClick={submit} data-testid={edit ? "identity-save" : "identity-add"}>{edit ? "Save changes" : "Create identity"}</button>{edit && <button type="button" onClick={onDone} data-testid="identity-cancel">Cancel</button>}</p>
      <Outcome last={lab.last} prefix="/api/identities" />
    </section>
  );
}

export default function IdentitiesTab({ story, lab }) {
  const s = lab.state; const ro = lab.readOnly;
  const [editing, setEditing] = useState(null);
  const [keyName, setKeyName] = useState("a new key");
  const [owner, setOwner] = useState("identity:fid-001");
  const [scopes, setScopes] = useState(["mcp"]);
  const identities = s.identities;
  const editTarget = identities.find((i) => i.id === editing) || null;
  const toggleScope = (sc) => setScopes((x) => (x.includes(sc) ? x.filter((y) => y !== sc) : [...x, sc]));
  const [kind, ref] = owner.split(":");
  const createKey = (extra = {}) => lab.act("POST", "/api/keys", { key: { name: keyName, owner: { kind, ref }, scopes, ...extra } });
  const ownerChoices = [...identities.map((i) => [`identity:${i.id}`, `identity: ${i.name}`]), ...s.people.map((p) => [`human:${p.id}`, `person: ${p.id}`])];
  const people = s.people;
  const storedKeys = s.keys.filter((k) => k.auth === "stored");

  return (
    <div className="stack">
      {ro && <p className="muted" data-testid="read-only-note">Mock only reads tables: switch to Live to create, edit, revoke or remove identities and keys.</p>}
      <section className="panel">
        <h2 className="panel__title">Federated Identity <ClaimTag /> <AvailTag value="GA (slide tag)" /></h2>
        <p className="lesson">Platform-issued short-lived identity for agents: nothing long-lived is stored in the workload. One identity binds <strong>one issuer, one subject and one audience, exactly</strong>, with an <strong>enforced lifetime</strong> (default one hour), optional <strong>pinned claims</strong>, and a <strong>key set</strong> the gateway validates, refreshes and keeps through outages.</p>
        <p className="muted" data-testid="naming-note"><strong>Naming.</strong> Federated Identity is the new display name of Non-Human Identity (deck slide 35). The console API object is <strong>still</strong> <code>NonHumanIdentity</code> at <code>/v1/nonhumanidentities</code> (console swagger, 2026-10-31, schema only). Slide 57 of the deck still says "Non-Human Identity": we follow slide 35 and flag the inconsistency. Self-Hosted Agents is the new name of "NHI Agents Discovery and Enforcement".</p>
        <p className="muted" data-testid="mcp-note"><strong>What we measured, and what we did not.</strong> The deck says Federated Identity is accepted across the MCP and LLM gateways with identical verification. Our own earlier test of the MCP path did not prove it (measured, our note, 2026-10-21: 401 on both routes, no accepted or rejected line logged). The lab implements the deck's claim and proves nothing about the product.</p>
        <details><summary>The deck's nine rows for this feature (slide 40)</summary>
          <ul className="plain" data-testid="claims">{story.claims.filter((c) => c.slide === 40).map((c) => <li key={c.id}>{c.claim} <SourceTag source="deck" /></li>)}</ul>
        </details>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="identities">
          <caption>Identities ({identities.length} of {s.limits.identities})</caption>
          <thead><tr><th>Name</th><th>State</th><th>Issuer and subject (exact)</th><th>Audience</th><th>Lifetime cap</th><th>Pinned claims</th><th>Scopes</th><th>Key set</th><th>Actions</th></tr></thead>
          <tbody>{identities.map((i) => (
            <tr key={i.id} data-testid={`identity-${i.id}`}>
              <td>{visible(i.name)}<br /><code>{i.id}</code> <span className="tag" data-state="none">{i.kind === "self-hosted-agent" ? "self-hosted agent" : i.platform}</span></td>
              <td><StatusTag status={i.enabled ? "enabled" : "disabled"} />{i.notAfter && <div className="muted">until {i.notAfter}</div>}</td>
              <td><code>{visible(i.federation.issuer)}</code><br /><code>{i.federation.allowAnySubject ? "(any subject)" : visible(i.federation.subject)}</code></td>
              <td><code>{visible(i.federation.audience)}</code></td>
              <td>{i.federation.effectiveCapSec} s{i.federation.maxTokenLifetimeSec ? "" : " (default)"}</td>
              <td>{Object.keys(i.federation.requiredClaims).length ? Object.entries(i.federation.requiredClaims).map(([k, v]) => <div key={k}><code>{visible(k)}={visible(String(v))}</code></div>) : "none"}</td>
              <td>{i.scopes.join(", ")}</td>
              <td>{i.keyset.source === "pinned" ? "pinned" : "fetched"}: {i.keyset.kids.join(", ")}</td>
              <td className="toggles">
                {i.enabled ? <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${i.id}`, { identity: { enabled: false } })} data-testid={`revoke-${i.id}`}>Revoke</button>
                  : <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${i.id}`, { identity: { enabled: true } })} data-testid={`restore-${i.id}`}>Restore</button>}
                <button type="button" disabled={ro} onClick={() => setEditing(i.id)} data-testid={`edit-${i.id}`}>Edit</button>
                <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", `/api/identities/${i.id}/remove`, { remove: {} })} data-testid={`remove-${i.id}`}>Remove</button>
              </td>
            </tr>))}
          </tbody>
        </table></div>
        <p className="muted">Revoking sets <code>Enabled</code> to false (the console swagger calls it the only kill switch): the very next request from that workload is refused. The deck says "immediately"; we did not measure revocation on our tenant (app and policy edits took about four minutes: measured, our note).</p>
        <Outcome last={lab.last} prefix="/api/identities" />
      </section>

      {!ro && (editTarget ? <IdentityForm key={editTarget.id} story={story} lab={lab} edit={editTarget} onDone={() => setEditing(null)} /> : <IdentityForm story={story} lab={lab} />)}

      <section className="panel" data-testid="keys-panel">
        <h2 className="panel__title">A key owned by an identity, or by a person <ClaimTag /></h2>
        <p className="muted">Slide 40: an agent access key can name a Federated Identity as the principal it acts as, instead of borrowing a human owner, so a fully autonomous agent gets a real principal in audit and policy; that identity supplies the verification material. In the console swagger the key field is <code>CustodianRef</code>, which names a <code>NonHumanIdentity</code> (schema only). An identity with no key behind it authenticates nobody (measured, our note).</p>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="keys">
          <caption>Keys ({s.keys.length} of {s.limits.keys})</caption>
          <thead><tr><th>Key</th><th>Principal (who it acts as)</th><th>Authenticates by</th><th>Scopes (effective)</th><th>State</th><th>Actions</th></tr></thead>
          <tbody>{s.keys.map((k) => (
            <tr key={k.id} data-testid={`key-${k.id}`}>
              <td>{visible(k.name)}<br /><code>{k.id}</code></td>
              <td data-testid={`principal-${k.id}`}>{visible(k.principalLabel)}</td>
              <td>{k.auth === "stored" ? "a stored secret (a standing secret)" : "a platform-issued token, verified per request"}</td>
              <td>{k.effectiveScopes.join(", ") || "none"}{k.scopes.length !== k.effectiveScopes.length ? ` (key asks for ${k.scopes.join(", ")})` : ""}</td>
              <td><StatusTag status={k.enabled ? "enabled" : "revoked"} />{k.ownerMissing && <span className="tag" data-state="bad">identity removed</span>}</td>
              <td className="toggles">
                <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/keys/${k.id}`, { key: { enabled: !k.enabled } })} data-testid={`key-toggle-${k.id}`}>{k.enabled ? "Revoke" : "Enable"}</button>
                <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", `/api/keys/${k.id}/remove`, { remove: {} })} data-testid={`key-remove-${k.id}`}>Remove</button>
              </td>
            </tr>))}
          </tbody>
        </table></div>
        <h3 className="panel__sub">Create a key</h3>
        <div className="filters">
          <label>Name<input value={keyName} onChange={(e) => setKeyName(e.target.value)} data-testid="k-name" /></label>
          <label>Owner<select value={owner} onChange={(e) => setOwner(e.target.value)} data-testid="k-owner">{ownerChoices.map(([v, t]) => <option key={v} value={v}>{visible(t)}</option>)}</select></label>
        </div>
        <fieldset className="fieldset"><legend>Scopes</legend>{["mcp", "a2a", "llm", "shadowai:write", "policy:read"].map((sc) => <label key={sc} className="check"><input type="checkbox" checked={scopes.includes(sc)} onChange={() => toggleScope(sc)} data-testid={`k-scope-${sc}`} /> {sc}</label>)}</fieldset>
        <p className="toggles">
          <button type="button" className="primary" disabled={ro || lab.busy} onClick={() => createKey()} data-testid="key-add">Create key</button>
          <button type="button" disabled={ro || lab.busy || kind !== "identity"} onClick={() => createKey({ ownFederation: true })} data-testid="key-both-federation">Try: the key also carries its own workload identity</button>
          <button type="button" disabled={ro || lab.busy || kind !== "identity"} onClick={() => createKey({ userRef: people[0].id })} data-testid="key-both-person">Try: the key also names a person</button>
        </p>
        <p className="muted">The last two are refused by the console (measured, our note, 2026-10-21): the two forms are mutually exclusive, and the owner and the user reference must not be different principals. Narrowing only: a key's scopes must be within its identity's (lab reading).</p>
        <Outcome last={lab.last} prefix="/api/keys" />

        <h3 className="panel__sub">The contrast: a stored key that borrows a person</h3>
        <p className="muted">A stored key is a standing secret owned by a person. If that person's account goes inactive the key stops (measured, our note); a key owned by an identity is not tied to anyone's account. The lab never shows a stored secret.</p>
        <div className="toggles">
          {people.map((p) => <button key={p.id} type="button" aria-pressed={p.active} disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/people/${p.id}`, { person: { active: !p.active } })} data-testid={`person-${p.id}`}>{visible(p.id)}: {p.active ? "active" : "inactive"} (click to toggle)</button>)}
        </div>
        {storedKeys.map((k) => (
          <p key={k.id} className="toggles">Call with {visible(k.name)}:{" "}
            {["mcp", "a2a", "llm"].map((svc) => <button key={svc} type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", `/api/keys/${k.id}/stored-call`, { call: { service: svc } })} data-testid={`stored-${k.id}-${svc}`}>{svc}</button>)}</p>
        ))}
        <Outcome last={lab.last} prefix="/stored-call" />
        {lab.last?.route?.includes("stored-call") && lab.last.result && <Json value={{ principal: lab.last.result.principal, forwarded: lab.last.result.forwarded?.request }} label="stored key call" testId="stored-result" />}
        {lab.last?.hops?.length > 0 && lab.last.route.includes("/keys") && <Hops hops={lab.last.hops} traceId={lab.last.traceId} truncated={lab.last.truncated} />}
      </section>
      <FieldSources fields={story.fieldSources.filter((x) => /Federated Identity is|imodelNonHuman|modelAgentWorkload|Pinned|A key owned|Key scopes|Scopes shadow/.test(x.field))} />
    </div>
  );
}
