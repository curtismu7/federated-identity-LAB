import { useEffect, useMemo, useRef } from "react";
import { visible } from "../safeText";
import { decodeToken, labTime, tamper } from "../token";
import { ClaimTag, FieldSources, Hops, Json, Outcome, SourceTag, StatusTag, Verdict, VerifySteps } from "./Bits";

const ISSUER_CHOICES = [["kube", "Kubernetes API server"], ["github", "GitHub Actions"], ["gitlab", "GitLab CI"], ["spire", "SPIFFE/SPIRE server"], ["private", "Private issuer"], ["attacker", "Attacker (no registered issuer)"]];

const blank = () => ({ issuer: "kube", alg: "RS256", kidMode: "current", kid: "", generation: "", iss: "", issOmit: false, sub: "", aud: "", iat: "0", iatOmit: false, exp: "3600", expOmit: false, nbf: "", extra: "" });

const toLines = (extra) => Object.entries(extra || {}).map(([k, v]) => `${k}=${v}`).join("\n");
// A preset's mint arguments as the editor's fields.
export function fieldsFromPreset(m) {
  const c = m.claims || {}; const t = m.times || {};
  return {
    ...blank(), issuer: m.issuer, alg: m.alg || "RS256", kidMode: m.kid === null ? "omit" : m.kid ? "override" : "current", kid: m.kid || "", generation: m.generation === undefined ? "" : String(m.generation),
    iss: typeof c.iss === "string" ? c.iss : "", issOmit: c.iss === null, sub: typeof c.sub === "string" ? c.sub : "", aud: Array.isArray(c.aud) ? c.aud.join("|") : typeof c.aud === "string" ? c.aud : "",
    iat: t.iat === undefined || t.iat === null ? "0" : String(t.iat), iatOmit: t.iat === null, exp: t.exp === undefined || t.exp === null ? "3600" : String(t.exp), expOmit: t.exp === null, nbf: t.nbf === undefined || t.nbf === null ? "" : String(t.nbf), extra: toLines(c.extra),
  };
}
const parseValue = (v) => (v === "true" ? true : v === "false" ? false : v !== "" && Number.isFinite(Number(v)) ? Number(v) : v);
// The editor's fields as the mint operation's arguments.
export function mintFromFields(f) {
  const claims = {};
  if (f.issOmit) claims.iss = null; else if (f.iss) claims.iss = f.iss;
  if (f.sub !== "") claims.sub = f.sub;
  if (f.aud !== "") claims.aud = f.aud.includes("|") ? f.aud.split("|").map((x) => x.trim()) : f.aud;
  const extra = {};
  for (const line of f.extra.split("\n")) { const i = line.indexOf("="); if (i > 0) extra[line.slice(0, i).trim()] = parseValue(line.slice(i + 1).trim()); }
  if (Object.keys(extra).length) claims.extra = extra;
  const times = { iat: f.iatOmit ? null : Number(f.iat), exp: f.expOmit ? null : Number(f.exp) };
  if (f.nbf !== "") times.nbf = Number(f.nbf);
  const m = { issuer: f.issuer, alg: f.alg, claims, times };
  if (f.kidMode === "omit") m.kid = null; else if (f.kidMode === "override") m.kid = f.kid;
  if (f.kidMode === "current" && f.generation !== "") m.generation = Number(f.generation);
  return m;
}

// Mock mode: the scripted scenarios, read from a generated table. Each step shows its result; a verification shows all fifteen steps.
function Scenarios({ lab, scenarioId, setScenarioId }) {
  const sc = lab.scenario;
  if (!sc) return null;
  return (
    <section className="panel" data-testid="scenarios">
      <h2 className="panel__title">Scripted scenarios (Mock) <ClaimTag /> <SourceTag source="invented" label="generated from the lab's engine" /></h2>
      <label>Scenario<select value={scenarioId || sc.id} onChange={(e) => setScenarioId(e.target.value)} data-testid="scenario-pick">{lab.scenarios.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}</select></label>
      <p className="muted" data-testid="scenario-say">{sc.say}</p>
      <ol className="plain" data-testid="scenario-steps">
        {sc.steps.map((st, i) => (
          <li key={i}>
            {st.say} <StatusTag status={st.ok ? "ok" : "refused"} /> {!st.ok && <code>{st.code}</code>}
            {st.result?.steps && <details><summary>The fifteen steps</summary><VerifySteps steps={st.result.steps} />{st.result.forwarded && <Json value={st.result.forwarded} label="backend request" />}</details>}
            {st.op === "mint" && st.result?.claims && <details><summary>Decoded claims (the token itself is not stored in a table)</summary><Json value={{ header: st.result.header, claims: st.result.claims }} label="decoded" /></details>}
          </li>
        ))}
      </ol>
    </section>
  );
}

export default function VerifyTab({ story, lab, scenarioId, setScenarioId, pending, ui, setUi }) {
  const ro = lab.readOnly; const s = lab.state;
  // The editor's state lives in App, so it survives a visit to another tab.
  useEffect(() => { if (!ui) setUi({ presetId: "k8s-right", f: fieldsFromPreset(story.presets[0].mint), identityId: "fid-001", service: "mcp", token: "", result: null, minted: null }); }, [ui]); // eslint-disable-line react-hooks/exhaustive-deps
  const seq = useRef(0);
  const cur = ui || { presetId: "k8s-right", f: blank(), identityId: "fid-001", service: "mcp", token: "", result: null, minted: null };
  const { presetId, f, identityId, service, token, result, minted } = cur;
  const patch = (o) => setUi((x) => ({ ...(x || cur), ...o }));
  const setF = (fn) => setUi((x) => { const b = x || cur; return { ...b, f: typeof fn === "function" ? fn(b.f) : fn }; });
  const setIdentityId = (v) => patch({ identityId: v }); const setService = (v) => patch({ service: v }); const setToken = (v) => patch({ token: v });
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));
  const load = (id) => { const p = story.presets.find((x) => x.id === id); if (!p) return; patch({ presetId: id, f: fieldsFromPreset(p.mint), identityId: p.identityId, service: p.service, token: "", result: null, minted: null }); };
  useEffect(() => { if (pending?.id && ui) load(pending.id); }, [pending, !!ui]); // eslint-disable-line react-hooks/exhaustive-deps
  const decoded = useMemo(() => decodeToken(token), [token]);
  const identities = s?.identities || [];
  const now = s?.clock.now;

  const mint = async () => {
    const mine = ++seq.current;
    const r = await lab.act("POST", "/api/tokens/mint", { mint: mintFromFields(f) });
    if (mine !== seq.current) return;
    if (r.body?.ok) patch({ token: r.body.result.mintedToken, minted: { label: r.body.result.label, notes: r.body.result.notes }, result: null }); else patch({ minted: { error: r.body?.error, detail: r.body?.detail } });
  };
  const verify = async () => {
    const mine = ++seq.current;
    patch({ result: null }); // the previous verdict is cleared, so a stale answer is never mistaken for the new one
    const r = await lab.act("POST", "/api/verify", { verify: { token, service, ...(identityId ? { identityId } : {}) } });
    if (mine !== seq.current) return;
    const b = r.body || {};
    patch({ result: b.result ? { ...b.result, hops: b.hops, traceId: b.traceId, truncated: b.hopsTruncated } : { ok: false, code: b.error, detail: b.detail, status: r.status, steps: null } });
  };

  return (
    <div className="stack">
      {ro && <p className="muted" data-testid="read-only-note">Mock only reads tables: switch to Live to mint and verify your own tokens (real RS256 on the lab's own keys).</p>}
      {ro && <Scenarios lab={lab} scenarioId={scenarioId} setScenarioId={setScenarioId} />}
      {!ro && s && (
        <>
          <section className="panel" data-testid="editor">
            <h2 className="panel__title">Token editor <ClaimTag /> <SourceTag source="invented" label="lab-invented steps and reasons" /></h2>
            <p className="muted">Pick a preset, or edit any claim, then <strong>Mint</strong>: a mock issuer signs it (a real RSA signature, good only in this lab). Edit or <strong>Tamper</strong> the token text, then <strong>Verify</strong>: the lab's gateway checks it step by step and names the exact reason. Times are seconds from the lab clock ({labTime(now)} UTC). A real gateway's refusals are thin (measured, our note); this one explains itself.</p>
            <div className="filters">
              <label>Preset<select value={presetId} onChange={(e) => load(e.target.value)} data-testid="preset">{story.presets.map((p) => <option key={p.id} value={p.id}>{p.title}</option>)}</select></label>
              <label>Present it to<select value={identityId} onChange={(e) => setIdentityId(e.target.value)} data-testid="identity-under-test"><option value="">Let the gateway find the identity (issuer and subject)</option>{identities.map((i) => <option key={i.id} value={i.id}>{visible(i.name)} ({i.id})</option>)}</select></label>
              <label>Service<select value={service} onChange={(e) => setService(e.target.value)} data-testid="service"><option value="mcp">MCP server</option><option value="a2a">Peer agent (A2A)</option><option value="llm">LLM provider</option></select></label>
            </div>
            <div className="filters">
              <label>Signed by<select value={f.issuer} onChange={set("issuer")} data-testid="f-issuer">{ISSUER_CHOICES.map(([id, n]) => <option key={id} value={id}>{n}</option>)}</select></label>
              <label>Algorithm (alg)<select value={f.alg} onChange={set("alg")} data-testid="f-alg">{story.mintAlgs.map((a) => <option key={a} value={a}>{a}</option>)}</select></label>
              <label>Key (kid)<select value={f.kidMode} onChange={set("kidMode")} data-testid="f-kidmode"><option value="current">the issuer's current key</option><option value="override">a kid I type</option><option value="omit">no kid</option></select></label>
              {f.kidMode === "override" && <label>kid<input value={f.kid} onChange={set("kid")} data-testid="f-kid" /></label>}
              {f.kidMode === "current" && <label>Key generation (blank = current)<input value={f.generation} onChange={set("generation")} inputMode="numeric" data-testid="f-generation" /></label>}
            </div>
            <div className="filters">
              <label>iss (blank = the issuer's)<input value={f.iss} onChange={set("iss")} disabled={f.issOmit} data-testid="f-iss" /></label>
              <label className="check"><input type="checkbox" checked={f.issOmit} onChange={set("issOmit")} data-testid="f-iss-omit" /> omit iss</label>
              <label>sub (blank = omit)<input value={f.sub} onChange={set("sub")} data-testid="f-sub" /></label>
              <label>aud (blank = omit; several with |)<input value={f.aud} onChange={set("aud")} data-testid="f-aud" /></label>
            </div>
            <div className="filters">
              <label>iat (seconds from now)<input value={f.iat} onChange={set("iat")} disabled={f.iatOmit} inputMode="numeric" data-testid="f-iat" /></label>
              <label className="check"><input type="checkbox" checked={f.iatOmit} onChange={set("iatOmit")} data-testid="f-iat-omit" /> omit iat</label>
              <label>exp (seconds from now)<input value={f.exp} onChange={set("exp")} disabled={f.expOmit} inputMode="numeric" data-testid="f-exp" /></label>
              <label className="check"><input type="checkbox" checked={f.expOmit} onChange={set("expOmit")} data-testid="f-exp-omit" /> omit exp</label>
              <label>nbf (blank = omit)<input value={f.nbf} onChange={set("nbf")} inputMode="numeric" data-testid="f-nbf" /></label>
            </div>
            <label>Extra claims (one name=value per line; the lab's flat claim names)<textarea rows={4} value={f.extra} onChange={set("extra")} data-testid="f-extra" /></label>
            <p><button type="button" className="primary" disabled={lab.busy} onClick={mint} data-testid="mint">Mint</button></p>
            {minted?.error && <p className="field-error" role="alert" data-testid="mint-error">Refused ({minted.error}): {visible(minted.detail || "")}</p>}
            {minted?.label && <p className="muted" data-testid="mint-label">{minted.label}{minted.notes ? `; ${minted.notes}` : ""}</p>}
          </section>

          <section className="panel" data-testid="token-panel">
            <h2 className="panel__title">The token <SourceTag source="invented" label="mock-issued, labelled" /></h2>
            <label>Token (edit it freely; this is what the gateway will be given)<textarea rows={5} value={token} onChange={(e) => setToken(e.target.value)} spellCheck={false} data-testid="token" /></label>
            <p className="toggles">
              <button type="button" onClick={() => setToken(tamper(token))} disabled={!decoded} data-testid="tamper">Tamper (change the subject, keep the signature)</button>
              <button type="button" className="primary" disabled={lab.busy || !token} onClick={verify} data-testid="verify">Verify</button>
            </p>
            {token && !decoded && <p className="muted" data-testid="not-decodable">That text does not decode as a JWT; the gateway will refuse it at the parse step.</p>}
            {decoded && (
              <div className="cols" data-testid="decoded">
                <div><h3 className="panel__sub">Header</h3><Json value={decoded.header} label="header" /></div>
                <div><h3 className="panel__sub">Claims</h3><Json value={decoded.payload} label="claims" />
                  <p className="muted" data-testid="decoded-times">{["iat", "nbf", "exp"].filter((k) => typeof decoded.payload[k] === "number").map((k) => `${k} ${labTime(decoded.payload[k])}`).join("; ")}{typeof decoded.payload.exp === "number" && typeof decoded.payload.iat === "number" ? `; lifetime (exp minus iat) ${decoded.payload.exp - decoded.payload.iat} s` : ""}</p></div>
              </div>
            )}
          </section>

          {result && (
            <section className="panel" aria-label="Verification" data-testid="result" data-state={result.ok ? "ok" : "bad"}>
              <h2 className="panel__title">Verification <ClaimTag /></h2>
              <Verdict r={result} />
              {result.steps && <VerifySteps steps={result.steps} />}
              {result.refresh?.attempted && <p className="muted" data-testid="refresh-note">Key set refreshed on an unknown kid: {result.refresh.ok ? "the issuer answered" : "the issuer did not answer, the last known good set was kept"}.</p>}
              {result.ok && (
                <div data-testid="allowed-detail">
                  <p>Principal: <strong>{visible(result.principal)}</strong> (a key owned by an identity, not a borrowed person). Attributed to the deployment: <strong data-testid="deployment">{visible(result.deployment)}</strong>.</p>
                  {result.forwarded && (
                    <>
                      <h3 className="panel__sub">What the backend receives (backend isolation, deck claim)</h3>
                      <p className="muted">The token stops at the gateway. The backend gets the application's own credential ({result.forwarded.authMode}), masked here because the lab holds none. Inbound token forwarded: <strong data-testid="forwarded-flag">{String(result.forwarded.inboundTokenForwarded)}</strong>.</p>
                      <Json value={result.forwarded.request} label="outbound request" testId="forwarded" />
                    </>
                  )}
                </div>
              )}
              {result.hops && <Hops hops={result.hops} traceId={result.traceId} truncated={result.truncated} />}
            </section>
          )}
          <Outcome last={lab.last} prefix="/api/tokens" />
        </>
      )}
      <FieldSources fields={story.fieldSources.filter((x) => /Issuer and subject|Pinned extra|Expiry required|iat required|asymmetric|Gateway refusal|AllowAnySubject|Backends receive|Revoking/.test(x.field))} />
    </div>
  );
}
