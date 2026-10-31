import { visible } from "../safeText";
import { ClaimTag, FieldSources, Hops, Outcome, SourceTag, StatusTag } from "./Bits";

const MOVES = [1, 5, 15, 60, 180];
const time = (iso) => (iso ? String(iso).slice(0, 19).replace("T", " ") : "-");

// Issuers and keys: the five mock issuers (each with a real RSA key and a JWKS you can rotate and take down), the lab clock, and each identity's key set.
export default function IssuersTab({ story, lab }) {
  const s = lab.state; const ro = lab.readOnly; const c = s.clock;
  const act = (id, action, extra = {}) => lab.act("POST", `/api/issuers/${id}/actions`, { action: { action, ...extra } });
  const idents = s.identities;
  return (
    <div className="stack">
      {ro && <p className="muted" data-testid="read-only-note">Mock only reads tables: switch to Live to rotate keys, take an issuer down and move the lab clock.</p>}
      <section className="panel" data-testid="clock">
        <h2 className="panel__title">The lab clock <ClaimTag /> <SourceTag source="invented" /></h2>
        <p className="lesson" data-testid="clock-now">Lab time: <strong>{time(c.at)} UTC</strong> (started {time(c.startedAt)}; moved {c.advancedMin} of {c.totalCapMin} minutes). It never reads the real time and only moves forward, by an explicit move of at most {c.perMoveCapMin} minutes. Key sets refresh every {c.refreshSeconds / 60} lab minutes as it moves.</p>
        <div className="toggles">{MOVES.map((m) => <button key={m} type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", "/api/clock", { clock: { minutes: m } })} data-testid={`advance-${m}`}>+{m} min</button>)}</div>
        <Outcome last={lab.last} prefix="/api/clock" />
      </section>

      <section className="panel">
        <h2 className="panel__title">Mock issuers <ClaimTag /></h2>
        <p className="muted">Each issuer holds an RSA key in this process's memory (never shown; only the public half is published as a JWKS) and signs the tokens you mint. Nothing is fetched from the network: every address is a <code>.example</code> name the lab resolves itself. Rotate a key and the gateway still holds the old key set until it refreshes; take the issuer down and it keeps the last known good set.</p>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="issuers">
          <thead><tr><th>Issuer</th><th>Address</th><th>State</th><th>Current key</th><th>Published now</th><th>Actions</th></tr></thead>
          <tbody>{s.issuers.map((i) => (
            <tr key={i.id} data-testid={`issuer-${i.id}`}>
              <td>{visible(i.name)}<div className="muted">{visible(i.standsFor)}</div></td>
              <td><code>{visible(i.url)}</code><br /><code>{i.jwksUri ? visible(i.jwksUri) : "no key-set address (pinned keys)"}</code></td>
              <td><StatusTag status={i.up ? "up" : "down"} /></td>
              <td><code data-testid={`kid-${i.id}`}>{i.kid}</code><div className="muted">{i.rotationsLeft} rotations left</div></td>
              <td><code>{i.published.join(", ")}</code></td>
              <td className="toggles">
                <button type="button" disabled={ro || lab.busy || i.rotationsLeft < 1} onClick={() => act(i.id, "rotate")} data-testid={`rotate-${i.id}`}>Rotate (retire the old key)</button>
                <button type="button" disabled={ro || lab.busy || i.rotationsLeft < 1} onClick={() => act(i.id, "rotate", { retireOld: false })} data-testid={`rotate-keep-${i.id}`}>Rotate (keep the old published)</button>
                {i.up ? <button type="button" disabled={ro || lab.busy} onClick={() => act(i.id, "down")} data-testid={`down-${i.id}`}>Take down</button> : <button type="button" disabled={ro || lab.busy} onClick={() => act(i.id, "up")} data-testid={`up-${i.id}`}>Bring up</button>}
              </td>
            </tr>))}
          </tbody>
        </table></div>
        <Outcome last={lab.last} prefix="/api/issuers" />
      </section>

      <section className="panel" data-testid="keysets">
        <h2 className="panel__title">Key sets the gateway holds <ClaimTag /> <SourceTag source="deck" label="deck claim: validated at creation, refreshed every fifteen minutes and on an unknown kid, last known good kept" /></h2>
        <div className="scroll"><table className="tbl tbl--wide">
          <thead><tr><th>Identity</th><th>Source</th><th>Keys held</th><th>Last attempt</th><th>Next refresh</th><th>Actions</th></tr></thead>
          <tbody>{idents.map((i) => (
            <tr key={i.id} data-testid={`keyset-${i.id}`}>
              <td>{visible(i.name)}</td>
              <td>{i.keyset.source === "pinned" ? "pinned key material" : "fetched from the issuer"}</td>
              <td><code data-testid={`held-${i.id}`}>{i.keyset.kids.join(", ")}</code></td>
              <td><StatusTag status={i.keyset.last.ok ? "ok" : "failed"} /> {visible(i.keyset.last.reason)}: {visible(i.keyset.last.detail)} <div className="muted">{time(i.keyset.last.at)}</div></td>
              <td>{i.keyset.nextRefreshAt ? time(i.keyset.nextRefreshAt) : "never (nothing to fetch)"}</td>
              <td className="toggles">
                {i.federation.jwksUri ? <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("POST", `/api/identities/${i.id}/refresh`, { refresh: {} })} data-testid={`refresh-${i.id}`}>Refresh now</button>
                  : <button type="button" disabled={ro || lab.busy} onClick={() => lab.act("PUT", `/api/identities/${i.id}`, { identity: { federation: { pinFromIssuer: story.issuers.find((x) => x.url === i.federation.issuer)?.id || "private" } } })} data-testid={`repin-${i.id}`}>Pin the issuer's current keys again</button>}
              </td>
            </tr>))}
          </tbody>
        </table></div>
        <Outcome last={lab.last} prefix="/refresh" />
        <details><summary>Refresh history</summary>
          {idents.map((i) => <div key={i.id}><h4 className="hops__title">{visible(i.name)}</h4><ul className="plain">{i.keyset.log.map((l, n) => <li key={n}>{time(l.at)}: {visible(l.reason)}: {l.ok ? "ok" : "failed"} ({l.kids.join(", ")}){l.kept ? ", last known good kept" : ""}</li>)}</ul></div>)}
        </details>
        {lab.last?.hops?.length > 0 && /issuers|refresh|clock/.test(lab.last.route) && <Hops hops={lab.last.hops} traceId={lab.last.traceId} truncated={lab.last.truncated} />}
      </section>
      <FieldSources fields={story.fieldSources.filter((x) => /Key set validated|Pinned key material|lab clock/.test(x.field))} />
    </div>
  );
}
