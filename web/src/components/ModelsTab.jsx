import { visible } from "../safeText";
import { AvailTag, ClaimTag, FieldSources, SourceTag } from "./Bits";

// The five deployment models (slide 40), and the backend credential modes. The sidecar row claims no behaviour.
export default function ModelsTab({ story, lab, tryPreset }) {
  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">Five deployment models <ClaimTag /> <SourceTag source="deck" /></h2>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="models">
          <thead><tr><th>Model</th><th>Example</th><th>The deck says</th><th>What the lab does</th><th>Try</th></tr></thead>
          <tbody>{story.deploymentModels.map((m) => (
            <tr key={m.id} data-testid={`model-${m.id}`}>
              <td>{visible(m.name)} {m.id === "sidecar" && <AvailTag value="in development" />}</td>
              <td>{visible(m.example)}</td><td>{visible(m.deck)}</td><td data-state={m.modelled ? "ok" : "none"}>{visible(m.lab)}</td>
              <td>{m.preset ? <button type="button" onClick={() => tryPreset(m.preset)} data-testid={`try-${m.id}`}>Mint and verify</button> : m.id === "stored-key" ? <button type="button" onClick={() => tryPreset(null, "identities")} data-testid="try-stored-key">See the keys</button> : "not modelled"}</td>
            </tr>))}
          </tbody>
        </table></div>
        {lab.readOnly && <p className="muted">The Try buttons open the Verify tab with that preset; switch to Live to mint and verify it.</p>}
      </section>
      <section className="panel">
        <h2 className="panel__title">Backend isolation: what a backend receives <ClaimTag /></h2>
        <p className="muted">The token stops at the gateway and is never forwarded. Backends receive the application's own configured credential: static, per-user from the vault, or OAuth. The credential is shown masked: the lab holds none.</p>
        <div className="scroll"><table className="tbl" data-testid="auth-modes"><thead><tr><th>Mode</th><th>Meaning</th></tr></thead><tbody>{story.backendAuthModes.map((m) => <tr key={m.mode}><td><code>{m.mode}</code></td><td>{visible(m.text)}</td></tr>)}</tbody></table></div>
        <p className="muted" data-testid="token-pass-note">Not shown: the console swagger also lists an application AuthMode <code>token-pass</code> that forwards the verified inbound workload assertion unchanged (schema only). The deck says the token is never forwarded; the lab shows the deck's behaviour and flags the difference on the Talk track tab.</p>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="backends"><thead><tr><th>Backend</th><th>Service</th><th>Auth mode</th><th>Credential it receives</th></tr></thead>
          <tbody>{(lab.state?.backends || []).map((b) => <tr key={b.id}><td>{visible(b.label)}<br /><code>{visible(b.url)}</code></td><td>{b.service}</td><td>{b.authMode}</td><td>{visible(b.credential)}</td></tr>)}</tbody></table></div>
      </section>
      <FieldSources fields={story.fieldSources.filter((x) => /Backends receive|Pinned|Platform/.test(x.field))} />
    </div>
  );
}
