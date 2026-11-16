import { useCallback, useEffect, useMemo, useState } from "react";
import fs from "node:fs";
import ShelfLink from "./components/ShelfLink";
import VerifyMark from "./components/VerifyMark.jsx";
import IdentitiesTab from "./components/IdentitiesTab";
import VerifyTab from "./components/VerifyTab";
import IssuersTab from "./components/IssuersTab";
import ModelsTab from "./components/ModelsTab";
import SensorsTab from "./components/SensorsTab";
import AuditTab from "./components/AuditTab";
import DiagramTab from "./components/DiagramTab";
import TalkTrack from "./components/TalkTrack";
import LastAction from "./components/LastAction";
import ErrorBoundary from "./components/ErrorBoundary";
import useLab from "./hooks/useLab";
import TopMenu, { applyFontSize } from "./top-menu/TopMenu.jsx";
import { getJson, postJson, resetWorkspace } from "./api";
import PrivilegeCheck from "./privilege-check/PrivilegeCheck.jsx";
import GatewayCheckTrace from "./components/GatewayCheckTrace";

export const TABS = [
  { id: "identities", label: "Federated Identity" },
  { id: "verify", label: "Verify" },
  { id: "issuers", label: "Issuers and keys" },
  { id: "models", label: "Deployment models" },
  { id: "sensors", label: "Self-Hosted Agents" },
  { id: "audit", label: "Audit" },
  { id: "diagram", label: "Diagram" },
  { id: "talk", label: "Talk track" },
];
// The banner is never blank and never claims one mode before it knows: until the story answers it says both, honestly.
const TAIL = "Every product claim is a Ping release claim, UNVERIFIED on our tenant (release 2026-11-02). Nothing else touches a tenant, gateway, issuer or cluster.";
export const BANNER_UNKNOWN = `SIMULATED, MOCK or LIVE mode: the lab's own engine is loopback only. The Privilege gateway check goes out only in Real mode, and only when run with a gateway configured. ${TAIL}`;
const WRITE_TABS = ["identities", "verify", "issuers", "sensors", "audit"];

const tabFromHash = () => { const h = window.location.hash.replace("#", ""); return TABS.some((t) => t.id === h) ? h : "identities"; };

const THEME_KEY = "fedid.theme";
function initialTheme() {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "light" || t === "dark") return t; } catch { /* storage blocked */ }
  return "auto";
}

let CONTEXT_COUNTER = 0;

// Version for the TopMenu About button: read once from the lab root package.json (same source the server's health uses).
const LAB_VERSION = (() => { try { return JSON.parse(fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version || null; } catch { return null; } })();

export default function App() {
  const [vertical, setVertical] = useState("finance");
  const [story, setStory] = useState(null);
  const [mode, setModeState] = useState(null);
  const [scenarioId, setScenarioId] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState(tabFromHash());
  const [presenter, setPresenter] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [resetMsg, setResetMsg] = useState("");
  const [pending, setPending] = useState(null);
  const [verifyUi, setVerifyUi] = useState(null);
  const [gateway, setGateway] = useState(null); // the gateway card's last finished check (its onResult), which "What Privilege did" draws
  const [theme, setTheme] = useState(initialTheme);
  const [fontStep, setFontStep] = useState(() => { try { const f = localStorage.getItem("fedid.font"); return ["S", "M", "L"].includes(f) ? f : "M"; } catch { return "M"; } });
  const pickTheme = (next) => {
    try { if (next === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    setTheme(next);
  };
  // The picker only sets data-theme; the shared stylesheet does the rest ("auto" follows the system setting).
  useEffect(() => { if (theme === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => {
    applyFontSize(fontStep);
    try { localStorage.setItem("fedid.font", fontStep); } catch { /* not remembered */ }
  }, [fontStep]);
  const lab = useLab({ mode, vertical, scenario: scenarioId });
  // One number per (vertical, mode) choice, new on every change (even back to an earlier choice): work started under one choice can never land in a later one.
  const ctxGen = useMemo(() => ++CONTEXT_COUNTER, [vertical, mode]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { getJson("/api/info").then((i) => setModeState((m) => m || i.mode || i.source), () => setModeState((m) => m || "mock")); }, []);
  useEffect(() => {
    let live = true; // a late story for a vertical the visitor has already left is dropped
    getJson(`/api/story?vertical=${encodeURIComponent(vertical)}`).then((j) => { if (live) { setStory(j); setError(null); } }, (e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [vertical]);
  useEffect(() => { setGateway(null); }, [mode]); // a check from an earlier visit to Real is not shown on the next one
  useEffect(() => { setVerifyUi(null); }, [vertical, mode]); // presets carry the cast, so a new vertical (or mode) gives a new editor; answers still in flight are dropped by their context tag
  useEffect(() => {
    const on = () => setTab(tabFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  // Rule 19: switching is a server call (POST /api/mode with exactly {source}), then the data reloads so the banner,
  // mode chip and every tab reflect the mode the server answered with.
  const [modeError, setModeError] = useState(null);
  const setMode = async (m) => {
    setModeError(null);
    const source = m === "live" || m === "real" ? "real" : "mock"; // TopMenu sends the wire value "real"; the lab's internal name is "live"
    const r = await postJson("/api/mode", { source });
    if (!r.ok) { setModeError(r.body?.detail || r.body?.error || `HTTP ${r.status}`); return; }
    setModeState(r.body?.mode || m);
  };
  const select = (id) => { setTab(id); try { window.history.replaceState(null, "", `#${id}`); } catch { /* ignore */ } };
  // The Models tab's Try buttons: open Verify with that preset (or another tab).
  const tryPreset = useCallback((presetId, toTab = "verify") => { if (presetId) setPending({ id: presetId, n: Date.now() }); select(toTab); }, []);

  useEffect(() => {
    const on = (e) => {
      if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
      if (e.key === "p" || e.key === "P") setPresenter((v) => !v);
      else if (e.key === "Escape") setPresenter(false);
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);

  // Reset: the server clears this workspace's engines (identities, keys, issuers, audit, sensors, findings, the clock); the diagram goes back in place.
  const reset = useCallback(async () => {
    const ok = await resetWorkspace().catch(() => false);
    setResetSignal((n) => n + 1);
    await lab.reload();
    setResetMsg(ok ? "Reset: your workspace's identities, keys, issuers, audit log, sensors, findings and lab clock are back to the start, and the diagram is back in place." : "Reset failed on the server; the view was reloaded.");
  }, [lab.reload]); // eslint-disable-line react-hooks/exhaustive-deps

  const banner = story && mode ? story.banner[mode] : BANNER_UNKNOWN;
  const ready = story && mode;
  // Every tab draws only when the story, the lab state and the chosen vertical and mode all agree: a late answer for the previous vertical never meets the new one.
  const settled = !!(story && lab.state && story.vertical === vertical && lab.data?.vertical === vertical && lab.data?.mode === mode);
  const props = { story, mode, vertical, lab };
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header className="shell-bar">
        <span className="shell-brand">
          <span className="shell-logo" aria-hidden="true">FI</span>
          <h1>Federated Identity LAB</h1>
          <span className={`shell-badge${mode === "live" ? " shell-badge--live" : ""}`} data-testid="mode">Mode: {mode || "..."}{mode === "live" ? " (local engine, loopback)" : mode === "mock" ? " (tables)" : ""}</span>
        </span>
        <nav className="shell-nav" aria-label="Lab sections">
          {TABS.map((t) => (
            <a key={t.id} href={`#${t.id}`} aria-current={tab === t.id ? "page" : undefined}
              onClick={(e) => { e.preventDefault(); select(t.id); }}>{t.label}</a>
          ))}
        </nav>
        <TopMenu
          mode={{ value: mode === "live" ? "real" : "mock", onChange: setMode, realAvailable: true, realHint: undefined }}
          vertical={{ value: vertical, onChange: setVertical, options: story ? story.verticals : ["finance"] }}
          theme={{ value: theme, onChange: pickTheme }}
          fontSize={{ value: fontStep, onChange: setFontStep }}
          present={{ active: presenter, onToggle: () => setPresenter((v) => !v) }}
          help={{ href: "https://github.com/curtismu7/federated-identity-LAB#readme" }}
          version={LAB_VERSION}
          onReset={reset}
        >
          <ShelfLink />
          <VerifyMark id="federated-identity-lab" />
        </TopMenu>
      </header>
      <main className="page">
        <p className="banner" role="status" data-state={mode === "live" ? "live" : "mock"} data-testid="banner">{banner}</p>
        {modeError && <p className="app-error" role="alert" data-testid="mode-error">{modeError}</p>}
        {!presenter && story && <p className="page-intro">{story.intro}</p>}
        {mode === "live" && <><PrivilegeCheck onResult={setGateway} /><GatewayCheckTrace result={gateway} /></>}
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        <div id={`panel-${tab}`} className="page-panel">
          {error || lab.error ? <p className="app-error" role="alert">Could not load the lab ({error || lab.error}). Is the server running?</p> : !ready ? <p className="muted">Loading...</p> : (
            <>
              {mode === "mock" && lab.scenario && WRITE_TABS.includes(tab) && tab !== "verify" && (
                <p className="muted" data-testid="scenario-note">Showing the end of the scripted scenario "{lab.scenario.title}". Pick another on the Verify tab, or switch to Live to act yourself. Mock only reads tables.</p>
              )}
              {presenter && tab !== "talk" && (
                <aside className="presenter-say" data-testid="presenter-say" aria-label="Talk track">
                  {story.talkTrack.filter((t) => (story.presenterTalk[tab] || []).includes(t.id)).map((t) => <p key={t.id}><strong>{t.title}.</strong> {t.say}</p>)}
                </aside>
              )}
              {!settled && tab !== "diagram" && tab !== "talk" ? <p className="muted" data-testid="settling">Loading...</p> : (
                <ErrorBoundary key={`${vertical}|${mode}|${tab}`}>
                  {tab === "identities" && <IdentitiesTab key={`${vertical}|${mode}`} {...props} />}
                  {tab === "verify" && <VerifyTab key={`${vertical}|${mode}`} {...props} scenarioId={scenarioId} setScenarioId={setScenarioId} pending={pending} ui={verifyUi} setUi={setVerifyUi} ctxGen={ctxGen} />}
                  {tab === "issuers" && <IssuersTab key={`${vertical}|${mode}`} {...props} />}
                  {tab === "models" && <ModelsTab key={`${vertical}|${mode}`} {...props} tryPreset={tryPreset} />}
                  {tab === "sensors" && <SensorsTab key={`${vertical}|${mode}`} {...props} />}
                  {tab === "audit" && <AuditTab key={`${vertical}|${mode}`} {...props} />}
                </ErrorBoundary>
              )}
              {tab === "diagram" && <ErrorBoundary key={`${vertical}|d`}><DiagramTab vertical={vertical} resetSignal={resetSignal} /></ErrorBoundary>}
              {tab === "talk" && <ErrorBoundary key={`${vertical}|t`}><TalkTrack story={story} /></ErrorBoundary>}
              {mode === "live" && ["identities", "issuers", "audit", "models"].includes(tab) && <LastAction last={lab.last} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}
