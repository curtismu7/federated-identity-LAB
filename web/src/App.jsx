import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import fs from "node:fs";
import ShelfLink from "./components/ShelfLink";
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
const TAIL = "Every product claim is a Ping release claim, UNVERIFIED on our tenant (release 2026-11-02). Nothing here calls a real tenant, gateway, issuer or cluster.";
export const BANNER_UNKNOWN = `SIMULATED, MOCK or LIVE mode (loopback only, no outbound network). ${TAIL}`;
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
  const tabsRef = useRef(null);
  const lab = useLab({ mode, vertical, scenario: scenarioId });
  // One number per (vertical, mode) choice, new on every change (even back to an earlier choice): work started under one choice can never land in a later one.
  const ctxGen = useMemo(() => ++CONTEXT_COUNTER, [vertical, mode]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { getJson("/api/info").then((i) => setModeState((m) => m || i.mode || i.source), () => setModeState((m) => m || "mock")); }, []);
  useEffect(() => {
    let live = true; // a late story for a vertical the visitor has already left is dropped
    getJson(`/api/story?vertical=${encodeURIComponent(vertical)}`).then((j) => { if (live) { setStory(j); setError(null); } }, (e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [vertical]);
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

  // Keep the active tab fully in view in the scrolling tab strip (375px).
  useEffect(() => {
    const strip = tabsRef.current; const el = document.getElementById(`tab-${tab}`);
    if (!strip || !el) return;
    const left = el.offsetLeft - strip.offsetLeft;
    if (left < strip.scrollLeft || left + el.offsetWidth > strip.scrollLeft + strip.clientWidth) strip.scrollLeft = Math.max(0, left - 8);
  }, [tab]);

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

  const onKeyTab = (e, i) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };

  const banner = story && mode ? story.banner[mode] : BANNER_UNKNOWN;
  const ready = story && mode;
  // Every tab draws only when the story, the lab state and the chosen vertical and mode all agree: a late answer for the previous vertical never meets the new one.
  const settled = !!(story && lab.state && story.vertical === vertical && lab.data?.vertical === vertical && lab.data?.mode === mode);
  const props = { story, mode, vertical, lab };
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header>
        <p className="banner" role="status" data-state={mode === "live" ? "live" : "mock"} data-testid="banner">{banner}</p>
        {modeError && <p className="app-error" role="alert" data-testid="mode-error">{modeError}</p>}
        <div className="head">
          <div>
            <h1 className="head__title">Federated Identity LAB</h1>
            {!presenter && story && <p className="head__intro">{story.intro}</p>}
          </div>
          <div className="head__tools">
            <TopMenu
              mode={{ value: mode === "live" ? "real" : "mock", onChange: setMode, realAvailable: true, realHint: undefined }}
              vertical={{ value: vertical, onChange: setVertical, options: story ? story.verticals : ["finance"] }}
              theme={{ value: theme, onChange: pickTheme }}
              fontSize={{ value: fontStep, onChange: setFontStep }}
              present={{ active: presenter, onToggle: () => setPresenter((v) => !v) }}
              help={{ href: "https://github.com/curtismu7/federated-identity-LAB#readme" }}
              version={LAB_VERSION}
              onReset={reset}
              extra={<span className="chip" data-testid="mode">Mode: {mode || "..."}{mode === "live" ? " (local engine, loopback)" : mode === "mock" ? " (tables)" : ""}</span>}
            >
              <ShelfLink />
            </TopMenu>
          </div>
        </div>
      </header>
      <main>
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        <div role="tablist" aria-label="Lab sections" className="tabs" ref={tabsRef}>
          {TABS.map((t, i) => (
            <button key={t.id} id={`tab-${t.id}`} role="tab" type="button" aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} tabIndex={tab === t.id ? 0 : -1}
              onClick={() => select(t.id)} onKeyDown={(e) => onKeyTab(e, i)}>{t.label}</button>
          ))}
        </div>
        <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
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
