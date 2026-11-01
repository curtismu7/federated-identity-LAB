import { useEffect, useState } from "react";
import PatternDiagram from "./PatternDiagram";
import { getJson } from "../api";

const NAMES = [["federated-identity-flow", "Federated Identity flow"], ["verification-steps", "Verification steps"], ["self-hosted-agent", "Self-Hosted Agent"]];

// Diagrams are diagram-studio/1 data loaded by name from the server (rule 17); nothing is drawn from hand-built nodes here.
export default function DiagramTab({ vertical, resetSignal }) {
  const [pattern, setPattern] = useState(null);
  const [error, setError] = useState(null);
  const [tries, setTries] = useState(0);
  const [name, setName] = useState("federated-identity-flow");
  useEffect(() => {
    let live = true; // a late answer for a diagram or vertical the visitor has already left is dropped
    setPattern(null); setError(null); // a failure belongs to the diagram that failed: choosing another, or trying again, starts clean
    getJson(`/api/diagram?vertical=${encodeURIComponent(vertical)}&name=${name}`).then((j) => { if (live) setPattern(j); }, (e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [vertical, name, tries]);
  return (
    <>
      <div className="seg" role="group" aria-label="Diagram">
        {NAMES.map(([id, label]) => <button key={id} type="button" aria-pressed={name === id} onClick={() => setName(id)} data-testid={`dg-${id}`}>{label}</button>)}
      </div>
      {error ? <p className="field-error" role="alert" data-testid="diagram-error">Could not load the diagram ({error}). <button type="button" onClick={() => setTries((t) => t + 1)} data-testid="diagram-retry">Try again</button></p>
        : pattern ? <PatternDiagram key={name} pattern={pattern} resetSignal={resetSignal} /> : <p className="muted">Loading...</p>}
    </>
  );
}
