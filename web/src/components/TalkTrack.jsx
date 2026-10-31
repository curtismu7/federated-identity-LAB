import { visible } from "../safeText";
import { AvailTag, ClaimTag, SourceTag } from "./Bits";

export default function TalkTrack({ story }) {
  return (
    <div className="stack">
      <div className="panel">
        <h2 className="panel__title">Talk track <ClaimTag /></h2>
        <ol className="talk" data-testid="talk-track">
          {story.talkTrack.map((t) => <li key={t.id}><h3>{t.title}</h3><p>{t.say}</p></li>)}
        </ol>
      </div>
      <section className="panel" data-testid="discrepancies">
        <h2 className="panel__title">What the deck, the schema and our own tests leave unresolved <ClaimTag /></h2>
        <p className="muted">Shown, not resolved.</p>
        <ul className="plain">{story.discrepancies.map((d) => <li key={d.id} data-testid={`disc-${d.id}`}><strong>{visible(d.title)}.</strong> {visible(d.text)}</li>)}</ul>
      </section>
      <section className="panel" data-testid="measured">
        <h2 className="panel__title">What we measured ourselves <SourceTag source="measured" /></h2>
        <ul className="plain">{story.measured.map((m) => <li key={m.id}>{visible(m.note)}</li>)}</ul>
      </section>
      <section className="panel" data-testid="availability">
        <h2 className="panel__title">Availability and what the lab models</h2>
        <ul className="plain">{story.availability.map((a) => <li key={a.capability}><strong>{visible(a.capability)}</strong> <AvailTag value={a.availability} />: {visible(a.lab)}</li>)}</ul>
        <h3 className="panel__sub">Not demonstrated</h3>
        <ul className="plain">{story.notDemonstrated.map((n) => <li key={n}>{visible(n)}</li>)}</ul>
      </section>
    </div>
  );
}
