// Rule 27: this lab's side of the shared run-observability panel. The vendored collector (runObservability.js) is never edited here.
//
// What a run is here. The lab's own engine makes every decision in Mock and in Live: its simulated gateway verifies a workload token in fifteen ordered
// steps, checks a stored key, takes a sensor's report and applies the sensor policy. eventsOf() turns the answer of ONE engine operation into events: it reads
// the answer the engine already gave and computes nothing a second time, and an event the engine did not produce is never shown. The same function serves the
// recorded scenarios (Mock) and the visitor's own actions (Live), so the two cannot drift apart.
//
// Mock reads the generated tables, which are read-only, so the record is built when it is asked for, from the steps the table already holds (the table itself
// is untouched, like verifyTrace.js). The time of an event is the lab clock at its step: it starts at 2026-11-02 09:00 UTC and moves only when a step moves it,
// so the steps of one scenario can share a time (their order is kept). Nothing runs when a table is read, so Mock writes no stdout line.
// Live (rule 19 Real) runs the engine on the visitor's own actions: each event is one stdout line, written when the action ran. These decisions belong to the lab's
// own simulated engine, so they are NOT a Real record: a Real record holds only what the lab RECEIVED from the Privilege gateway on the gateway check (the agent
// key's tools/list and one probe), as `response` rows, never `logged`.
//
// Stdout line: `<iso> federated-identity-lab decision step=<step> layer=<layer> actor=<who> result=<passed|stopped|unclear|no-reply> cause=<cause> [labtime=<lab clock>] run=<id>`.
// The family's matchers read words such as refused, denied, rejected, forbidden, failed, invalid, expired, mismatch, token, audience, scope and served, so steps and
// causes come from the tables below and use none of them, and the one typed field (the gateway check's caller label) has them removed. A line never holds a
// credential, a claim, a name a visitor typed or a gateway URL: it carries ids the lab wrote (fid-001, key-0006), step words and the run id. A test runs every line
// kind through the shared classify() for every product.
import crypto from 'node:crypto';
import { createMasker, createRunObservability, LAYERS } from './runObservability.js';
import { ATTACKER, ISSUER } from './catalog.js';

export const SERVICE = 'federated-identity-lab';
export const KEEP_RUNS = 5; // Real runs kept (a run is stored when it ends, so the open run is never evicted)

// Only safe characters survive, so a typed name cannot add a second key=value pair, a quote or a line.
export const lineValue = (v, n = 64) => String(v ?? '').replace(/[^A-Za-z0-9._:/@-]+/g, '_').slice(0, n) || '-';
// The panel masks emails, addresses and ids in every row, so the line masks them too (then keeps only safe characters). The words a shared matcher reads are
// removed from a typed field: a label named after one would otherwise put it in the line.
const { mask } = createMasker();
const MATCHER_WORDS = /refused|denied|rejected|forbidden|failed|invalid|expired|mismatch|token|audience|scope|served/gi;
const field = (v) => lineValue(mask(String(v ?? '')).replace(MATCHER_WORDS, '_'));
// The lab's outcomes: allowed, refused, blocked (the sensor policy's own stop) and info.
const RESULT = { allowed: 'passed', refused: 'stopped', blocked: 'stopped', info: 'unclear' };

// A recorder that throws must never break the run or the audit: the failure goes to stderr and the run goes on. Only a code (or the error's name) and a fixed
// text are written: the error's own text could carry anything (the masker does not know the shape of the agent key), so it is never logged.
export function reportFailure(where, err) {
  process.stderr.write(`[${SERVICE}] run observability: ${lineValue(where, 40)} ${lineValue(err?.code || err?.name || 'error', 40)} (the error's text is not logged)\n`);
}
export function safely(where, fn) {
  try { return fn(); } catch (err) { reportFailure(where, err); return undefined; }
}

// ---- Engine events ----------------------------------------------------------------------------------------------------------------------------
// The cause word of a verification that stopped, by the step it stopped at (the engine's fifteen step ids). Fixed words: nothing typed is ever echoed.
export const STOPPED_AT = {
  parse: 'parse', identity: 'identity', alg: 'algorithm', issuer: 'issuer', keyset: 'key-set', signature: 'signature', expiry: 'end-time', notbefore: 'start-time', issued: 'issue-time',
  lifetime: 'lifetime', audience: 'target', subject: 'subject', claims: 'pinned-claims', key: 'key', scope: 'permission',
};
// A stored key's refusal, by the engine's code.
export const KEY_TURNED_AWAY = {
  key_revoked: ['key-turned-off', 'the key is revoked'],
  owner_inactive: ['custodian-inactive', 'the person who owns the key is inactive'],
  scope_not_on_key: ['no-permission', 'the key is not scoped for that service'],
};
// The sensor policy's effect on one finding, by the engine's word: [outcome, cause, text]. Only an enforced stop is `blocked`; an audit-mode or monitoring record is information.
export const EFFECT = {
  blocked: ['blocked', 'enforced', 'enforce mode: the sensor terminates it'],
  'would-have-blocked': ['info', 'audit-only', 'audit mode: recorded, not blocked (enforce mode would block it)'],
  allowed: ['allowed', 'permitted', 'the policy allows this kind of finding'],
  monitored: ['info', 'monitored', 'the policy only monitors this kind of finding'],
  warned: ['info', 'warned', 'the policy only warns about this kind of finding'],
  'out-of-scope': ['info', 'outside-policy', 'this namespace is not in the policy\'s namespaces, so nothing was evaluated'],
  off: ['info', 'policy-off', 'the policy is off, so nothing was evaluated'],
  'no-policy': ['info', 'no-policy', 'no policy is bound to this identity'],
};
const issuerName = (id) => ISSUER[id]?.name ?? (id === ATTACKER.id ? ATTACKER.name : 'an unknown issuer');

const stopOf = (r) => {
  const i = r.steps.findIndex((x) => x.status === 'fail');
  return i < 0 ? null : { n: i + 1, of: r.steps.length, title: r.steps[i].title, id: r.steps[i].id };
};
const refreshOf = (r) => (r.refresh ? { keySetRefresh: r.refresh.attempted ? (r.refresh.ok ? 'tried-ok' : 'tried-no-answer') : 'cooled-down' } : {});

const GATEWAY = 'lab simulated gateway';
const MODEL = 'lab Federated Identity model';

// The lab's gateway verifying a workload token (the Verify tab, and the token a sensor reports with). `what` names the caller in the message.
function tokenVerdict(step, r, what) {
  const stop = stopOf(r);
  const ok = step.ok === true;
  const cause = ok ? 'accepted' : stop ? `stopped-at-${STOPPED_AT[stop.id]}` : 'no-node-claim';
  const lead = `The lab's simulated gateway ${ok ? 'accepted' : 'turned away'} ${what} for ${r.scope} (HTTP ${step.status})`;
  const message = ok ? `${lead}: all ${r.steps.length} checks passed.`
    : stop ? `${lead} at check ${stop.n} of ${stop.of}, "${stop.title}", code ${step.code}. The checks after it were not reached.`
      : `${lead}: the token passed all ${r.steps.length} checks but names no node, so the report is not taken (code ${step.code}).`;
  return { layer: 'gateway', product: GATEWAY, step: 'gateway-verdict', outcome: ok ? 'allowed' : 'refused', cause, who: r.identityId || '-', message,
    detail: { service: r.scope, status: step.status, code: step.code ?? r.code, ...(stop ? { stoppedAt: stop.n, check: stop.title } : {}), ...(r.keyId ? { key: r.keyId } : {}), reason: r.detail, ...refreshOf(r) } };
}

// The identity the gateway checked the token against: the agent's own identity (it is the same reply as the verdict, so it is information).
const identityRow = (r) => (r.identityId ? [{ layer: 'agent', product: MODEL, step: 'identity-check', outcome: 'info', cause: 'identity-found', who: r.identityId,
  message: `The lab's gateway checked the token against Federated Identity ${r.identityName} (${r.identityId}). That is the identity the verdict below is about, not a second decision.`,
  detail: { identity: r.identityId, ...(r.deployment ? { deployment: r.deployment } : {}) } }] : []);

// What the lab changed in its own model (a Privilege console action in the real product). A change is not a decision about an access.
const change = (layer, step, who, message, detail) => [{ layer, product: layer === 'person' ? 'lab roster (no sign-in)' : MODEL, step, outcome: 'info', cause: step, who, message: `${message} A change is not a decision about an access.`, detail }];
const CHANGES = {
  createIdentity: (r) => change('privilege', 'identity-created', r.identityId, `Federated Identity ${r.identityId} was created.`, { identity: r.identityId }),
  updateIdentity: (r) => change('privilege', 'identity-saved', r.identityId, `Federated Identity ${r.identityId} was saved; Enabled is now ${r.enabled}.`, { identity: r.identityId, enabled: r.enabled }),
  deleteIdentity: (r) => change('privilege', 'identity-removed', r.identityId, `Federated Identity ${r.identityId} was removed.`, { identity: r.identityId }),
  createKey: (r) => change('privilege', 'key-created', r.keyId, `Key ${r.keyId} was created.`, { key: r.keyId }),
  updateKey: (r) => change('privilege', 'key-saved', r.keyId, `Key ${r.keyId} was saved; Enabled is now ${r.enabled}.`, { key: r.keyId, enabled: r.enabled }),
  deleteKey: (r) => change('privilege', 'key-removed', r.keyId, `Key ${r.keyId} was removed.`, { key: r.keyId }),
  enrollSensor: (r) => change('privilege', 'sensor-enrolled', r.identityId, `A Kubernetes sensor was enrolled as Federated Identity ${r.identityId}, with key ${r.keyId}.`, { identity: r.identityId, key: r.keyId }),
  setPolicy: (r) => change('privilege', 'policy-set', r.identityId, `A policy in ${r.mode} mode was bound to ${r.identityId}.`, { identity: r.identityId, mode: r.mode }),
  setPerson: (r) => change('person', 'person-set', r.person, `The lab set ${r.person} ${r.active ? 'active' : 'inactive'}: a stored key that borrows this person stops working while the person is inactive.`, { person: r.person, active: r.active }),
};

function mintEvents(r) {
  return [{ layer: 'agent', product: 'lab mock issuer', step: 'issue', outcome: 'info', cause: 'issued', who: '-',
    message: `${issuerName(r.issuer)} signed a token for ${typeof r.claims?.sub === 'string' ? r.claims.sub : 'no subject'} (alg ${r.alg}). Issuing a token is not a decision, and the token itself is not shown.`,
    detail: { issuer: r.issuer, alg: r.alg, ...(typeof r.kid === 'string' ? { kid: r.kid } : {}) } }];
}

function storedKeyEvents(step, r) {
  const ok = step.ok === true;
  const [cause, why] = ok ? ['accepted', ''] : KEY_TURNED_AWAY[step.code];
  return [
    { layer: 'person', product: 'lab roster (no sign-in)', step: 'custodian', outcome: 'info', cause: 'borrowed', who: r.keyId,
      message: `Stored key ${r.keyId} acts as ${r.principal}: a stand-in for a person, because the lab has no sign-in.${step.code === 'owner_inactive' ? ' The lab holds that person as inactive.' : ''}`, detail: { key: r.keyId } },
    { layer: 'gateway', product: GATEWAY, step: 'gateway-verdict', outcome: ok ? 'allowed' : 'refused', cause, who: r.keyId,
      message: ok ? `The lab's simulated gateway accepted stored key ${r.keyId} for ${r.service} (HTTP ${step.status}): the key is on, its person is active and the service is on the key.`
        : `The lab's simulated gateway turned stored key ${r.keyId} away for ${r.service} (HTTP ${step.status}, code ${step.code}): ${why}.`,
      detail: { service: r.service, status: step.status, code: step.code, key: r.keyId } },
  ];
}

function sensorEvents(step, r) {
  const rows = [...identityRow(r), tokenVerdict(step, r, 'the sensor\'s report token')];
  if (step.ok === true) {
    for (const f of r.findings) {
      const [outcome, cause, text] = EFFECT[f.effect];
      rows.push({ layer: 'privilege', product: 'lab sensor policy', step: 'sensor-policy', outcome, cause, who: r.identityId,
        message: `The sensor policy ${outcome === 'blocked' ? 'blocked' : outcome === 'allowed' ? 'allowed' : 'recorded'} ${f.kind} ${f.name} (${f.namespace}/${f.pod}): ${text}.`,
        detail: { finding: f.id, kind: f.kind, name: f.name, namespace: f.namespace, pod: f.pod, action: f.action, effect: f.effect } });
    }
  }
  return rows;
}

// The events ONE operation produced, from its answer: { op, ok, status, code, result }. `null` means the request itself was turned away before any decision
// (a bad field, an unknown id, a cap): that begins no run and has no row. An operation that is no decision of any layer (a clock move, an issuer's key rotation,
// a key-set refresh) is an empty list.
export function eventsOf(step) {
  if (step.ok !== true && !step.result) return null;
  const r = step.result;
  switch (step.op) {
    case 'mint': return mintEvents(r);
    case 'verify': return [...identityRow(r), tokenVerdict(step, r, 'the workload token')];
    case 'storedKeyCall': return storedKeyEvents(step, r);
    case 'sensorReport': return sensorEvents(step, r);
    default: return Object.hasOwn(CHANGES, step.op) ? CHANGES[step.op](r) : [];
  }
}

// ---- Stdout lines ---------------------------------------------------------------------------------------------------------------------------
export function decisionLine(ev, at, runId) {
  const result = ev.noReply ? 'no-reply' : RESULT[ev.outcome];
  return `${at} ${SERVICE} decision step=${lineValue(ev.step)} layer=${lineValue(ev.layer, 12)} actor=${field(ev.who)} result=${result} cause=${lineValue(ev.cause)}${ev.labtime ? ` labtime=${lineValue(ev.labtime, 30)}` : ''} run=${lineValue(runId)}`;
}

// ---- What the lab receives from the Privilege gateway (Real) ----------------------------------------------------------------------------------
const NO_REPLY = /^MCP HTTP request (?:unreachable|timed out)/;
const UNREAD = /^(?:reply larger than|reply is not JSON)/;
const RECEIVED = 'This is the reply the lab received, not a gateway log line.';
const STEP_TEXT = { 'tools/list': 'tools/list', probe: 'the refusal probe (a tool nothing grants)' };

// One call's answer -> an event, or null when there was no reply (a call that did not connect or timed out). Only the answer in hand is read: nothing
// from an earlier call. The gateway's own words are never copied into a row (they are on the page's gateway card, scrubbed of keys).
// A call the lab completed names its step. A call that failed does not: the shared client does not say which of its requests (the opening handshake or the
// call itself) got the status or the JSON-RPC error, so the row says "while the lab was opening or making" the call and `detail.during` names the call.
export function replyOf(step, r) {
  if (!r || typeof r !== 'object') return null;
  const what = STEP_TEXT[step];
  const done = (outcome, cause, message, detail) => ({ outcome, cause, message: `${message} ${RECEIVED}`, detail: { step, ...detail } });
  if (r.ok === true) {
    if (step === 'tools/list') {
      const n = Array.isArray(r.tools) ? r.tools.length : 0;
      return n > 0
        ? done('allowed', 'tools-listed', `The gateway answered ${what} with ${n} tools for the agent key.`, { tools: n, ms: r.ms })
        : done('info', 'empty-list', `The gateway answered ${what} with no tools, so there is no usable tool list to count as a pass.`, { tools: 0, ms: r.ms });
    }
    if (r.isError === true) return done('refused', 'tool-error', `The gateway answered ${what} with a tool error (isError): the call was not carried out.`, { ms: r.ms });
    return typeof r.text === 'string' && r.text.length > 0
      ? done('allowed', 'tool-ran', `The gateway let ${what} through and returned a tool result. A tool nothing grants should be refused: check the gateway policy.`, { ms: r.ms })
      : done('info', 'no-content', `The gateway answered ${what} with no content, so the lab cannot read it as a tool result.`, { ms: r.ms });
  }
  const f = r.refusal && typeof r.refusal === 'object' ? r.refusal : {};
  const status = Number.isInteger(f.status) ? f.status : null;
  const opening = `while the lab was opening or making ${what}`;
  const failed = (outcome, cause, message, detail) => ({ outcome, cause, message: `${message} ${RECEIVED}`, detail: { during: step, ...detail } });
  if (status === 401) return failed('refused', 'status-401', `The gateway answered HTTP 401 ${opening}: it did not accept the agent key.`, { status, ms: r.ms });
  if (status === 403) return failed('refused', 'status-403', `The gateway answered HTTP 403 ${opening}${step === 'probe' ? '. For a tool nothing grants, that is the answer the probe expects if it came from the call itself' : ''}.`, { status, ms: r.ms });
  if (status !== null) return failed('info', `status-${status}`, `The gateway answered HTTP ${status} ${opening}. That status is not a policy verdict, so it is counted as information.`, { status, ms: r.ms });
  const text = String(f.message ?? '');
  if (NO_REPLY.test(text)) return null;
  if (UNREAD.test(text)) return failed('info', 'unreadable', `The lab could not read the gateway's answer ${opening} as a tool result, so it is counted as information.`, { ms: r.ms });
  return failed('refused', 'jsonrpc-error', `The gateway answered ${opening} with a JSON-RPC error inside a successful HTTP reply: the lab reads that as a refusal.`, { ms: r.ms });
}

// ---- The run log ------------------------------------------------------------------------------------------------------------------------------
const iso = (ms) => new Date(ms).toISOString();
// Live: one run per action, lines only. Real: one run per gateway check, kept when it ends (the last KEEP_RUNS, one list for the lab: the page's card sends no workspace).
export function createRunLog({ write = (line) => process.stdout.write(`${line}\n`), clock = () => Date.now() } = {}) {
  const part = crypto.randomBytes(3).toString('hex'); // so an id never repeats after a restart or in another workspace (probabilistic across them)
  let made = 0;
  let runs = [];
  const stamp = () => iso(clock());

  return {
    // The engine events of one Live action: one line each, stamped when written, under one run id. `null` (the request was turned away before any decision) is one
    // line under `run=-`: it began no run. One line at a time: a write that throws drops that line only, never the rest of the action's lines.
    live(events, labtime) {
      if (events === null) { safely('live-line', () => write(decisionLine({ step: 'request', layer: 'lab', who: '-', outcome: 'refused', cause: 'bad-request' }, stamp(), '-'))); return; }
      if (!events.length) return;
      const id = `act-${part}-${++made}`;
      for (const ev of events) safely('live-line', () => write(decisionLine({ ...ev, labtime }, stamp(), id)));
    },
    // One gateway check. now() is the clock a call's start is read from; reply() writes the line and keeps the event at the time the lab had the answer (the call's
    // start plus its own measured time: the door helper also waits for a session close after the answer, so "now" would be later); end() stores the run.
    beginCheck(caller) {
      const run = { id: `gw-${part}-${++made}`, startedAt: stamp(), endedAt: null, events: [], notes: [], noReply: false };
      return {
        id: run.id,
        now: clock,
        reply(step, result, sentAt) {
          const at = Number.isFinite(sentAt) && Number.isFinite(result?.ms) ? iso(sentAt + result.ms) : stamp();
          const r = replyOf(step, result);
          const which = step === 'probe' ? 'gateway-probe' : 'gateway-list';
          if (!r) {
            // The shared client's "unreachable" and "timed out" words are the only sign of no connection, so a gateway refusal that used those exact words reads the same way.
            run.noReply = true;
            run.notes.push(`The ${step === 'probe' ? 'refusal probe' : 'tools/list call'} got no reply (it did not connect, or it timed out), so it has no row and absence is not proof the gateway did nothing. The lab reads a failure carrying exactly the shared client's "unreachable" or "timed out" words as no connection; a gateway refusal that used those exact words could, in rare cases, be read this way. It is never shown as allowed.`);
            write(decisionLine({ step: which, layer: 'gateway', who: caller, noReply: true, cause: 'no-reply' }, at, run.id));
            return;
          }
          const ev = { ...r, at, layer: 'gateway', product: 'Privilege gateway reply', step: which, who: caller };
          run.events.push(ev);
          write(decisionLine(ev, at, run.id));
        },
        skipped(note) { run.notes.push(note); },
        end() { run.endedAt = stamp(); runs = [...runs, run].slice(-KEEP_RUNS); },
      };
    },
    // The run with this id (when it is still one of the last few), or the newest.
    get: (id) => (id === undefined ? runs.at(-1) : runs.find((r) => r.id === id)) ?? null,
  };
}

// ---- The records -------------------------------------------------------------------------------------------------------------------------------
const WHY_MOCK = {
  person: 'No stored-key call or person change in this scenario. The lab has no sign-in: a person appears only as the custodian of a stored key.',
  agent: 'No token was issued or checked in this scenario.',
  authorize: 'This lab does not call PingOne Authorize.',
  privilege: 'No change to the lab\'s Federated Identity model and no sensor policy decision in this scenario. The lab\'s own model stands in for Privilege here; Privilege\'s own policy log is not read.',
  gateway: 'No call reached the lab\'s simulated gateway in this scenario.',
  resource: 'This lab has no resource server. The request its gateway would send on to a backend (with the application\'s own credential, masked) is modelled: nothing receives or answers it, so there is nothing to log.',
};
const WHY_REAL = {
  person: 'The lab calls the gateway with an agent access key, not as a person, and it has no sign-in. Nothing here is a person\'s sign-in.',
  agent: 'The caller is an agent access key (a Federated Identity), not an OBO token. The gateway\'s own log of that key is not read by this lab.',
  authorize: 'This lab does not call PingOne Authorize.',
  privilege: 'Privilege\'s policy log (its SIEM index and console activity log) is not read by this lab. The lab\'s own Federated Identity model and sensor policy stay in its local engine in Real too: their decisions are not in this record.',
  gateway: 'The lab received no reply from the gateway.',
  resource: 'The tool behind the gateway wrote no log the lab can read, and this lab has no resource server.',
};

// Ties (the lab clock moves only when a step moves it) are put back in the order the events were written; ids are renumbered to match.
function inEventOrder(rec) {
  const stamped = rec.rows.filter((r) => r.at !== null).sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.detail.eventSeq - b.detail.eventSeq);
  return { ...rec, rows: [...stamped.map((r, i) => ({ ...r, id: `r${i + 1}` })), ...rec.rows.filter((r) => r.at === null)] };
}

// The events of one table scenario, at the lab clock of each step. Read from the steps the table holds; nothing is run again.
export function tableEvents(sc) {
  const events = []; let at = sc.state.clock.startedAt;
  sc.steps.forEach((st, i) => {
    if (st.op === 'advance' && st.ok === true) { at = st.result.at; return; }
    for (const ev of eventsOf(st) ?? []) events.push({ ...ev, at, eventSeq: events.length, message: `Step ${i + 1}: ${ev.message}` });
  });
  return events;
}

// Mock: the events the recorded scenario holds. Unknown vertical or scenario is the caller's to refuse (the route does).
export async function mockRecord(table, vertical, scenarioId, { clock = Date.now } = {}) {
  const v = table.verticals[vertical];
  const sc = (typeof scenarioId === 'string' && v.scenarios.find((s) => s.id === scenarioId)) || v.scenarios[0];
  const events = tableEvents(sc);
  const rec = await createRunObservability({ clock }).collectRun({
    runId: `table-${vertical}-${sc.id}`, startedAt: sc.state.clock.startedAt, endedAt: sc.state.clock.at, source: 'mock',
    layers: LAYERS.map((layer) => ({
      layer, products: [], reason: WHY_MOCK[layer],
      simulated: events.filter((e) => e.layer === layer).map((e) => ({ at: e.at, product: e.product, outcome: e.outcome, message: e.message, detail: { ...e.detail, eventSeq: e.eventSeq } })),
    })),
  }); // no correlation: nothing is matched against logs here, so no id is declared and names stay readable
  return inEventOrder(rec);
}

// Real: what the lab received from the gateway on one check, as `response` rows. The layers the lab's own engine covers say so.
// No correlation here either: this lab reads no logs, so there is nothing to match, and a declared id would only shorten a name in the lines and rows.
export async function realRecord(run, { clock = Date.now } = {}) {
  const rec = await createRunObservability({ clock }).collectRun({
    runId: run.id, startedAt: run.startedAt, endedAt: run.endedAt, source: 'real',
    layers: LAYERS.map((layer) => ({
      layer, products: [], reason: layer === 'gateway' ? (run.notes.join(' ') || WHY_REAL.gateway) : WHY_REAL[layer],
      responses: layer === 'gateway' ? run.events.map((e, i) => ({ at: e.at, product: e.product, outcome: e.outcome, message: e.message, detail: { ...e.detail, eventSeq: i } })) : [],
    })),
  });
  const out = inEventOrder(rec);
  // A layer that has rows shows no reason of its own, so a call that got no reply or was not sent is named here, and a call with no reply makes the record partial.
  const note = run.notes.join(' ');
  if (note && run.events.length) out.reasons = { ...out.reasons, gateway: note };
  if (run.noReply) out.partial = { ...out.partial, gateway: true };
  return out;
}

const RUN_ID = /^gw-[0-9a-f]{6}-\d+$/; // the shape createRunLog gives a gateway check's id
// The route's answer. The mode is the page's wire value: only 'real' and 'mock' make a record, and anything else answers a plain note (no Real wording, no record).
// A Real run is only ever returned in Real and a Mock record only in Mock: the run is built from this mode's own source.
export async function answerFor({ source, table, runLog, query, verticalOf }) {
  const fail = (status, error, message) => ({ status, body: { error, message } });
  if (!Object.keys(query).every((k) => ['vertical', 'scenario', 'runId'].includes(k))) return fail(400, 'unknown_field', 'the query carries a parameter the lab does not take');
  if (source === 'real') {
    if (query.runId !== undefined && (typeof query.runId !== 'string' || !RUN_ID.test(query.runId))) return fail(400, 'bad_run_id', 'runId must be one run id (gw-, six hex, a counter)');
    const run = runLog.get(query.runId);
    if (!run) return { status: 200, body: { record: null, message: query.runId === undefined ? 'No gateway check has run in Real yet: nothing was received from the gateway, so there is nothing to show.' : 'That gateway check is no longer kept (the lab keeps the last few).' } };
    return { status: 200, body: { record: await realRecord(run) } };
  }
  if (source === 'mock') {
    // A runId is not read here on purpose: a Mock answer is always a Mock record, so a Real run's id can never bring back a Real record in Mock (the mode test pins it).
    const vertical = verticalOf(query.vertical);
    if (vertical === null) return fail(400, 'bad_vertical', 'there is no such pack');
    const sc = query.scenario;
    if (sc !== undefined && (typeof sc !== 'string' || !table.verticals[vertical].scenarios.some((s) => s.id === sc))) return fail(404, 'unknown_scenario', 'there is no such scenario in this pack');
    return { status: 200, body: { record: await mockRecord(table, vertical, sc) } };
  }
  return { status: 200, body: { record: null, message: 'The lab is in a mode that makes no run record, so there is nothing to show. Use the Mode toggle to choose a mode.' } };
}
