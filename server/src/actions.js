// One dispatch for everything that changes an engine, used by the API, the scripted scenarios and the tests, so they cannot drift apart.
// A request-level refusal (bad shape, unknown id, a cap) is data ({ ok: false, status, code, detail }), never an exception. A TOKEN refusal (verify, a sensor report,
// a stored-key call) is also data, and carries the whole step-by-step result as `result`. Anything else is a bug and propagates.
import { InputError } from './errors.js';

const OPS = {
  mint: (e, p) => e.mint(p),
  verify: (e, p) => e.verify(p),
  advance: (e, p) => e.advance(p),
  issuer: (e, p) => e.issuerAction(p),
  refreshKeys: (e, p) => e.refreshKeys(p),
  createIdentity: (e, p) => e.createIdentity(p),
  updateIdentity: (e, p) => e.updateIdentity(p),
  deleteIdentity: (e, p) => e.deleteIdentity(p),
  createKey: (e, p) => e.createKey(p),
  updateKey: (e, p) => e.updateKey(p),
  deleteKey: (e, p) => e.deleteKey(p),
  setPerson: (e, p) => e.setPerson(p),
  storedKeyCall: (e, p) => e.storedKeyCall(p),
  enrollSensor: (e, p) => e.enrollSensor(p),
  sensorReport: (e, p) => e.sensorReport(p),
  setPolicy: (e, p) => e.setPolicy(p),
};
export const OP_NAMES = Object.keys(OPS);
const OUTCOME_OPS = new Set(['verify', 'storedKeyCall', 'sensorReport']);

export function perform(engine, op, params) {
  if (!Object.hasOwn(OPS, op)) throw new Error(`unknown op ${op}`);
  try {
    const r = OPS[op](engine, params);
    if (OUTCOME_OPS.has(op)) return r.ok ? { ok: true, result: r } : { ok: false, status: r.status, code: r.code, detail: r.detail, result: r };
    return { ok: true, result: r };
  } catch (e) { if (e instanceof InputError) return { ok: false, status: e.status, code: e.code, detail: e.message }; throw e; }
}
