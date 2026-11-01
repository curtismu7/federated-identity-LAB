// The glue between the HTTP layer and the engine: Mock reads tables, Live drives the workspace's engine. Every action gets one W3C trace and a list of hops
// (the raw request and response panes), with anything credential-shaped masked.
import { Engine } from './engine.js';
import { perform } from './actions.js';
import { reveal } from './clean.js';
import { newTrace, formatTraceparent } from './trace.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// A copy of the visitor's parameters that is safe to show: credential-shaped strings and keys masked, hidden characters written out, nothing else changed. Depth-limited.
export function scrub(value, depth = 0) {
  if (typeof value === 'string') return reveal(value, 300);
  if (Array.isArray(value)) return depth > 3 ? [] : value.slice(0, 10).map((v) => scrub(v, depth + 1));
  if (isObj(value)) return depth > 3 ? {} : Object.fromEntries(Object.keys(value).slice(0, 20).map((k) => [reveal(k, 40), scrub(value[k], depth + 1)]));
  return typeof value === 'number' || typeof value === 'boolean' || value === null ? value : undefined;
}

export function mockState(table, vertical, scenarioId) {
  const v = table.verticals[vertical];
  const sc = (typeof scenarioId === 'string' && v.scenarios.find((s) => s.id === scenarioId)) || v.scenarios[0];
  return { state: sc.state, scenario: { id: sc.id, title: sc.title, say: sc.say, steps: sc.steps }, scenarios: v.scenarios.map((s) => ({ id: s.id, title: s.title, say: s.say })) };
}

export function liveState(ws, workspaces, vertical, cast) {
  const e = workspaces.peek(ws, vertical) || new Engine(cast);
  return e.snapshot();
}

export function runAction({ ws, workspaces, vertical, cast, op, params, traceparent, route }) {
  const e = workspaces.engine(ws, vertical, cast);
  const t = newTrace(traceparent);
  const root = t.span();
  e.trace = { traceId: t.traceId, span: t.span }; e.hops = []; e.hopsTruncated = false;
  let outcome;
  try { outcome = perform(e, op, params); } finally { e.trace = null; }
  const first = { n: 1, label: 'browser to the lab API', request: { method: route.method, url: route.url, headers: { traceparent: formatTraceparent(t.traceId, root), 'x-workspace': ws }, body: scrub(params) }, response: { status: outcome.ok ? 200 : outcome.status, body: outcome.ok ? { ok: true } : { error: outcome.code } } };
  const hops = [first, ...e.hops.map((h, i) => ({ ...h, n: i + 2 }))];
  const truncated = e.hopsTruncated; e.hops = [];
  return { outcome, hops, hopsTruncated: truncated, traceparent: formatTraceparent(t.traceId, root), traceId: t.traceId, state: e.snapshot() };
}

// The public JWKS of one issuer as this workspace's engine publishes it now (a workspace that has done nothing yet has the seeded world).
export function jwksFor(ws, workspaces, vertical, cast, issuerId) {
  const e = workspaces.peek(ws, vertical) || new Engine(cast);
  return e.jwksOf(issuerId);
}
