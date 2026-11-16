// "What Privilege did" for the Verify tab. On this tab the lab never contacts a real Privilege gateway (only the separate Real-mode gateway check does): the gateway is its own simulation (engine.verifyCore, fifteen steps in a
// fixed order), so every trace here is source 'mock' and every decision is 'checked': the engine computed it (Live signs and verifies real RS256 on the lab's own keys,
// Mock reads a generated table; both are the lab's gateway). A step that was never reached is 'skipped'. Nothing is invented: a decision is one engine step, with its own
// title and detail; the request is the one the engine's own hop records (POST to the gateway's service address, no JSON-RPC body, the token never shown, only its length);
// the response is the status and code the engine returned.
// The host matches the lab's raw hops pane (gateway.<cast host>.example), so the page names one address for one call.
import { bearerForDisplay, mockTrace } from './gatewayTrace.js';

const OUTCOME = { pass: 'pass', fail: 'fail', skip: 'skipped' };

const decisionsOf = (steps) => (Array.isArray(steps) ? steps : []).map((s) => ({ id: s.id, label: s.title, outcome: OUTCOME[s.status] || 'info', evidence: s.detail }));

// result: the engine's verification result ({ status, code, scope, steps, ok }). authorization: what to show for the Authorization header.
function trace({ cast, result, authorization, traceparent }) {
  const service = result.scope;
  return mockTrace({
    url: `https://gateway.${cast.castHost}.example/${service}`,
    authorization,
    rpc: null,
    status: result.status,
    body: { code: result.code },
    requestHeaders: { accept: null, ...(traceparent ? { traceparent } : {}) },
    decisions: decisionsOf(result.steps),
    record: `verify service=${service} outcome=${result.ok ? 'allowed' : 'refused'} code=${result.code} status=${result.status}`,
  });
}

// Live: the answer to the visitor's own Verify. The token is the visitor's (any text): only its length is shown, never the text.
export function liveVerifyTrace({ cast, result, token, traceparent }) {
  if (!result || !Array.isArray(result.steps) || typeof result.scope !== 'string') return null;
  return trace({ cast, result, authorization: bearerForDisplay('<workload token>', () => String(token)), traceparent });
}

// Mock: a scripted scenario's verify steps, from the generated table, built at request time so the table itself (and its drift test) is untouched.
// The table holds no token, so the header says so.
export function withMockVerifyTraces(steps, cast) {
  return steps.map((st) => (st.op === 'verify' && st.result && Array.isArray(st.result.steps) && typeof st.result.scope === 'string'
    ? { ...st, gatewayTrace: trace({ cast, result: st.result, authorization: 'Bearer <MOCK-ISSUED token: a Mock table holds no token>' }) }
    : st));
}
