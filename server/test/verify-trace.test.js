// "What Privilege did" (Rule 25) for the Verify tab: every trace the lab builds is the lab's own simulated gateway (source 'mock', every decision 'checked'),
// the contract holds (assertTrace), and no token text or secret is in it. Fake values are built at run time.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assertTrace } from '../src/gatewayTrace.js';
import { liveVerifyTrace, withMockVerifyTraces } from '../src/verifyTrace.js';
import { C, GW, K8S_SUB, api, get, json, withServer } from './helpers.js';

const mint = (url, ws, body = {}) => api(url, 'POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW }, ...body } }, ws);
const verify = (url, ws, token, extra = {}) => api(url, 'POST', '/api/verify', { verify: { token, service: 'mcp', identityId: 'fid-001', ...extra } }, ws);
const STEP_IDS = ['parse', 'identity', 'alg', 'issuer', 'keyset', 'signature', 'expiry', 'notbefore', 'issued', 'lifetime', 'audience', 'subject', 'claims', 'key', 'scope'];

test('Live: an allowed verify returns a mock trace with all fifteen decisions checked and passed, in the engine order', async () => {
  await withServer(async (url) => {
    const { body: m } = await mint(url, 'w-trace-ok');
    const token = m.result.mintedToken;
    const { status, body } = await verify(url, 'w-trace-ok', token);
    assert.equal(status, 200);
    const t = body.gatewayTrace;
    assert.deepEqual(assertTrace(t), []);
    assert.equal(t.source, 'mock');
    assert.deepEqual(t.decisions.map((d) => d.id), STEP_IDS);
    assert.ok(t.decisions.every((d) => d.outcome === 'pass' && d.basis === 'checked'));
    assert.equal(t.request.url, `https://gateway.${C.castHost}.example/mcp`);
    assert.equal(t.request.body, null);
    assert.equal(t.request.headers.accept, undefined, 'the lab sends no accept header, so the trace shows none');
    assert.match(t.request.headers.traceparent, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/, 'the same traceparent the raw hops pane shows');
    assert.equal(t.response.status, 200); assert.deepEqual(t.response.body, { code: 'allowed' });
    assert.match(t.record, /^verify service=mcp outcome=allowed code=allowed status=200$/);
  });
});

test('Live: a refusal keeps its HTTP status; the failed step is fail, the later ones skipped, all checked', async () => {
  await withServer(async (url) => {
    const { body: m } = await mint(url, 'w-trace-bad', { claims: { sub: `${K8S_SUB}-other`, aud: GW } });
    const { status, body } = await verify(url, 'w-trace-bad', m.result.mintedToken);
    assert.ok(status === 401 || status === 403 || status === 404, `status ${status}`);
    const t = body.gatewayTrace;
    assert.deepEqual(assertTrace(t), []);
    assert.equal(t.response.status, status);
    assert.equal(t.response.body.code, body.error);
    const failed = t.decisions.filter((d) => d.outcome === 'fail');
    assert.equal(failed.length, 1);
    const at = t.decisions.findIndex((d) => d.outcome === 'fail');
    assert.ok(t.decisions.slice(at + 1).every((d) => d.outcome === 'skipped'), 'steps after the refusal were never reached');
    assert.ok(t.decisions.slice(0, at).every((d) => d.outcome === 'pass'));
    assert.ok(t.decisions.every((d) => d.basis === 'checked'));
  });
});

test('the visitor token text is never in a trace: only its length (a fake, run-time-built token)', async () => {
  await withServer(async (url) => {
    const secret = ['fake', 'token', 'body'].join('-') + 'X'.repeat(30);
    const { body } = await verify(url, 'w-trace-secret', secret);
    const t = body.gatewayTrace;
    assert.deepEqual(assertTrace(t), []);
    assert.ok(!JSON.stringify(t).includes(secret), 'the token text is not in the trace');
    assert.equal(t.request.headers.authorization, `Bearer <token, ${secret.length} characters, kept on the server>`);
    const { body: m } = await mint(url, 'w-trace-secret');
    const real = m.result.mintedToken;
    const r2 = await verify(url, 'w-trace-secret', real);
    assert.ok(!JSON.stringify(r2.body.gatewayTrace).includes(real.split('.')[2]), 'no part of the signature is in the trace');
  });
});

test('a verify that never reaches the gateway (bad request shape) carries no trace', async () => {
  await withServer(async (url) => {
    const { status, body } = await api(url, 'POST', '/api/verify', { verify: { token: 5, service: 'mcp' } }, 'w-trace-none');
    assert.equal(status, 400);
    assert.equal(body.gatewayTrace, undefined);
    const other = await mint(url, 'w-trace-none');
    assert.equal(other.body.gatewayTrace, undefined, 'only verify has one');
  });
});

test('Mock: every scripted verify step carries a trace built at request time; the table holds none', async () => {
  await withServer(async (url) => {
    let seen = 0;
    for (const scenario of ['one-credential', 'revocation', 'key-owner', 'lifetimes']) {
      const s = await json(await get(url, `/api/state?mode=mock&vertical=finance&scenario=${scenario}`));
      for (const st of s.scenario.steps) {
        if (st.op !== 'verify') { assert.equal(st.gatewayTrace, undefined, `${scenario}: ${st.op} has no trace`); continue; }
        seen += 1;
        const t = st.gatewayTrace;
        assert.deepEqual(assertTrace(t), [], `${scenario}: ${st.say}`);
        assert.equal(t.source, 'mock');
        assert.deepEqual(t.decisions.map((d) => d.id), STEP_IDS);
        assert.ok(t.decisions.every((d) => d.basis === 'checked'));
        assert.equal(t.response.status, st.status);
        assert.equal(t.request.headers.authorization, 'Bearer <MOCK-ISSUED token: a Mock table holds no token>');
        assert.equal(t.request.headers.traceparent, undefined, 'a table has no live traceparent');
      }
    }
    assert.ok(seen >= 10, `${seen} verify steps traced`);
  });
});

test('the builders refuse nothing they should accept and invent nothing: a result without steps or scope gives no trace', () => {
  assert.equal(liveVerifyTrace({ cast: C, result: { steps: null, scope: 'mcp' }, token: 'x' }), null);
  assert.equal(liveVerifyTrace({ cast: C, result: { steps: [], status: 401, code: 'x' }, token: 'x' }), null);
  const steps = [{ op: 'mint', result: {} }, { op: 'verify', result: { steps: [] } }];
  assert.deepEqual(withMockVerifyTraces(steps, C), steps);
});

test('Live mode and a second vertical: the trace host follows the cast', async () => {
  await withServer(async (url) => {
    const r = await api(url, 'POST', '/api/verify', { vertical: 'health', verify: { token: 'a.b.c', service: 'llm' } }, 'w-trace-health');
    assert.equal(r.body.gatewayTrace.request.url, 'https://gateway.contoso.example/llm');
    assert.deepEqual(assertTrace(r.body.gatewayTrace), []);
  });
});
