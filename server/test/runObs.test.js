// Rule 27: the lab's half of the run-observability panel (runObs.js, the route, the stdout lines, the events read from the recorded scenarios). The vendored collector has its own
// tests in the shared folder. Real is tested against an in-process fake Privilege gateway on loopback only; the shared settings file is pointed at a file that does not exist.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { MOCK_TABLE } from '../src/mockTable.js';
import { POLICY_ACTIONS, POLICY_MODES, FINDING_KINDS } from '../src/catalog.js';
import { STEPS } from '../src/engine.js';
import { assertRunObservability, classify, layerMatchers, createMasker, LAYERS } from '../src/runObservability.js';
import { EFFECT, KEEP_RUNS, KEY_TURNED_AWAY, STOPPED_AT, answerFor, createRunLog, decisionLine, eventsOf, lineValue, mockRecord, realRecord, replyOf } from '../src/runObs.js';
import { createWorkspaces } from '../src/workspaces.js';
import { seededRand } from '../src/scenarios.js';
import { maskDeep } from '../src/mask.js';
import { C, GW, K8S_SUB, api, get, newEngine, post, rawHttp, withServer } from './helpers.js';

const NO_ENV = '/nonexistent/none.env'; // the shared settings file is read live by realDoorFrom: never the owner's
process.env.STANDALONE_ENV = NO_ENV;
for (const k of Object.keys(process.env)) if (k.startsWith('FID_GW_') || k === 'FID_LAB_MODE') delete process.env[k];

const WORDS = /refused|denied|rejected|forbidden|failed|invalid|expired|mismatch|token|audience|scope|served|unauthorized|insufficient|not allowed/i;
const LINE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z federated-identity-lab decision step=[A-Za-z0-9._:/@-]+ layer=[a-z]+ actor=[A-Za-z0-9._:/@-]+ result=(?:passed|stopped|unclear|no-reply) cause=[A-Za-z0-9._:/@-]+(?: labtime=[A-Za-z0-9._:/@-]+)? run=[A-Za-z0-9._:/@-]+$/;
const PRODUCTS = [...new Set(layerMatchers.map((m) => m.product))];
const fragments = (...p) => p.join('');
const KEY = fragments('fake-agent-key-', 'qqqqqqqqqq', '-end');
const rows = (rec) => rec.rows.filter((r) => r.origin !== 'not-logged');
const noMatcherReads = (line) => { for (const product of PRODUCTS) { const at = line.split(' ')[0]; assert.equal(classify({ product, message: line, at: Date.parse(at), atExact: at }, []), null, `${product}: ${line}`); } };
const checkLine = (l) => { assert.match(l, LINE); assert.ok(!WORDS.test(l), `a matcher word in the line: ${l}`); noMatcherReads(l); noMatcherReads(`[${l.split(' ')[0]}] INFO: ${l.split(' ').slice(1).join(' ')}`); };
const stderrOf = async (fn) => {
  const written = []; const realWrite = process.stderr.write;
  process.stderr.write = (c, ...rest) => { written.push(String(c)); return typeof rest.at(-1) === 'function' ? rest.at(-1)() : true; };
  try { await fn(); } finally { process.stderr.write = realWrite; }
  return written.join('');
};

// ---- A fake Privilege gateway on loopback: the MCP calls the lab's client makes, answered by a script ------------------------------------------
async function fakeGateway() {
  const g = { script: { list: null, call: null }, seen: [], url: '', port: 0, initFail: 0, notifyFail: 0, initRpcError: false, closeDelayMs: 0 };
  const json = (res, obj, status = 200, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); };
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.method === 'DELETE') { setTimeout(() => { res.writeHead(200); res.end(); }, g.closeDelayMs); return; }
      let m; try { m = JSON.parse(body); } catch { res.writeHead(400); return res.end(); }
      g.seen.push({ method: m.method, auth: req.headers.authorization });
      if (m.method === 'initialize' && g.initFail) return json(res, { message: 'handshake refused' }, g.initFail);
      if (m.method === 'initialize' && g.initRpcError) return json(res, { jsonrpc: '2.0', id: m.id, error: { code: -32000, message: 'no handshake' } });
      if (m.method === 'notifications/initialized' && g.notifyFail) return json(res, { message: 'handshake refused' }, g.notifyFail);
      if (m.method === 'initialize') return json(res, { jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'fake-gateway' }, capabilities: {} } }, 200, { 'mcp-session-id': 's1' });
      if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
      const step = m.method === 'tools/list' ? g.script.list : g.script.call;
      return step({ m, res, req, json: (o, s, h) => json(res, o, s, h) });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  g.port = server.address().port; g.url = `http://127.0.0.1:${g.port}`;
  g.close = () => new Promise((r) => { server.closeAllConnections(); server.close(r); });
  return g;
}
const tools = (n) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: Array.from({ length: n }, (_x, i) => ({ name: `tool_${i}`, description: 'a tool' })) } });
const status = (code, text = 'nope') => ({ json }) => json({ message: text }, code);
const rpcResult = (result) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result });
const rpcError = (message) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message } });
const drop = ({ req }) => req.socket.destroy();
const rawText = ({ res }) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('<html>not json</html>'); };

// The lab reads its gateway settings from the process environment (the file is pointed at nothing), like gateway-check.test.js.
async function withGateway(fn, { runLog, label = 'LAB_AGENT' } = {}) {
  const gw = await fakeGateway();
  const set = { STANDALONE_ENV: NO_ENV, FID_GW_URL: gw.url, FID_GW_APPS: 'door-a', [`FID_GW_KEY_${label}`]: KEY };
  const keep = Object.fromEntries(Object.keys(set).map((k) => [k, process.env[k]]));
  Object.assign(process.env, set);
  try { await withServer(async (url, ctx) => fn(url, gw, ctx), { runLog }); } finally {
    for (const [k, v] of Object.entries(keep)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    await gw.close();
  }
}
const toReal = (url) => post(url, '/api/mode', { source: 'real' });
const toMock = (url) => post(url, '/api/mode', { source: 'mock' });
const check = async (url) => (await post(url, '/api/gateway-check', {})).json();
const record = async (url, q = '') => (await get(url, `/api/run-observability${q}`)).json();

// ---- Mock: the recorded scenarios ------------------------------------------------------------------------------------------------------------
test('every recorded scenario of every vertical has a Mock record that passes the shared contract, is all simulated, numbers its steps, and comes through the response mask unchanged', async () => {
  await withServer(async (url) => {
    for (const [v, vv] of Object.entries(MOCK_TABLE.verticals)) {
      for (const sc of vv.scenarios) {
        const res = await get(url, `/api/run-observability?vertical=${v}&scenario=${sc.id}`);
        assert.equal(res.status, 200, `${v}/${sc.id}`);
        const { record: rec } = await res.json();
        assert.deepEqual(assertRunObservability(rec), [], `${v}/${sc.id}`);
        assert.equal(rec.source, 'mock'); assert.equal(rec.runId, `table-${v}-${sc.id}`);
        assert.ok(rows(rec).length > 0, `${v}/${sc.id} has rows`);
        assert.ok(rows(rec).every((r) => r.origin === 'simulated' && !r.basis && !r.matchedBy && /^Step \d+: /.test(r.message) && !r.message.endsWith('…')), 'no row is presented as read from a log, every row names its step, and none was cut at the message cap');
        assert.deepEqual(Object.keys(rec.coverage).sort(), [...LAYERS].sort());
        assert.equal(rec.coverage.authorize, 'not-logged'); assert.equal(rec.coverage.resource, 'not-logged', 'there is no resource server, so there is nothing to log');
        // the route's answer is exactly the record the lab built: the response mask changed no word of it
        assert.deepEqual(rec, JSON.parse(JSON.stringify(await mockRecord(MOCK_TABLE, v, sc.id))));
        assert.deepEqual(maskDeep({ record: rec }), { record: rec });
        assert.deepEqual(rec.rows.map((r) => r.id).filter((id) => /^r\d+$/.test(id)), rows(rec).map((_r, i) => `r${i + 1}`), 'ids follow the order of the events');
      }
    }
    assert.equal((await record(url)).record.runId, `table-finance-${MOCK_TABLE.verticals.finance.scenarios[0].id}`, 'no scenario named: the first one');
  });
});

test('each row is what the table\'s step holds: a verdict row is allowed or refused exactly as the step was, a step that was no decision has no row, and nothing is shown for a request that never reached a decision', async () => {
  for (const [v, vv] of Object.entries(MOCK_TABLE.verticals)) {
    for (const sc of vv.scenarios) {
      const rec = await mockRecord(MOCK_TABLE, v, sc.id);
      const byStep = Map.groupBy(rows(rec), (r) => Number(/^Step (\d+):/.exec(r.message)[1]));
      sc.steps.forEach((st, i) => {
        const here = byStep.get(i + 1) ?? [];
        const verdicts = here.filter((r) => r.product === 'lab simulated gateway');
        if (['verify', 'storedKeyCall', 'sensorReport'].includes(st.op) && st.result) assert.deepEqual(verdicts.map((r) => r.outcome), [st.ok ? 'allowed' : 'refused'], `${v}/${sc.id} step ${i + 1}: ${st.op}`);
        else assert.equal(verdicts.length, 0, `${v}/${sc.id} step ${i + 1}`);
        if (!st.ok && !st.result) assert.equal(here.length, 0, `${v}/${sc.id} step ${i + 1}: a request turned away before any decision has no row`);
        if (['advance', 'issuer'].includes(st.op)) assert.equal(here.length, 0, `${v}/${sc.id} step ${i + 1}: ${st.op} is no decision`);
        if (st.op === 'mint' && st.ok) assert.deepEqual(here.map((r) => [r.layer, r.outcome]), [['agent', 'info']], 'issuing a token is information, never allowed');
      });
      assert.ok(!rec.rows.some((r) => r.layer === 'resource' && r.origin !== 'not-logged'));
    }
  }
});

test('one-credential: each verification is the matched identity (information) and the gateway\'s verdict, in that order; the LLM service is refused at the last check', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'one-credential');
  assert.deepEqual(rows(rec).map((r) => [r.layer, r.outcome]), [['agent', 'info'], ['agent', 'info'], ['gateway', 'allowed'], ['agent', 'info'], ['gateway', 'allowed'], ['agent', 'info'], ['gateway', 'refused']]);
  const last = rows(rec).at(-1);
  assert.match(last.message, /Step 4: .*turned away the workload token for llm \(HTTP 403\) at check 15 of 15, "The scope is on the key", code scope_not_on_key\. The checks after it were not reached/);
  assert.equal(last.detail.stoppedAt, 15);
  assert.deepEqual(rec.summary, { allowed: 2, refused: 1, blocked: 0, info: 4, unverified: 0 }, 'the matched identity and the issuance are information, never a pass');
  assert.match(rows(rec)[1].message, /That is the identity the verdict below is about, not a second decision/);
});

test('revocation: an identity that is disabled stops at check 2, one that is removed is found by no row of the agent lane, and a configuration change is information', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'revocation');
  const step = (n) => rows(rec).filter((r) => r.message.startsWith(`Step ${n}:`));
  assert.deepEqual(step(5).map((r) => [r.layer, r.outcome]), [['privilege', 'info']]); assert.match(step(5)[0].message, /was saved; Enabled is now false\. A change is not a decision about an access/);
  assert.deepEqual(step(6).map((r) => [r.layer, r.outcome]), [['agent', 'info'], ['gateway', 'refused']]); assert.match(step(6)[1].message, /check 2 of 15/);
  assert.deepEqual(step(8).map((r) => r.outcome), ['info', 'allowed'], 'restored: allowed again');
  assert.deepEqual(step(9).map((r) => [r.layer, r.outcome]), [['privilege', 'info']]);
  assert.deepEqual(step(10).map((r) => [r.layer, r.outcome]), [['gateway', 'refused']], 'no identity matched, so no agent row');
});

test('lifetimes: the lab clock is the time of each row; an advance has no row and moves the rows after it', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'lifetimes');
  const at = (n) => [...new Set(rows(rec).filter((r) => r.message.startsWith(`Step ${n}:`)).map((r) => r.atExact))];
  assert.deepEqual(at(1), ['2026-11-02T09:00:00.000Z']); assert.deepEqual(at(12), ['2026-11-02T09:00:00.000Z']);
  assert.deepEqual(at(13), []); assert.deepEqual(at(14), ['2026-11-02T10:01:00.000Z']);
  assert.equal(rec.window.from, '2026-11-02T09:00:00.000Z'); assert.equal(rec.window.to, '2026-11-02T10:01:00.000Z');
});

test('key-owner: a stored key is the person (information, a stand-in) and the gateway\'s verdict; the console-style refusals of a key form have no row; a person change is the person lane', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'key-owner');
  const step = (n) => rows(rec).filter((r) => r.message.startsWith(`Step ${n}:`));
  assert.deepEqual(step(1).map((r) => [r.layer, r.outcome]), [['privilege', 'info']]);
  assert.deepEqual([step(2), step(3)], [[], []], 'a request turned away before any decision begins no run and has no row');
  assert.deepEqual(step(4).map((r) => [r.layer, r.outcome]), [['person', 'info'], ['gateway', 'allowed']]);
  assert.deepEqual(step(5).map((r) => [r.layer, r.outcome]), [['person', 'info']]); assert.match(step(5)[0].message, /set maya\.chen inactive/);
  assert.deepEqual(step(6).map((r) => [r.layer, r.outcome]), [['person', 'info'], ['gateway', 'refused']]);
  assert.match(step(6)[0].message, /holds that person as inactive/); assert.match(step(6)[1].message, /code owner_inactive.*the person who owns the key is inactive/);
  assert.match(step(11)[1].message, /check 14 of 15/);
  assert.equal(rec.coverage.person, 'simulated');
});

test('enforcement: audit mode records (information), enforce mode blocks, a namespace outside the policy and a warning are information; only an enforced stop is blocked', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'enforcement');
  const policy = rows(rec).filter((r) => r.product === 'lab sensor policy');
  assert.deepEqual(policy.map((r) => [r.message.slice(0, 7), r.outcome]), [['Step 3:', 'info'], ['Step 3:', 'info'], ['Step 3:', 'info'], ['Step 5:', 'blocked'], ['Step 5:', 'info'], ['Step 5:', 'info']]);
  assert.match(policy[0].message, /audit mode: recorded, not blocked \(enforce mode would block it\)/); assert.match(policy[3].message, /enforce mode: the sensor terminates it/);
  assert.equal(rec.summary.blocked, 1); assert.equal(rec.summary.allowed, 2, 'only the two gateway verdicts');
  assert.ok(policy.every((r) => r.layer === 'privilege'));
});

test('sensor: a report with another audience stops at check 11; a disabled sensor identity stops at check 2; the sensor\'s findings are weighed only when its report was taken', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'sensor');
  const step = (n) => rows(rec).filter((r) => r.message.startsWith(`Step ${n}:`));
  assert.deepEqual(step(2).map((r) => [r.layer, r.outcome]), [['agent', 'info'], ['gateway', 'allowed'], ['privilege', 'info'], ['privilege', 'info']], 'no policy is bound: each finding is recorded, not decided');
  assert.match(step(3)[1].message, /check 11 of 15/); assert.deepEqual(step(3).map((r) => r.layer), ['agent', 'gateway']);
  assert.match(step(5)[1].message, /check 2 of 15/); assert.equal(step(5).length, 2, 'a refused report brings no finding');
});

test('the words the engine can write are all in the lab\'s tables: every sensor effect, every step a verification stops at, every refusal of a stored key', () => {
  const e = newEngine(); const effects = new Set();
  for (const mode of POLICY_MODES) for (const all of [true, false]) for (const action of POLICY_ACTIONS) {
    const policy = { mode, scope: { all, namespaces: all ? [] : [C.castNs] }, actions: Object.fromEntries(FINDING_KINDS.map((k) => [k, action])) };
    for (const namespace of [C.castNs, C.castNs2]) effects.add(e.decide(policy, { kind: 'model-server', namespace }).effect);
  }
  effects.add(e.decide(null, {}).effect);
  assert.deepEqual([...effects].sort(), Object.keys(EFFECT).sort());
  assert.deepEqual(Object.keys(STOPPED_AT).sort(), STEPS.map((s) => s.id).sort());
  const codes = new Set();
  const call = (service = 'mcp') => e.storedKeyCall({ keyId: 'key-0006', service }).code;
  codes.add(call()); codes.add(call('a2a')); e.setPerson({ person: C.castOwner, active: false }); codes.add(call());
  e.setPerson({ person: C.castOwner, active: true }); e.updateKey({ keyId: 'key-0006', enabled: false }); codes.add(call());
  assert.deepEqual([...codes].filter((c) => c !== 'allowed').sort(), Object.keys(KEY_TURNED_AWAY).sort());
});

test('no credential, token or key is in any Mock record (the table is public)', async () => {
  for (const [v, vv] of Object.entries(MOCK_TABLE.verticals)) {
    for (const sc of vv.scenarios) {
      const text = JSON.stringify(await mockRecord(MOCK_TABLE, v, sc.id));
      assert.ok(!/eyJ[\w-]{10,}/.test(text) && !/mintedToken|Bearer\s+[A-Za-z0-9]/.test(text), `${v}/${sc.id}`);
    }
  }
});

// ---- The route ------------------------------------------------------------------------------------------------------------------------------
test('the route answers errors as {error, message} JSON, takes only its own parameters, answers GET only, and keeps the host and origin checks', async () => {
  await withServer(async (url) => {
    const cases = [['?bogus=1', 400, 'unknown_field'], ['?scenario=nope', 404, 'unknown_scenario'], ['?vertical=nope', 400, 'bad_vertical'], ['?vertical=a&vertical=b', 400, 'bad_vertical'], ['?scenario[]=x', 404, 'unknown_scenario'], ['?scenario=__proto__', 404, 'unknown_scenario']];
    for (const [q, st, code] of cases) {
      const r = await get(url, `/api/run-observability${q}`); const b = await r.json();
      assert.equal(r.status, st, q); assert.equal(b.error, code); assert.equal(typeof b.message, 'string');
    }
    for (const m of ['POST', 'PUT', 'DELETE']) {
      const r = await fetch(`${url}/api/run-observability`, { method: m, headers: { origin: url, 'content-type': 'application/json' }, body: m === 'DELETE' ? undefined : '{}' });
      assert.equal(r.status, 405, m); assert.match(r.headers.get('allow'), /GET/);
    }
    assert.equal((await get(url, '/api/run-observability')).headers.get('cache-control'), 'no-store');
    assert.equal((await rawHttp(`${url}/api/run-observability`, { headers: { host: 'evil.example.invalid:7400' } })).status, 403, 'a foreign Host');
    assert.equal((await fetch(`${url}/api/run-observability`, { method: 'POST', headers: { origin: 'http://evil.example.invalid', 'content-type': 'application/json' }, body: '{}' })).status, 403, 'a cross-origin write');
    await toReal(url);
    assert.equal((await get(url, '/api/run-observability?runId=a&runId=b')).status, 400); assert.equal((await get(url, '/api/run-observability?runId[x]=1')).status, 400);
    const bad = await (await get(url, '/api/run-observability?runId=a&runId=b')).json(); assert.equal(bad.error, 'bad_run_id');
    // an empty or malformed run id is a 400 too, never "no longer kept": only a well-formed id that is not kept is a 200 with no record
    for (const id of ['', '../x', 'gw-1', 'gw-ABCDEF-1']) {
      const r = await get(url, `/api/run-observability?runId=${encodeURIComponent(id)}`);
      assert.equal(r.status, 400, `runId=${id}`); assert.equal((await r.json()).error, 'bad_run_id', `runId=${id}`);
    }
  });
});

test('only Mock and Real make a record: any other mode answers a plain note with no Real wording, and the route follows the toggle in both directions', async () => {
  const empty = createRunLog({ write: () => {} });
  for (const source of ['live', 'bogus', undefined, null, '']) {
    const a = await answerFor({ source, table: MOCK_TABLE, runLog: empty, query: {}, verticalOf: () => 'finance' });
    assert.equal(a.status, 200); assert.equal(a.body.record, null); assert.ok(!/Real|gateway check/.test(a.body.message), String(source));
  }
  await withServer(async (url) => {
    assert.equal((await record(url)).record.source, 'mock');
    await toReal(url);
    assert.deepEqual(await record(url), { record: null, message: 'No gateway check has run in Real yet: nothing was received from the gateway, so there is nothing to show.' });
    await toMock(url);
    assert.equal((await record(url)).record.source, 'mock');
  });
  // a lab that opens in Live (FID_LAB_MODE=live) reports source real on /api/info, and the route agrees
  process.env.FID_LAB_MODE = 'live';
  try {
    await withServer(async (url) => {
      assert.equal((await (await get(url, '/api/info')).json()).source, 'real');
      assert.match((await record(url)).message, /No gateway check has run in Real yet/);
    });
  } finally { delete process.env.FID_LAB_MODE; }
});

// ---- Live: one stdout line per decision --------------------------------------------------------------------------------------------------------
const FINDINGS = [{ kind: 'model-server', name: 'vllm', namespace: C.castNs, pod: 'p-0' }, { kind: 'model-server', name: 'ollama', namespace: C.castNs3, pod: 'p-1' }];
async function liveSession(url, ws) {
  const mint = await api(url, 'POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: K8S_SUB, aud: GW } } }, ws);
  const token = mint.body.result.mintedToken;
  const answers = [mint.status];
  const go = async (...a) => { const r = await api(url, ...a, ws); answers.push(r.status); return r; };
  await go('POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'mcp' } });
  await go('POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'llm' } });
  await go('POST', '/api/keys', { key: { name: 'narrow', owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] } });
  await go('POST', '/api/keys/key-0006/stored-call', { call: { service: 'mcp' } });
  await go('PUT', `/api/people/${C.castOwner}`, { person: { active: false } });
  await go('POST', '/api/keys/key-0006/stored-call', { call: { service: 'mcp' } });
  await go('POST', '/api/sensors', { sensor: { name: 'node sensor' } });
  await go('PUT', '/api/sensors/fid-006/policy', { policy: { mode: 'enforce', scope: { namespaces: [C.castNs] }, actions: { 'ai-agent': 'allow', 'mcp-server': 'warn', 'model-server': 'deny' } } });
  await go('POST', '/api/sensors/fid-006/reports', { report: { node: C.castNode1, body: { findings: FINDINGS } } });
  await go('POST', '/api/clock', { clock: { minutes: 5 } });
  await go('POST', '/api/issuers/kube/actions', { action: { action: 'rotate' } });
  await go('POST', '/api/verify', { verify: { token, service: 'nope' } }); // a request turned away before any decision
  return answers;
}

test('Live: each decision the engine makes is one stdout line, one run id per action, no word a shared matcher reads, and no shared matcher reads any line', async () => {
  const lines = [];
  await withServer(async (url) => {
    const answers = await liveSession(url, 'w-obs-live');
    assert.equal(answers.at(-1), 400, 'the last request was turned away');
    assert.equal(lines.length, 1 + 2 + 2 + 1 + 2 + 1 + 2 + 1 + 1 + 4 + 1, 'mint 1, verify 2 and 2, key 1, stored key 2, person 1, stored key 2, sensor 1, policy 1, report 4, the turned-away request 1; a clock move and a key rotation none');
    for (const l of lines) checkLine(l);
    const steps = lines.map((l) => / step=(\S+)/.exec(l)[1]);
    for (const s of ['issue', 'identity-check', 'gateway-verdict', 'key-created', 'custodian', 'person-set', 'sensor-enrolled', 'policy-set', 'sensor-policy', 'request']) assert.ok(steps.includes(s), `${s} was written`);
    // one run id per action: its lines share it, ids are unique across actions, and a request turned away has no run
    const byRun = Map.groupBy(lines.filter((l) => !/ run=-$/.test(l)), (l) => / run=(\S+)$/.exec(l)[1]);
    assert.deepEqual([...byRun.values()].map((v) => v.length), [1, 2, 2, 1, 2, 1, 2, 1, 1, 4]);
    assert.equal(lines.filter((l) => / run=-$/.test(l)).length, 1); assert.match(lines.at(-1), / step=request layer=lab actor=- result=stopped cause=bad-request run=-$/);
    // results: a verdict is passed or stopped at the step it stopped at, issuance and a change are `unclear`, only an enforced stop is `stopped` among the policy lines
    assert.ok(lines.some((l) => / step=gateway-verdict .* actor=fid-001 result=passed cause=accepted /.test(l)));
    assert.ok(lines.some((l) => / step=gateway-verdict .* actor=fid-001 result=stopped cause=stopped-at-permission /.test(l)));
    assert.ok(lines.some((l) => / step=gateway-verdict .* actor=key-0006 result=stopped cause=custodian-inactive /.test(l)));
    assert.deepEqual(lines.filter((l) => / step=sensor-policy /.test(l)).map((l) => /result=(\S+) cause=(\S+)/.exec(l).slice(1, 3).join(':')), ['stopped:enforced', 'unclear:outside-policy']);
    assert.ok(lines.filter((l) => / step=(issue|key-created|person-set|policy-set|sensor-enrolled|identity-check) /.test(l)).every((l) => / result=unclear /.test(l)), 'information is never a pass');
    // the lab clock is in the line as labtime, the line's own time is the wall clock
    assert.ok(lines.filter((l) => !/ run=-$/.test(l)).every((l) => /labtime=2026-11-02T\d\d:\d\d:\d\d\.\d{3}Z/.test(l)));
    // nothing is written for a read, for a Mock table, or for a write Mock refuses
    const before = lines.length;
    await get(url, '/api/state?mode=mock&vertical=finance'); await get(url, '/api/state?mode=live&vertical=finance', { 'x-workspace': 'w-obs-live' }); await record(url);
    assert.equal((await api(url, 'POST', '/api/tokens/mint', { mode: 'mock', mint: { issuer: 'kube' } }, 'w-obs-live')).status, 409);
    assert.equal(lines.length, before);
    // Live decisions are not a Real record: with no gateway check there is nothing received, so nothing to show
    await toReal(url);
    assert.equal((await record(url)).record, null);
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
});

test('every step and cause the lab can write passes the shared matchers, for every hostile actor, with no field stripped', () => {
  const at = '2026-11-02T09:00:00.000Z';
  const evs = [];
  for (const cause of ['accepted', 'no-node-claim', ...Object.values(STOPPED_AT).map((w) => `stopped-at-${w}`), ...Object.values(KEY_TURNED_AWAY).map(([c]) => c)]) evs.push({ step: 'gateway-verdict', layer: 'gateway', cause, outcome: cause === 'accepted' ? 'allowed' : 'refused' });
  for (const [outcome, cause] of Object.values(EFFECT)) evs.push({ step: 'sensor-policy', layer: 'privilege', cause, outcome });
  for (const step of ['issue', 'identity-check', 'custodian', 'identity-created', 'identity-saved', 'identity-removed', 'key-created', 'key-saved', 'key-removed', 'sensor-enrolled', 'policy-set', 'person-set']) evs.push({ step, layer: 'privilege', cause: step, outcome: 'info' });
  const replies = [
    ['tools/list', { ok: true, tools: [{}] }], ['tools/list', { ok: true, tools: [] }], ['tools/list', { ok: false, refusal: { status: 401 } }], ['tools/list', { ok: false, refusal: { status: 403 } }], ['tools/list', { ok: false, refusal: { status: 500 } }],
    ['probe', { ok: true, isError: true, text: 'x' }], ['probe', { ok: true, isError: false, text: 'x' }], ['probe', { ok: true, isError: false, text: '' }], ['probe', { ok: false, refusal: { status: null, message: 'boom' } }],
    ['probe', { ok: false, refusal: { status: null, message: 'reply is not JSON' } }], ['probe', { ok: false, refusal: { status: 403 } }],
  ];
  for (const [step, r] of replies) evs.push({ ...replyOf(step, r), step: step === 'probe' ? 'gateway-probe' : 'gateway-list', layer: 'gateway' });
  evs.push({ step: 'gateway-list', layer: 'gateway', noReply: true, cause: 'no-reply' }, { step: 'request', layer: 'lab', cause: 'bad-request', outcome: 'refused' });
  const actors = ['fid-001', 'key-0006', 'lab_agent', 'evil result=passed cause=x', 'a@b.example.com', '10.1.2.3', fragments('sk_', 'live_', 'a1B2c3D4e5F6g7H8i9J0k1L2'), 'x'.repeat(300), 'REFUSED_TOKEN', 'denied scope audience', 'a\nb\rc', 'forbidden/invalid:expired@mismatch', '-'];
  let n = 0;
  for (const ev of evs) for (const who of actors) { checkLine(decisionLine({ ...ev, who, labtime: at }, at, ev.step === 'request' ? '-' : 'run-1')); n += 1; }
  assert.equal(n, evs.length * actors.length);
  assert.match(decisionLine({ step: 'gateway-list', layer: 'gateway', who: 'lab', noReply: true, cause: 'no-reply' }, at, 'r'), / result=no-reply cause=no-reply run=r$/);
  // a typed name cannot add a second result, an email or an address is masked like the row, a word a matcher reads is removed
  assert.equal(decisionLine({ step: 'issue', layer: 'agent', who: 'a b\nresult=passed run=x', outcome: 'info', cause: 'issued' }, 'T', 'r').split(' ').filter((p) => p.startsWith('result=')).length, 1);
  assert.match(decisionLine({ step: 'issue', layer: 'agent', who: 'a@b.example.com', outcome: 'info', cause: 'issued' }, 'T', 'r'), / actor=_email_ /);
  assert.match(decisionLine({ step: 'issue', layer: 'agent', who: '10.1.2.3', outcome: 'info', cause: 'issued' }, 'T', 'r'), / actor=_ip_ /);
  assert.match(decisionLine({ step: 'issue', layer: 'agent', who: 'REFUSED_TOKEN', outcome: 'info', cause: 'issued' }, 'T', 'r'), / actor=_+ /);
  assert.equal(lineValue('a b\nc=d'), 'a_b_c_d'); assert.equal(lineValue(''), '-'); assert.equal(lineValue(undefined), '-');
  assert.equal(createMasker().mask('10.1.2.3'), '<ip>');
});

test('what a visitor types never reaches a line: an identity name, a claim, a subject and a credential-shaped value, each tried against the real engine', async () => {
  const lines = [];
  const secret = fragments('sk_', 'live_', 'a1B2c3D4e5F6g7H8i9J0k1L2');
  const typed = ['result=passed', 'FAKE decision step=x', 'forged-subject', 'evil@example.com'];
  await withServer(async (url) => {
    const ws = 'w-obs-hostile';
    const created = await api(url, 'POST', '/api/identities', { identity: { name: `${typed[0]} ${typed[1]}`, description: typed[3], platform: 'oidc', scopes: ['mcp'], federation: { issuer: 'https://kube-api.cluster-a.example', subject: typed[2], audience: GW, jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks' } } }, ws);
    assert.equal(created.status, 200, JSON.stringify(created.body).slice(0, 200));
    const mint = await api(url, 'POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: typed[2], aud: GW, extra: { note: typed[1] } } } }, ws);
    await api(url, 'POST', '/api/verify', { verify: { token: mint.body.result.mintedToken, service: 'mcp' } }, ws);
    await api(url, 'POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: secret, aud: GW } } }, ws); // credential-shaped: turned away
    await api(url, 'POST', '/api/verify', { verify: { token: secret, identityId: typed[1], service: 'mcp' } }, ws);
    const text = lines.join('\n');
    assert.ok(lines.length >= 4);
    for (const l of lines) checkLine(l);
    for (const t of [...typed, secret, mint.body.result.mintedToken.slice(0, 30)]) assert.ok(!text.includes(t), `typed text in a line: ${t}`);
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
});

// ---- Real: what the lab received from the Privilege gateway ---------------------------------------------------------------------------------------
test('Real: a gateway check is one stdout line and one `response` row per reply, at the time the lab had the reply; the key and the gateway address are in neither', async () => {
  const lines = [];
  let t = Date.UTC(2026, 10, 22, 12, 0, 0);
  const runLog = createRunLog({ write: (l) => lines.push(l), clock: () => { t += 250; return t; } });
  await withGateway(async (url, gw) => {
    gw.script.list = ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: `tool-${KEY}`, description: `see ${gw.url}` }, { name: 'b', description: 'c' }] } });
    gw.script.call = ({ json }) => json({ message: `denied for ${KEY} at ${gw.url}` }, 403);
    // Mock first: the check is turned away, and the record route answers a Mock record
    assert.equal((await post(url, '/api/gateway-check', {})).status, 409);
    assert.equal((await record(url)).record.source, 'mock');
    await toReal(url);
    const out = await check(url);
    assert.equal(out.listing.ok, true); assert.equal(out.refusal.ok, false); assert.match(out.runId, /^gw-[0-9a-f]{6}-\d+$/);
    const { record: rec } = await record(url, `?runId=${out.runId}`);
    assert.deepEqual(assertRunObservability(rec), []);
    assert.equal(rec.source, 'real'); assert.equal(rec.runId, out.runId);
    assert.deepEqual(rows(rec).map((r) => [r.layer, r.outcome, r.origin]), [['gateway', 'allowed', 'response'], ['gateway', 'refused', 'response']]);
    assert.ok(rec.rows.every((r) => r.origin !== 'logged' && r.origin !== 'simulated' && !r.basis && !r.matchedBy));
    assert.deepEqual(rec.coverage, { person: 'not-logged', agent: 'not-logged', authorize: 'not-logged', privilege: 'not-logged', gateway: 'response', resource: 'not-logged' });
    assert.match(rec.reasons.privilege, /stay in its local engine in Real too/);
    assert.match(rows(rec)[0].message, /2 tools/); assert.match(rows(rec)[1].message, /HTTP 403 while the lab was opening or making the refusal probe.*answer the probe expects/s);
    assert.match(rows(rec)[0].message, /reply the lab received, not a gateway log line/);
    const mine = JSON.stringify(rec) + lines.join('\n');
    assert.ok(!mine.includes(KEY) && !mine.includes(`:${gw.port}`) && !mine.includes('127.0.0.1'), 'no key and no gateway address in the record or the lines');
    assert.ok(!JSON.stringify(out).includes(KEY), 'and no key in the answer');
    assert.equal(gw.seen.find((s) => s.method === 'tools/list').auth, `Bearer ${KEY}`, 'the lab did send the key to the gateway');
    // two lines, one per row, with the row's own time
    assert.equal(lines.length, 2); lines.forEach(checkLine);
    assert.deepEqual(lines.map((l) => l.split(' ')[0]), rows(rec).map((r) => r.atExact));
    assert.match(lines[0], / step=gateway-list layer=gateway actor=lab_agent result=passed cause=tools-listed run=gw-/);
    assert.match(lines[1], / step=gateway-probe .* result=stopped cause=status-403 run=gw-/);
    // the page-facing answer carries the run id and the trace as before, and the masked answer keeps the id readable
    assert.ok(out.trace.listing && out.trace.refusal);
  }, { runLog });
});

test('Real: the time of a row is the time of the reply, not the time the helper finished waiting for the session to close', async () => {
  const lines = [];
  await withGateway(async (url, gw) => {
    gw.script.list = tools(2); gw.script.call = status(403); gw.closeDelayMs = 500; // each helper call waits half a second after its answer
    await toReal(url);
    const out = await check(url); const ended = Date.now();
    const { record: rec } = await record(url, `?runId=${out.runId}`);
    const [list, probe] = rows(rec).map((r) => Date.parse(r.atExact));
    assert.ok(ended - list >= 900, `tools/list was answered before BOTH closes: ${ended - list} ms before the end`);
    assert.ok(ended - probe >= 450 && probe > list + 400, `the probe was answered before its own close: ${ended - probe} ms before the end`);
    assert.deepEqual(lines.map((l) => l.split(' ')[0]), rows(rec).map((r) => r.atExact), 'the line says the same time as the row');
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
});

test('Real: how each kind of reply is read (401 and 403 refused, a usable 200 allowed, a JSON-RPC error or isError refused, an unparsed body or another status information)', async () => {
  const cases = [
    { name: 'list 401', list: status(401), want: [['refused', 'status-401']], probeSent: false },
    { name: 'list 403', list: status(403), want: [['refused', 'status-403']], probeSent: false },
    { name: 'list 500', list: status(500), want: [['info', 'status-500']], probeSent: false },
    { name: 'list not JSON', list: rawText, want: [['info', 'unreadable']], probeSent: false },
    { name: 'list JSON-RPC error', list: rpcError('no'), want: [['refused', 'jsonrpc-error']], probeSent: false },
    { name: 'list empty', list: tools(0), call: status(403), want: [['info', 'empty-list'], ['refused', 'status-403']] },
    { name: 'probe 401', list: tools(2), call: status(401), want: [['allowed', 'tools-listed'], ['refused', 'status-401']] },
    { name: 'probe isError', list: tools(2), call: rpcResult({ isError: true, content: [{ type: 'text', text: 'no' }] }), want: [['allowed', 'tools-listed'], ['refused', 'tool-error']] },
    { name: 'probe JSON-RPC error', list: tools(2), call: rpcError('policy says no'), want: [['allowed', 'tools-listed'], ['refused', 'jsonrpc-error']] },
    { name: 'probe 200 with a result', list: tools(2), call: rpcResult({ content: [{ type: 'text', text: 'ok' }] }), want: [['allowed', 'tools-listed'], ['allowed', 'tool-ran']] },
    { name: 'probe 200 with nothing to read', list: tools(2), call: rpcResult({ content: [] }), want: [['allowed', 'tools-listed'], ['info', 'no-content']] },
    { name: 'probe 502', list: tools(2), call: status(502), want: [['allowed', 'tools-listed'], ['info', 'status-502']] },
    { name: 'probe not JSON', list: tools(2), call: rawText, want: [['allowed', 'tools-listed'], ['info', 'unreadable']] },
  ];
  for (const c of cases) {
    const lines = [];
    await withGateway(async (url, gw) => {
      gw.script.list = c.list; gw.script.call = c.call || status(418, 'the probe must not be sent');
      await toReal(url);
      const out = await check(url);
      const { record: rec } = await record(url, `?runId=${out.runId}`);
      assert.deepEqual(assertRunObservability(rec), [], c.name);
      assert.deepEqual(rows(rec).map((r) => r.outcome), c.want.map((w) => w[0]), c.name);
      assert.deepEqual(lines.map((l) => /cause=(\S+)/.exec(l)[1]), c.want.map((w) => w[1]), c.name);
      if (c.probeSent === false) {
        assert.ok(!gw.seen.some((s) => s.method === 'tools/call'), c.name);
        assert.match(rec.reasons.gateway, /only sent after tools\/list is answered with a tool list/, c.name);
      }
      assert.ok(rows(rec).every((r) => r.origin === 'response'));
      assert.deepEqual(rec.partial, {}, `${c.name}: every call that was made got a reply`);
    }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
  }
});

test('Real: a call that got no reply is no row and no pass: a no-reply line, the layer says why, and the record is partial', async () => {
  const lines = [];
  await withGateway(async (url, gw) => {
    await toReal(url);
    gw.script.list = drop; gw.script.call = status(403);
    let out = await check(url);
    assert.equal(out.listing.ok, false);
    let { record: rec } = await record(url, `?runId=${out.runId}`);
    assert.equal(rows(rec).length, 0); assert.equal(rec.coverage.gateway, 'not-logged'); assert.match(rec.reasons.gateway, /tools\/list call got no reply.*absence is not proof/s);
    assert.deepEqual(rec.partial, { gateway: true }); assert.deepEqual(assertRunObservability(rec), []);
    assert.match(lines.at(-1), / step=gateway-list .* result=no-reply cause=no-reply run=gw-/);
    // the list answered, the probe was dropped: one row, the other named in the layer's reason; the earlier answer is not borrowed for it
    gw.script.list = tools(3); gw.script.call = drop;
    out = await check(url);
    ({ record: rec } = await record(url, `?runId=${out.runId}`));
    assert.deepEqual(rows(rec).map((r) => r.outcome), ['allowed']);
    assert.equal(rec.coverage.gateway, 'response'); assert.match(rec.reasons.gateway, /refusal probe got no reply/); assert.deepEqual(rec.partial, { gateway: true });
    assert.match(lines.at(-1), / step=gateway-probe .* result=no-reply /);
    assert.deepEqual(assertRunObservability(rec), []);
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
});

test('the mode is stored on the run: a Real run is never answered in Mock and a Mock record never in Real; an attempt that began no run does not change the answer; Reset keeps the check', async () => {
  await withGateway(async (url, gw) => {
    gw.script.list = tools(2); gw.script.call = status(403);
    await toReal(url);
    assert.equal((await record(url)).record, null, 'before any check: no run, and the message says so');
    const first = await check(url);
    assert.equal((await record(url)).record.runId, first.runId, 'the newest run');
    // attempts that never reach the gateway make no run and change nothing
    assert.equal((await post(url, '/api/gateway-check', { app: 'no-such-door' })).status, 400);
    assert.equal((await post(url, '/api/gateway-check', { bogus: 1 })).status, 400);
    assert.equal((await record(url)).record.runId, first.runId);
    // back to Mock: the same run id gets a Mock record (never the Real run), and Real comes back with the Real run again
    await toMock(url);
    const m = await record(url, `?runId=${first.runId}&vertical=finance&scenario=one-credential`);
    assert.equal(m.record.source, 'mock'); assert.notEqual(m.record.runId, first.runId);
    assert.equal((await post(url, '/api/gateway-check', {})).status, 409);
    await toReal(url);
    assert.equal((await record(url, `?runId=${first.runId}`)).record.source, 'real');
    // Reset clears this workspace's engines and nothing else: the gateway check is not the engine's
    assert.equal((await post(url, '/api/reset', {}, { 'x-workspace': 'w-obs-reset' })).status, 200);
    assert.equal((await record(url, `?runId=${first.runId}`)).record.runId, first.runId);
    assert.deepEqual(await record(url, '?runId=gw-000000-1'), { record: null, message: 'That gateway check is no longer kept (the lab keeps the last few).' });
  });
});

test('Real runs are kept in a bounded list, newest last, with ids that never repeat; the id is unique across checks and Live actions; an open run is never evicted', async () => {
  await withGateway(async (url, gw) => {
    gw.script.list = tools(1); gw.script.call = status(403);
    await toReal(url);
    const ids = [];
    for (let i = 0; i < KEEP_RUNS + 3; i += 1) ids.push((await check(url)).runId);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal((await record(url)).record.runId, ids.at(-1));
    assert.equal((await record(url, `?runId=${ids.at(-KEEP_RUNS)}`)).record.runId, ids.at(-KEEP_RUNS), 'the oldest kept run is still there');
    assert.equal((await record(url, `?runId=${ids[0]}`)).record, null, 'an evicted run says so');
  });
  const live1 = []; const log = createRunLog({ write: (l) => live1.push(l) });
  const a = log.beginCheck('lab-agent'); const b = log.beginCheck('lab-agent'); a.end(); b.end();
  log.live([{ step: 'issue', layer: 'agent', who: '-', outcome: 'info', cause: 'issued' }], 'T');
  assert.equal(new Set([a.id, b.id, / run=(\S+)$/.exec(live1[0])[1]]).size, 3);
  const open = log.beginCheck('lab-agent'); for (let i = 0; i < KEEP_RUNS + 2; i += 1) log.beginCheck('x').end();
  assert.equal(log.get(open.id), null); open.end(); assert.equal(log.get(open.id).id, open.id);
  assert.notEqual(createRunLog().beginCheck('x').id, createRunLog().beginCheck('x').id, 'two logs (a restart) never share an id');
});

test('a Real record is built from the lab\'s own events alone and keeps no word of the gateway\'s', async () => {
  const run = { id: 'gw-abcdef-1', startedAt: '2026-11-22T12:00:00.000Z', endedAt: '2026-11-22T12:00:01.000Z', notes: [], noReply: false, events: [{ ...replyOf('tools/list', { ok: true, tools: [{ name: 'x' }], ms: 5 }), at: '2026-11-22T12:00:00.500Z', layer: 'gateway', product: 'Privilege gateway reply', who: 'lab_agent' }] };
  const rec = await realRecord(run);
  assert.deepEqual(assertRunObservability(rec), []);
  assert.deepEqual(rows(rec).map((r) => r.detail), [{ step: 'tools/list', tools: 1, ms: 5, eventSeq: 0 }]);
  assert.equal(replyOf('probe', null), null); assert.equal(replyOf('probe', 'text'), null);
});

test('a recorder that throws never breaks the run or the audit: the lab answers as before and says why on stderr', async () => {
  const boom = () => { throw Object.assign(new Error('recorder is broken'), { code: 'E_BOOM' }); };
  const baseline = createWorkspaces({ makeRand: () => seededRand('http') });
  const base = []; await withServer(async (url) => { base.push(await liveSession(url, 'w-obs-boom')); }, { workspaces: baseline });
  let answers; let out;
  const err = await stderrOf(async () => {
    await withGateway(async (url, gw, { workspaces }) => {
      gw.script.list = tools(1); gw.script.call = status(403);
      answers = await liveSession(url, 'w-obs-boom');
      assert.equal(JSON.stringify(workspaces.peek('w-obs-boom', 'finance').s.audit), JSON.stringify(baseline.peek('w-obs-boom', 'finance').s.audit), 'the audit trail is the baseline\'s');
      await toReal(url);
      out = await check(url);
      const rec = await get(url, '/api/run-observability');
      assert.equal(rec.status, 500); assert.deepEqual(Object.keys(await rec.json()).sort(), ['error', 'message']);
    }, { runLog: { live: boom, beginCheck: boom, get: boom } });
  });
  assert.deepEqual(answers, base[0], 'every answer is the baseline\'s');
  assert.equal(out.listing.ok, true); assert.equal(out.runId, undefined, 'no run was kept, and the answer says nothing about one');
  assert.match(err, /run observability: live-decisions E_BOOM \(the error's text is not logged\)/); assert.match(err, /run observability: begin-check E_BOOM/); assert.match(err, /run observability: record E_BOOM/);
  assert.ok(!/recorder is broken/.test(err), 'the error text is not on stderr');
});

test('one failed write does not drop the rest of an action\'s lines, and stderr carries a code and a fixed text, never the error\'s own text or a key', async () => {
  const run = async (write) => {
    const workspaces = createWorkspaces({ makeRand: () => seededRand('http') }); let answers;
    await withServer(async (url) => { answers = await liveSession(url, 'w-obs-write'); }, { runLog: createRunLog({ write }), workspaces });
    return { answers, audit: JSON.stringify(workspaces.peek('w-obs-write', 'finance').s.audit) };
  };
  const base = []; const baseline = await run((l) => base.push(l));
  // The write that fails must NOT be the last line of its action, or a loop that drops the rest of the action would pass unseen.
  const runOf = (l) => l.match(/ run=(\S+)/)?.[1];
  const DROP = base.findIndex((l, i) => i + 1 < base.length && runOf(base[i + 1]) === runOf(l));
  assert.ok(DROP >= 0, 'the run has an action with two or more lines');
  const got = []; let n = 0; let thrown;
  const err = await stderrOf(async () => { thrown = await run((l) => { if (++n === DROP + 1) throw Object.assign(new Error(`disk full ${KEY} https://gateway.example.invalid`), { code: 'E_DISK' }); got.push(l); }); });
  assert.equal(n, base.length, 'every line was still tried');
  const same = (l) => l.split(' ').slice(1).join(' ').replace(/ run=\S+$/, '').replace(/ labtime=\S+/, '');
  assert.deepEqual(got.map(same), base.filter((_l, i) => i !== DROP).map(same), 'all lines but the one that could not be written');
  assert.deepEqual(thrown.answers, baseline.answers); assert.equal(thrown.audit, baseline.audit);
  assert.equal([...err.matchAll(/run observability: live-line E_DISK/g)].length, 1, 'the failure is reported once, on stderr');
  assert.ok(!err.includes(KEY) && !/gateway\.example|disk full/.test(err), err);
});

test('a reply that carries the key and the gateway address in every field it could keeps both out of the record', async () => {
  const text = {};
  await withGateway(async (url, gw) => {
    gw.script.list = ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: KEY, description: gw.url }] } });
    for (const call of [status(403, `${KEY} ${gw.url} Bearer ${KEY}`), rpcResult({ isError: true, content: [{ type: 'text', text: `${KEY} ${gw.url}` }] }), rpcError(`${KEY} ${gw.url}`)]) {
      gw.script.call = call;
      await toReal(url);
      const out = await check(url);
      text[out.runId] = JSON.stringify((await record(url, `?runId=${out.runId}`)).record);
    }
  });
  assert.equal(Object.keys(text).length, 3);
  for (const t of Object.values(text)) assert.ok(!t.includes(KEY) && !t.includes('127.0.0.1') && !/Bearer \w/.test(t));
});

test('a refusal that arrives while the lab is opening a call is not worded as the answer to tools/list, and a failure with the shared client\'s own "unreachable" or "timed out" words is no connection and never allowed', async () => {
  const cases = [
    { name: 'initialize 403', set: (g) => { g.initFail = 403; }, cause: 'status-403' },
    { name: 'initialize 401', set: (g) => { g.initFail = 401; }, cause: 'status-401' },
    { name: 'notifications/initialized 401', set: (g) => { g.notifyFail = 401; }, cause: 'status-401' },
    { name: 'initialize JSON-RPC error', set: (g) => { g.initRpcError = true; }, cause: 'jsonrpc-error' },
  ];
  for (const c of cases) {
    const lines = [];
    await withGateway(async (url, gw) => {
      c.set(gw); gw.script.list = tools(2); gw.script.call = status(403);
      await toReal(url);
      const out = await check(url);
      assert.ok(!gw.seen.some((s) => s.method === 'tools/list'), `${c.name}: tools/list was never sent`);
      const { record: rec } = await record(url, `?runId=${out.runId}`);
      const [row] = rows(rec);
      assert.equal(row.outcome, 'refused', c.name);
      assert.match(row.message, /while the lab was opening or making tools\/list/, c.name);
      assert.ok(!/answered tools\/list with/.test(row.message), c.name);
      assert.notEqual(row.detail.step, 'tools/list'); assert.equal(row.detail.during, 'tools/list');
      assert.match(lines[0], new RegExp(`cause=${c.cause} `));
    }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
  }
  assert.equal(replyOf('tools/list', { ok: true, tools: [{}], ms: 1 }).detail.step, 'tools/list');
  assert.equal(replyOf('probe', { ok: true, isError: true, text: 'x', ms: 1 }).detail.step, 'probe');
  for (const words of ['MCP HTTP request unreachable (ECONNREFUSED)', 'MCP HTTP request timed out after 15000ms']) {
    await withGateway(async (url, gw) => {
      gw.script.list = rpcError(words); gw.script.call = status(403);
      await toReal(url);
      const out = await check(url);
      const { record: rec } = await record(url, `?runId=${out.runId}`);
      assert.equal(rows(rec).length, 0, 'no row, so nothing shown as allowed'); assert.ok(!rec.rows.some((r) => r.outcome === 'allowed'));
      assert.match(rec.reasons.gateway, /did not connect, or it timed out/);
      assert.match(rec.reasons.gateway, /exactly the shared client's "unreachable" or "timed out" words as no connection.*could, in rare cases, be read this way.*never shown as allowed/s);
      assert.deepEqual(assertRunObservability(rec), []);
    });
  }
});

test('the Real record and the stdout line do not depend on a declared caller id: no row carries the caller label, a plain label stays readable, a key-shaped one is masked whole', async () => {
  const label = fragments('SK_LIVE_', 'A1B2C3D4E5F6G7H8'); const secretLike = fragments('sk_live_', 'a1b2c3d4e5f6g7h8');
  const seen = {};
  for (const [name, key] of [['plain', 'LAB_AGENT'], ['secretLike', label], ['words', 'REFUSED_TOKEN']]) {
    const lines = [];
    await withGateway(async (url, gw) => {
      gw.script.list = tools(2); gw.script.call = status(403);
      await toReal(url);
      const out = await check(url);
      assert.equal(out.listing.ok, true);
      seen[name] = { rec: (await record(url, `?runId=${out.runId}`)).record, lines: [...lines] };
    }, { runLog: createRunLog({ write: (l) => lines.push(l) }), label: key });
  }
  const strip = (rec) => rec.rows.map(({ id, at, atExact, detail, ...r }) => ({ ...r, detail: { ...detail, ms: 0 } }));
  assert.deepEqual(strip(seen.plain.rec), strip(seen.secretLike.rec), 'rows do not carry the caller label at all');
  assert.ok(seen.plain.lines.every((l) => / actor=lab_agent /.test(l)), 'a plain label stays readable');
  for (const l of seen.secretLike.lines) { checkLine(l); assert.ok(!l.includes(secretLike) && !/sk_l|_ef /.test(l), l); }
  for (const l of seen.words.lines) checkLine(l);
  assert.ok(!JSON.stringify(seen.secretLike.rec).includes(secretLike));
});

test('the lab is core only: no server file names a log reader, and the exemption in entry.test.js is the one exact file name', () => {
  const entry = fs.readFileSync(new URL('./entry.test.js', import.meta.url), 'utf8');
  assert.match(entry, /const BUILDS_PATTERNS = 'runObservability\.js';/);
  assert.equal((entry.match(/BUILDS_PATTERNS/g) || []).length, 2, 'named once and used once');
  assert.match(entry, /if \(f !== BUILDS_PATTERNS\) assert\.ok\(!\/new RegExp/);
});
