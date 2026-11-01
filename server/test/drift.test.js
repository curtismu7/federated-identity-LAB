// The Mock tables are generated from the engine. A test fails if they drift, if the talk-track doc drifts, and if the HTTP API (Live) gives a different final
// state than the scripted run for the same steps (with the same deterministic random source).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MOCK_TABLE } from '../src/mockTable.js';
import { EXPECTED, buildMockTable, runScenario, scenarioList } from '../src/scenarios.js';
import { VERTICALS, DEFAULT_CAST } from '../src/cast.js';
import { renderTalkTrackMarkdown } from '../src/story.js';
import { OP_NAMES } from '../src/actions.js';
import { tamperToken } from '../src/jwt.js';
import { createWorkspaces } from '../src/workspaces.js';
import { seededRand } from '../src/scenarios.js';
import { api, withServer, get, json, W } from './helpers.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('the committed Mock table is exactly what the engine generates now (run `npm run mock-table` after a change)', () => {
  assert.deepEqual(MOCK_TABLE, buildMockTable());
});

test('every scripted step gives the result the story says, in every vertical, and every scenario has a say', () => {
  for (const [v, cast] of Object.entries(VERTICALS)) {
    for (const sc of scenarioList(cast)) {
      const got = runScenario(cast, sc).steps.map((s) => (s.ok ? 'ok' : s.code));
      assert.deepEqual(got, EXPECTED[sc.id], `${v}/${sc.id}`);
      assert.ok(sc.say.length > 20); for (const st of sc.steps) assert.ok(st.say.length > 5);
    }
  }
  assert.deepEqual(Object.keys(EXPECTED).sort(), scenarioList(DEFAULT_CAST).map((s) => s.id).sort());
});

test('the table holds no token and no key material, only decoded claims, and every verify step list is complete', () => {
  const text = JSON.stringify(MOCK_TABLE);
  assert.ok(!/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./.test(text), 'no token');
  assert.ok(!/mintedToken|"d":"|PRIVATE KEY/.test(text));
  assert.ok(!/"n":"[A-Za-z0-9_-]{100,}"/.test(text), 'no key modulus');
  for (const sc of MOCK_TABLE.verticals.finance.scenarios) for (const st of sc.steps.filter((x) => x.op === 'verify')) assert.equal(st.result.steps.length, 15);
});

test('the Mock table agrees with the engine\'s own refusals: the steps recorded are the steps run', () => {
  const t = MOCK_TABLE.verticals.finance.scenarios.find((s) => s.id === 'fork-pr');
  assert.deepEqual(t.steps.map((s) => (s.ok ? 'ok' : s.code)), EXPECTED['fork-pr']);
  assert.equal(MOCK_TABLE.verticals.finance.scenarios.length, 14);
  const enf = MOCK_TABLE.verticals.finance.scenarios.find((s) => s.id === 'enforcement').state;
  assert.deepEqual(enf.findings.map((f) => f.effect), ['would-have-blocked', 'out-of-scope', 'warned', 'blocked', 'out-of-scope', 'warned']);
});

test('docs/talk-track.md is exactly what the talk-track data generates (run `npm run talk-track`)', () => {
  assert.equal(fs.readFileSync(path.join(root, 'docs/talk-track.md'), 'utf8'), renderTalkTrackMarkdown(DEFAULT_CAST));
});

// op -> the HTTP call the page makes
const HTTP = {
  mint: ['POST', () => '/api/tokens/mint', (p) => ({ mint: p })],
  verify: ['POST', () => '/api/verify', (p) => ({ verify: p })],
  advance: ['POST', () => '/api/clock', (p) => ({ clock: p })],
  issuer: ['POST', (p) => `/api/issuers/${p.issuer}/actions`, ({ issuer, ...r }) => ({ action: r })],
  refreshKeys: ['POST', (p) => `/api/identities/${p.identityId}/refresh`, () => ({ refresh: {} })],
  createIdentity: ['POST', () => '/api/identities', (p) => ({ identity: p })],
  updateIdentity: ['PUT', (p) => `/api/identities/${p.identityId}`, ({ identityId, ...r }) => ({ identity: r })],
  deleteIdentity: ['POST', (p) => `/api/identities/${p.identityId}/remove`, () => ({ remove: {} })],
  createKey: ['POST', () => '/api/keys', (p) => ({ key: p })],
  updateKey: ['PUT', (p) => `/api/keys/${p.keyId}`, ({ keyId, ...r }) => ({ key: r })],
  deleteKey: ['POST', (p) => `/api/keys/${p.keyId}/remove`, () => ({ remove: {} })],
  setPerson: ['PUT', (p) => `/api/people/${p.person}`, ({ person, ...r }) => ({ person: r })],
  storedKeyCall: ['POST', (p) => `/api/keys/${p.keyId}/stored-call`, ({ keyId, ...r }) => ({ call: r })],
  enrollSensor: ['POST', () => '/api/sensors', (p) => ({ sensor: p })],
  sensorReport: ['POST', (p) => `/api/sensors/${p.identityId}/reports`, ({ identityId, ...r }) => ({ report: r })],
  setPolicy: ['PUT', (p) => `/api/sensors/${p.identityId}/policy`, ({ identityId, ...r }) => ({ policy: r })],
};

test('MOCK/LIVE PARITY: replaying every scenario through the HTTP API gives exactly the state the Mock table holds', async () => {
  assert.deepEqual(Object.keys(HTTP).sort(), [...OP_NAMES].sort(), 'every op has an HTTP route');
  await withServer(async (url) => {
    let n = 0;
    for (const sc of scenarioList(VERTICALS.finance)) {
      const ws = `parity-${n++}`; let token = '';
      // every workspace gets the same deterministic random source, as the table was generated with
      for (const st of sc.steps) {
        const params = { ...st.params }; if (st.token) params.token = st.token === 'tampered' ? tamperToken(token) : token;
        const [m, route, body] = HTTP[st.op]; const r = await api(url, m, route(params), body(params), ws);
        if (st.op === 'mint' && r.body.ok) token = r.body.result.mintedToken;
        assert.equal(r.body.ok === true ? 'ok' : r.body.error, EXPECTED[sc.id][sc.steps.indexOf(st)], `${sc.id}: ${st.say}`);
      }
      const live = (await json(await get(url, '/api/state?mode=live&vertical=finance', W(ws)))).state;
      const mock = MOCK_TABLE.verticals.finance.scenarios.find((s) => s.id === sc.id).state;
      assert.deepEqual(live, mock, sc.id);
    }
  }, { workspaces: createWorkspaces({ makeRand: () => seededRand() }) });
});
