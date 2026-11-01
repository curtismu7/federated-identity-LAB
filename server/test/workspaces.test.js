import test from 'node:test';
import assert from 'node:assert/strict';
import { WORKSPACE_RE, createWorkspaces, validWorkspaceId, workspaceFrom } from '../src/workspaces.js';
import { VERTICALS } from '../src/cast.js';
import { codeOf, get, post, withServer } from './helpers.js';

const C = VERTICALS.finance;
test('workspaceFrom defaults, accepts a good id and refuses a bad, hex-looking or credential-looking one', () => {
  assert.equal(workspaceFrom({ headers: {} }), 'default');
  assert.equal(workspaceFrom({ headers: { 'x-workspace': 'abc-1' } }), 'abc-1');
  assert.equal(workspaceFrom({ headers: { 'x-workspace': 'w-0123456789abcdef' } }), 'w-0123456789abcdef');
  for (const bad of ['', 'A', 'a b', 'a/b', 'x'.repeat(41), ['a'], '__proto__', 'deadbeef'.repeat(4), '0123456789abcdef01234567']) assert.equal(workspaceFrom({ headers: { 'x-workspace': bad } }), null, String(bad));
  assert.ok(WORKSPACE_RE.test('a'));
});

test('engines are per workspace and per vertical, created on first use, and reset clears the workspace only', () => {
  const w = createWorkspaces();
  const a = w.engine('a', 'finance', C); const a2 = w.engine('a', 'finance', C); const ah = w.engine('a', 'health', VERTICALS.health); const b = w.engine('b', 'finance', C);
  assert.equal(a, a2); assert.notEqual(a, ah); assert.notEqual(a, b);
  assert.equal(w.peek('a', 'finance'), a); assert.equal(w.peek('zzz', 'finance'), null); assert.equal(w.peek('a', 'retail'), null);
  assert.equal(w.size(), 2, 'a peek never creates a workspace');
  w.reset('a');
  assert.equal(w.peek('a', 'finance'), null); assert.equal(w.peek('b', 'finance'), b);
});

test('the store expires idle workspaces and REFUSES a new one at the cap instead of evicting another', () => {
  let t = 0;
  const w = createWorkspaces({ max: 3, ttlMs: 100, now: () => t });
  for (const id of ['a', 'b', 'c']) w.engine(id, 'finance', C);
  assert.equal(codeOf(() => w.engine('d', 'finance', C)), 'workspaces_full');
  assert.ok(w.peek('a', 'finance'), 'nobody was evicted'); assert.equal(w.size(), 3);
  w.engine('a', 'finance', C);
  t = 150;
  assert.equal(w.peek('b', 'finance'), null, 'idle ones expire');
  assert.ok(w.engine('d', 'finance', C));
});

test('each engine gets its own random source', () => {
  let made = 0; const w = createWorkspaces({ makeRand: () => { made += 1; return () => Buffer.alloc(8, made); } });
  assert.notEqual(w.engine('a', 'finance', C).enrollSensor({}).audience, w.engine('b', 'finance', C).enrollSensor({}).audience);
});

test('a credential-looking workspace id is refused, not accepted and echoed masked (N3)', async () => {
  const bad = ['sk-abcdefghijklmnop', 'my-sk-abcdefghijklmnop', 'glpat-abcdefghijkl', 'xoxb-12345678', 'xoxp-abcdefgh', 'sk-' + 'a'.repeat(30)];
  const fine = ['sk-short', 'task-abcdefghijklmnop', 'sk', 'xoxb-1234567', 'glpat-abcdefghijk', 'w-0123456789abcdef', 'visitor-12'];
  for (const id of bad) assert.equal(workspaceFrom({ headers: { 'x-workspace': id } }), null, id);
  for (const id of fine) assert.equal(workspaceFrom({ headers: { 'x-workspace': id } }), id, id);
  assert.equal(validWorkspaceId('g'.repeat(40)), true); assert.equal(validWorkspaceId('g'.repeat(41)), false);
  await withServer(async (url) => {
    for (const id of bad) {
      for (const r of [await get(url, '/api/state?mode=live', { 'x-workspace': id }), await post(url, '/api/clock', { mode: 'live', clock: { minutes: 1 } }, { 'x-workspace': id }), await post(url, '/api/reset', {}, { 'x-workspace': id })]) {
        assert.equal(r.status, 400, id); const text = await r.text(); assert.deepEqual(JSON.parse(text), { error: 'bad_workspace' }); assert.ok(!text.includes(id.slice(0, 12)));
      }
    }
    assert.equal((await get(url, '/api/state?mode=live', { 'x-workspace': 'task-abcdefghijklmnop' })).status, 200);
  });
});
