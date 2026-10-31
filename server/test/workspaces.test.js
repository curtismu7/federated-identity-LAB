import test from 'node:test';
import assert from 'node:assert/strict';
import { WORKSPACE_RE, createWorkspaces, workspaceFrom } from '../src/workspaces.js';
import { VERTICALS } from '../src/cast.js';
import { codeOf } from './helpers.js';

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
