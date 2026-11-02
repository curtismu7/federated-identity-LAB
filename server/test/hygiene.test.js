// The edge of the HTTP app: one route table decides 405 (with Allow), an unknown address is a fixed JSON 404, a charset problem is a fixed 415 that logs nothing typed, the catch-all
// error handler never echoes input, and a workspace id that looks like a credential is refused (400 bad_workspace) before any slot exists. The page fallback is in static.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaces } from '../src/workspaces.js';
import { get, json, post, put, rawHttp, withServer } from './helpers.js';

// Credential-shaped values are assembled at run time, so none sits in the repository.
const H = ['hunter', '2xyz'].join('');
const BAD_IDS = [['p', 'w-', H].join(''), ['tok', 'en-', H].join(''), 'abcdefghijklmnop1234', ['s', 'k-', 'abcdefghijkl'].join(''), ['w-pass', 'word-', 'abc123'].join(''), 'deadbeef'.repeat(3), 'w-'.concat('deadbeef'.repeat(3))];

// Every route the API has, with the one method it answers. Literal list: 16 writes, the reset, 6 reads.
const WRITES = [
  ['POST', '/api/tokens/mint'], ['POST', '/api/verify'], ['POST', '/api/clock'], ['POST', '/api/issuers/kube/actions'], ['POST', '/api/identities'], ['PUT', '/api/identities/fid-001'],
  ['POST', '/api/identities/fid-001/remove'], ['POST', '/api/identities/fid-001/refresh'], ['POST', '/api/keys'], ['PUT', '/api/keys/key-001'], ['POST', '/api/keys/key-001/remove'],
  ['POST', '/api/keys/key-001/stored-call'], ['PUT', '/api/people/p-001'], ['POST', '/api/sensors'], ['POST', '/api/sensors/fid-001/reports'], ['PUT', '/api/sensors/fid-001/policy'],
];
const READS = ['/api/health', '/api/story', '/api/diagram', '/api/info', '/api/state', '/api/issuers/kube/jwks'];

const send = (url, method, path, headers = {}, body) => rawHttp(`${url}${path}`, { method, headers: { origin: url, 'content-type': 'application/json', ...headers }, body });

test('the route table: there are 16 writes, the reset and 6 reads, and a wrong method on any of them is 405 with the exact Allow, never 404', async () => {
  assert.equal(WRITES.length, 16); assert.equal(READS.length, 6);
  await withServer(async (url) => {
    let checked = 0;
    for (const [method, path] of WRITES) {
      for (const other of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
        if (other === method) continue;
        const r = await send(url, other, path);
        assert.equal(r.status, 405, `${other} ${path}`); assert.equal(r.headers.allow, method, `Allow for ${path}`); assert.deepEqual(JSON.parse(r.text), { error: 'method_not_allowed' });
        checked += 1;
      }
    }
    for (const path of [...READS, '/api/reset']) {
      const allowed = path === '/api/reset' ? 'POST' : 'GET, HEAD';
      for (const other of path === '/api/reset' ? ['GET', 'PUT', 'DELETE'] : ['POST', 'PUT', 'DELETE', 'PATCH']) {
        const r = await send(url, other, path); assert.equal(r.status, 405, `${other} ${path}`); assert.equal(r.headers.allow, allowed, `Allow for ${path}`); checked += 1;
      }
    }
    assert.equal(checked, 16 * 5 + 3 + 6 * 4, 'every wrong method was tried');
    // an unknown address, or one with an extra segment, is a 404 with no Allow header and a fixed body
    for (const [m, p] of [['POST', '/api/nope'], ['GET', '/api/identities/fid-001/remove/x'], ['DELETE', '/api/'], ['GET', '/api'], ['POST', '/api/tokens/mint/extra'], ['GET', '/api/w//']]) {
      const r = await send(url, m, p); assert.equal(r.status, 404, `${m} ${p}`); assert.equal(r.headers.allow, undefined); assert.deepEqual(JSON.parse(r.text), { error: 'not_found' });
    }
    // and the real method still works (a trailing slash too)
    assert.equal((await send(url, 'GET', '/api/info')).status, 200); assert.equal((await send(url, 'HEAD', '/api/info')).status, 200); assert.equal((await send(url, 'POST', '/api/reset/')).status, 200);
  });
});

test('a charset other than utf-8 is a fixed 415 that does not read the value into the answer, and nothing typed is logged', async () => {
  const seen = [];
  const keep = { out: process.stdout.write, err: process.stderr.write, log: console.log, error: console.error, warn: console.warn };
  // record AND forward: the test runner reports on the same streams, and a swallowed report would hide a failure
  const spy = (orig, stream) => (chunk, ...rest) => { seen.push(String(chunk)); return orig.call(stream, chunk, ...rest); };
  await withServer(async (url) => {
    process.stdout.write = spy(keep.out, process.stdout); process.stderr.write = spy(keep.err, process.stderr); console.log = (...a) => seen.push(a.join(' ')); console.error = (...a) => seen.push(a.join(' ')); console.warn = (...a) => seen.push(a.join(' '));
    const results = [];
    try {
      for (const ct of [`application/json; charset=${H}`, `application/json; charset="${H}"`, 'application/json; charset=utf-16', 'application/json; charset=utf-8; charset=latin1', 'application/json; charset', `application/json; x="a;charset=utf-8`]) {
        for (const [m, p] of [['POST', '/api/clock'], ['GET', '/api/state'], ['POST', '/api/nope']]) { const r = await send(url, m, p, { 'content-type': ct }, m === 'POST' ? '{}' : undefined); results.push([ct, r.status, r.text]); }
      }
      results.push(['utf-8 is fine', (await send(url, 'POST', '/api/clock', { 'content-type': 'application/json; charset=UTF-8', 'x-workspace': 'w-cs1' }, JSON.stringify({ mode: 'live', clock: { minutes: 1 } }))).status, '']);
    } finally { Object.assign(process.stdout, { write: keep.out }); Object.assign(process.stderr, { write: keep.err }); Object.assign(console, { log: keep.log, error: keep.error, warn: keep.warn }); }
    assert.equal(results.length, 6 * 3 + 1);
    for (const [ct, status, text] of results.slice(0, -1)) { assert.equal(status, 415, ct); assert.deepEqual(JSON.parse(text), { error: 'unsupported_charset' }, ct); }
    assert.equal(results.at(-1)[1], 200, 'charset=UTF-8 is accepted');
    assert.equal(seen.join('').includes(H), false, 'the typed charset value was not logged');
  });
});

test('the catch-all error handler: a bad body, a bad percent-escape and an over-size body answer a fixed code and never echo what was typed', async () => {
  await withServer(async (url) => {
    const cases = [
      ['POST', '/api/clock', `{"mode":"live","clock":{"minutes":"${H}`, 400, 'bad_request'],
      ['POST', '/api/clock', `[${H}]`, 400, 'bad_request'],
      ['POST', '/api/clock', JSON.stringify({ mode: 'live', pad: 'x'.repeat(40000) }), 413, 'payload_too_large'],
      ['PUT', `/api/identities/%E0%A4%A${H}`, '{}', 400, 'bad_request'],
    ];
    for (const [m, p, body, status, code] of cases) {
      const r = await send(url, m, p, { 'x-workspace': 'w-err1' }, body);
      assert.equal(r.status, status, `${m} ${p.slice(0, 30)}`); assert.deepEqual(JSON.parse(r.text), { error: code }); assert.ok(!r.text.includes(H));
    }
    assert.equal(cases.length, 4);
    const r = await send(url, 'GET', '/api/state?mode=live', { 'x-workspace': H }); assert.equal(r.status, 400); assert.deepEqual(JSON.parse(r.text), { error: 'bad_workspace' });
  });
});

test('a workspace id that looks like a credential is refused with 400 bad_workspace on every route that takes one, before a slot exists, and the id is never echoed', async () => {
  const workspaces = createWorkspaces();
  await withServer(async (url) => {
    let tried = 0;
    for (const id of BAD_IDS) {
      for (const [method, path] of [...WRITES, ['POST', '/api/reset'], ['GET', '/api/state?mode=live'], ['GET', '/api/issuers/kube/jwks?mode=live']]) {
        const r = await send(url, method, path, { 'x-workspace': id }, method === 'GET' ? undefined : JSON.stringify({ mode: 'live', vertical: 'finance' }));
        assert.equal(r.status, 400, `${id.slice(0, 8)} on ${method} ${path}`); assert.deepEqual(JSON.parse(r.text), { error: 'bad_workspace' }); assert.ok(!r.text.includes(id.slice(0, 6)));
        tried += 1;
      }
    }
    assert.equal(tried, 7 * 19);
    assert.equal(workspaces.size(), 0, 'no workspace slot was taken by a refused id');
    // a good id on the same routes works, and takes exactly one slot
    const ok = await post(url, '/api/clock', { mode: 'live', vertical: 'finance', clock: { minutes: 1 } }, { 'x-workspace': 'w-good-1' });
    assert.equal(ok.status, 200); assert.equal((await json(ok)).workspace, 'w-good-1'); assert.equal(workspaces.size(), 1);
    // an info route never takes a slot and never asks for an id
    assert.equal((await get(url, '/api/story', { 'x-workspace': BAD_IDS[0] })).status, 200); assert.equal(workspaces.size(), 1);
    // a read of an unknown workspace creates nothing
    assert.equal((await get(url, '/api/state?mode=live', { 'x-workspace': 'w-never-used' })).status, 200); assert.equal(workspaces.size(), 1);
    assert.equal((await put(url, '/api/identities/fid-001', { mode: 'live', identity: { enabled: false } }, { 'x-workspace': 'w-good-2' })).status, 200); assert.equal(workspaces.size(), 2);
  }, { workspaces });
});

test('the answer mask is a net under the input cleaners: a credential that reached the state by some future bug is still masked in the answer, as a value and as an object key', async () => {
  // A workspace store whose engines add a raw credential, in a value and in a key, to every snapshot (the cleaners that run on input are bypassed on purpose).
  const real = createWorkspaces();
  const dirty = (e) => { if (!e.dirtied) { const snap = e.snapshot.bind(e); e.snapshot = () => ({ ...snap(), leakedValue: `password: ${H}`, [`password: ${H}`]: 1, nested: [{ note: `the key is ${H}` }] }); e.dirtied = true; } return e; };
  const workspaces = { engine: (id, v, c) => dirty(real.engine(id, v, c)), peek: (id, v) => { const e = real.peek(id, v); return e ? dirty(e) : null; }, reset: (id) => real.reset(id), size: () => real.size() };
  await withServer(async (url) => {
    await post(url, '/api/clock', { mode: 'live', vertical: 'finance', clock: { minutes: 1 } }, { 'x-workspace': 'w-net' });
    const read = await (await get(url, '/api/state?mode=live', { 'x-workspace': 'w-net' })).text();
    const write = await (await post(url, '/api/clock', { mode: 'live', vertical: 'finance', clock: { minutes: 1 } }, { 'x-workspace': 'w-net' })).text();
    for (const [what, text] of [['a read', read], ['a write', write]]) {
      assert.ok(text.includes('leakedValue'), `${what}: the dirty snapshot did reach the answer`);
      assert.ok(!text.includes(H), `${what}: the credential is masked in the answer`);
    }
  }, { workspaces });
});
