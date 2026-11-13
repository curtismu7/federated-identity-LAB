// One Express app. /api = health, info, story, diagram, state and the action endpoints (mint, verify, clock, issuers, identities, keys, people, sensors, reset).
// Server state per workspace id (X-Workspace) is one engine per vertical, so one visitor's Reset never touches another's.
// Mock reads generated tables and refuses every write; Live drives the engine. Both are loopback-only with zero outbound calls.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { makeHostCheck, makeSameOriginWrites } from './safety.js';
import { createHealth } from './health.js';
import { loadCast, verticalFrom } from './cast.js';
import { defaultMode, modeOf } from './config.js';
import { buildStory } from './story.js';
import { DIAGRAM_NAMES, buildDiagram } from './diagramData.js';
import { InputError } from './errors.js';
import { MOCK_TABLE } from './mockTable.js';
import { createWorkspaces, workspaceFrom } from './workspaces.js';
import { jwksFor, liveState, mockState, runAction } from './service.js';
import { maskDeep, maskStatic } from './mask.js';
import { shelfInfo } from './shelfLink.js';
import { buildMethodTable, charsetProblem, isPageAddress, methodNotAllowed } from './shared/hygiene.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIST = process.env.WEB_DIST || path.resolve(HERE, '../../web/dist');
const CONFIG = process.env.CUSTOMER_CONFIG || path.resolve(HERE, '../../customer.config.json');
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// path -> allowed methods: the ONE route table. It decides the 405 (with Allow) and which paths are the API's own; every route below is registered through on(), so the table
// cannot drift from the routes. ":name" is one segment; HEAD is allowed wherever GET is.
export function createApp({ health = createHealth({ demoId: 'federated-identity-lab', demoName: 'Federated Identity LAB', version: '0.1.0', runChecks: () => [], allPassed: () => true }), configFile = CONFIG, workspaces = createWorkspaces(), table = MOCK_TABLE, env = process.env, proxyHosts = new Set() } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.use(makeHostCheck(proxyHosts));
  app.use(makeSameOriginWrites(proxyHosts));
  app.use((_req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });

  const ROUTES = {};
  const METHODS = { table: null };
  // Only UTF-8 bodies are read: any other declared charset is refused before a parser can decode it. The answer is a fixed body; the header value is never read into it.
  app.use((req, res, next) => (charsetProblem(req.headers['content-type']) ? res.status(415).json({ error: 'unsupported_charset' }) : next()));
  // Wrong method on a known path: 405 with Allow, from the route table. A path that is not in the table falls through to the JSON 404 below.
  app.use('/api', (req, res, next) => {
    METHODS.table ??= buildMethodTable(ROUTES);
    const miss = methodNotAllowed(METHODS.table, req.method, `/api${req.path}`);
    return miss ? res.set('Allow', miss.allow.join(', ')).status(405).json({ error: 'method_not_allowed' }) : next();
  });

  const api = express.Router();
  const on = (method, route, ...handlers) => { (ROUTES[`/api${route}`] ??= []).push(method.toUpperCase()); api[method](route, ...handlers); };
  api.use(express.json({ limit: '32kb' }));
  // Defence in depth: every JSON answer is masked for credential-shaped values, whatever path produced it (the lab's own opaque fields are exempt: mask.js). An answer the lab
  // wrote entirely itself (the story, the diagrams, the Mock tables: res.locals.lab) is masked as prose, where the words "token" and "password" are words.
  api.use((_req, res, next) => { const send = res.json.bind(res); res.json = (b) => send((res.locals.lab ? maskStatic : maskDeep)(b)); next(); });
  api.use('/health', health.router);
  api.get('/shelf', (_req, res) => { noStore(res); res.json(shelfInfo(env)); });
  ROUTES['/api/health'] = ['GET'];
  const verticalOf = (req) => verticalFrom(req.body?.vertical ?? req.query.vertical);
  const castFor = (req) => loadCast(configFile, verticalOf(req));
  const noStore = (res) => res.set('Cache-Control', 'no-store');
  // The workspace id is checked BEFORE anything is created for it: a refused id gets a fixed 400 that does not echo it, and no slot exists. Only a valid write takes a slot.
  const workspace = (req, res, next) => { const id = workspaceFrom(req); if (!id) return res.status(400).json({ error: 'bad_workspace' }); req.ws = id; return next(); };

  on('get', '/story', (req, res) => { noStore(res); res.locals.lab = true; res.json(buildStory(castFor(req), verticalOf(req))); });
  on('get', '/diagram', (req, res) => { noStore(res); res.locals.lab = true; res.json(buildDiagram(castFor(req), DIAGRAM_NAMES.includes(req.query.name) ? req.query.name : DIAGRAM_NAMES[0])); });
  // Rule 19: the server holds the Mock/Real mode. Both are available: mock reads generated tables, live drives the loopback engine.
  // The wire value of source is mock|real; this lab's internal mode is mock|live, and real means live here.
  let current = defaultMode();
  const toSource = (m) => (m === 'live' ? 'real' : m);
  const toMode = (s) => (s === 'real' ? 'live' : s);
  on('get', '/info', (_req, res) => { noStore(res); res.locals.lab = true; res.json({ mode: current, source: toSource(current), realAvailable: true, realReason: null, modes: ['mock', 'live'], simulated: true, release: '2026-11-02', unverified: true }); });
  // Rule 19: switching is server-side. The body is exactly { source: "mock" | "real" }.
  on('post', '/mode', (req, res) => {
    noStore(res);
    const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const next = b.source;
    if (next !== 'mock' && next !== 'real') return res.status(400).json({ error: 'bad_mode', detail: 'source must be exactly "mock" or "real"' });
    if (!Object.keys(b).every((k) => k === 'source')) return res.status(400).json({ error: 'unknown_field', detail: 'the body takes only source' });
    current = toMode(next);
    return res.json({ mode: current, source: toSource(current), realAvailable: true, realReason: null });
  });

  on('get', '/state', workspace, (req, res) => {
    const id = req.ws;
    noStore(res);
    const mode = modeOf(req.query.mode); if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
    const vertical = verticalOf(req);
    if (mode === 'mock') { res.locals.lab = true; return res.json({ mode, vertical, workspace: id, ...mockState(table, vertical, req.query.scenario) }); }
    return res.json({ mode, vertical, workspace: id, state: liveState(id, workspaces, vertical, castFor(req)) });
  });

  // The public key set an issuer publishes now (public halves only), for the page's own WebCrypto signature check. Same origin, Live only.
  on('get', '/issuers/:id/jwks', workspace, (req, res, next) => {
    const id = req.ws;
    noStore(res);
    try {
      if (modeOf(req.query.mode) !== 'live') return res.status(409).json({ error: 'live_only', detail: 'Mock tables hold no keys: the browser check is Live only' });
      return res.json(jwksFor(id, workspaces, verticalOf(req), castFor(req), typeof req.params.id === 'string' ? req.params.id : ''));
    } catch (e) { return next(e); }
  });

  // Every write: Live only, strict top-level keys, one trace, hops, and the whole fresh state back. Refusals keep their honest HTTP status.
  const write = (method, route, { op, keys, params }) => {
    on(method, route, workspace, (req, res, next) => {
      const id = req.ws;
      noStore(res);
      try {
        if (!isObj(req.body)) return res.status(400).json({ error: 'bad_request' });
        const mode = modeOf(req.body.mode);
        if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
        if (mode === 'mock') return res.status(409).json({ error: 'mock_is_read_only', detail: 'Mock mode only reads tables: switch to Live to act' });
        if (!Object.keys(req.body).every((k) => ['mode', 'vertical', ...keys].includes(k))) return res.status(400).json({ error: 'unknown_field', detail: 'the body carries a field the lab does not take' });
        const vertical = verticalOf(req);
        const r = runAction({ ws: id, workspaces, vertical, cast: castFor(req), op, params: params(req), traceparent: req.headers.traceparent, route: { method: method.toUpperCase(), url: `/api${route}` } });
        res.set('traceparent', r.traceparent);
        const common = { workspace: id, mode, vertical, hops: r.hops, hopsTruncated: r.hopsTruncated, traceId: r.traceId, state: r.state };
        if (r.outcome.ok) return res.json({ ok: true, result: r.outcome.result, ...common });
        return res.status(r.outcome.status || 400).json({ ok: false, error: r.outcome.code, detail: r.outcome.detail, result: r.outcome.result, ...common });
      } catch (e) { return next(e); }
    });
  };
  const idParam = (req) => (typeof req.params.id === 'string' ? req.params.id : '');
  const obj = (v) => (isObj(v) ? v : { __bad: 1 });
  write('post', '/tokens/mint', { op: 'mint', keys: ['mint'], params: (req) => obj(req.body.mint) });
  write('post', '/verify', { op: 'verify', keys: ['verify'], params: (req) => obj(req.body.verify) });
  write('post', '/clock', { op: 'advance', keys: ['clock'], params: (req) => obj(req.body.clock) });
  write('post', '/issuers/:id/actions', { op: 'issuer', keys: ['action'], params: (req) => ({ ...obj(req.body.action), issuer: idParam(req) }) });
  write('post', '/identities', { op: 'createIdentity', keys: ['identity'], params: (req) => obj(req.body.identity) });
  write('put', '/identities/:id', { op: 'updateIdentity', keys: ['identity'], params: (req) => ({ ...obj(req.body.identity), identityId: idParam(req) }) });
  write('post', '/identities/:id/remove', { op: 'deleteIdentity', keys: ['remove'], params: (req) => ({ ...obj(req.body.remove), identityId: idParam(req) }) });
  write('post', '/identities/:id/refresh', { op: 'refreshKeys', keys: ['refresh'], params: (req) => ({ ...obj(req.body.refresh), identityId: idParam(req) }) });
  write('post', '/keys', { op: 'createKey', keys: ['key'], params: (req) => obj(req.body.key) });
  write('put', '/keys/:id', { op: 'updateKey', keys: ['key'], params: (req) => ({ ...obj(req.body.key), keyId: idParam(req) }) });
  write('post', '/keys/:id/remove', { op: 'deleteKey', keys: ['remove'], params: (req) => ({ ...obj(req.body.remove), keyId: idParam(req) }) });
  write('post', '/keys/:id/stored-call', { op: 'storedKeyCall', keys: ['call'], params: (req) => ({ ...obj(req.body.call), keyId: idParam(req) }) });
  write('put', '/people/:id', { op: 'setPerson', keys: ['person'], params: (req) => ({ ...obj(req.body.person), person: idParam(req) }) });
  write('post', '/sensors', { op: 'enrollSensor', keys: ['sensor'], params: (req) => (req.body.sensor === undefined ? {} : obj(req.body.sensor)) });
  write('post', '/sensors/:id/reports', { op: 'sensorReport', keys: ['report'], params: (req) => ({ ...obj(req.body.report), identityId: idParam(req) }) });
  write('put', '/sensors/:id/policy', { op: 'setPolicy', keys: ['policy'], params: (req) => ({ ...obj(req.body.policy), identityId: idParam(req) }) });

  // Reset clears this workspace's engines (identities, keys, issuers, audit, sensors, findings, the clock) and nothing else.
  on('post', '/reset', workspace, (req, res) => { noStore(res); workspaces.reset(req.ws); return res.json({ reset: 'ok', workspace: req.ws }); });
  api.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use('/api', api);

  if (fs.existsSync(path.join(WEB_DIST, 'index.html'))) {
    // Real files only: no directory index, no redirect (so /assets and /assets/ are the JSON 404), dotfiles ignored; anything else falls through.
    app.use(express.static(WEB_DIST, { index: false, redirect: false, dotfiles: 'ignore', fallthrough: true }));
    // The page is the answer for the page's OWN addresses only (isPageAddress: no dot in the last segment, no dotfile segment, no empty or encoded-dot segment, not /assets or /api, decodable),
    // for a GET or HEAD from a client that did not ask for something else. A missing asset (/assets/missing.js, /favicon.ico, /robots.txt), /%, /%zz, /%2e%2e/%2e%2e/etc/passwd are a fixed JSON 404.
    app.use((req, res, next) => {
      const accept = req.get('accept');
      const wantsPage = accept === undefined || /text\/html|\*\/\*/.test(accept);
      if ((req.method === 'GET' || req.method === 'HEAD') && wantsPage && isPageAddress(req.originalUrl)) return res.sendFile(path.join(WEB_DIST, 'index.html'));
      return next();
    });
  }
  app.use((_req, res) => res.status(404).json({ error: 'not_found' })); // never Express's default 404, which echoes the path
  // Errors become short JSON with a fixed code from a whitelist: err.message and err.stack are never sent. Express's default handler would send an HTML stack trace with
  // absolute file paths. Last in the chain, so an error from the static files or the page lands here too.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (res.headersSent) return res.end();
    const status = Number(err?.status || err?.statusCode);
    if (err instanceof InputError) return res.status(err.status).json({ error: err.code });
    if (status === 413) return res.status(413).json({ error: 'payload_too_large' });
    if (status === 415) return res.status(415).json({ error: 'unsupported_charset' });
    if (status >= 400 && status < 500) return res.status(status).json({ error: 'bad_request' });
    return res.status(500).json({ error: 'internal_error' });
  });
  return app;
}

export function startHttpServer({ port, host, app = createApp() } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}/` }));
    server.once('error', reject);
  });
}
