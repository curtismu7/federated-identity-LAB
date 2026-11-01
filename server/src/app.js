// One Express app. /api = health, info, story, diagram, state and the action endpoints (mint, verify, clock, issuers, identities, keys, people, sensors, reset).
// Server state per workspace id (X-Workspace) is one engine per vertical, so one visitor's Reset never touches another's.
// Mock reads generated tables and refuses every write; Live drives the engine. Both are loopback-only with zero outbound calls.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { hostCheck, sameOriginWrites } from './safety.js';
import { createHealth } from './health.js';
import { loadCast, verticalFrom } from './cast.js';
import { defaultMode, modeOf } from './config.js';
import { buildStory } from './story.js';
import { DIAGRAM_NAMES, buildDiagram } from './diagramData.js';
import { InputError } from './errors.js';
import { MOCK_TABLE } from './mockTable.js';
import { createWorkspaces, workspaceFrom } from './workspaces.js';
import { jwksFor, liveState, mockState, runAction } from './service.js';
import { maskDeep } from './mask.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIST = process.env.WEB_DIST || path.resolve(HERE, '../../web/dist');
const CONFIG = process.env.CUSTOMER_CONFIG || path.resolve(HERE, '../../customer.config.json');
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function createApp({ health = createHealth(), configFile = CONFIG, workspaces = createWorkspaces(), table = MOCK_TABLE } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostCheck);
  app.use(sameOriginWrites);
  app.use((_req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });

  const api = express.Router();
  // Only UTF-8 bodies are read: any other declared charset is refused before a parser can decode it.
  api.use((req, res, next) => {
    const m = /charset\s*=\s*"?([^;"\s]+)/i.exec(String(req.headers['content-type'] || ''));
    if (m && !/^utf-8$/i.test(m[1])) return res.status(415).json({ error: 'unsupported_charset' });
    return next();
  });
  api.use(express.json({ limit: '32kb' }));
  // Defence in depth: every JSON answer is masked for credential-shaped values, whatever path produced it (the one lab-minted token field is exempt: mask.js).
  api.use((_req, res, next) => { const send = res.json.bind(res); res.json = (b) => send(maskDeep(b)); next(); });
  api.use('/health', health.router);
  const verticalOf = (req) => verticalFrom(req.body?.vertical ?? req.query.vertical);
  const castFor = (req) => loadCast(configFile, verticalOf(req));
  const noStore = (res) => res.set('Cache-Control', 'no-store');
  const ws = (req, res) => { const id = workspaceFrom(req); if (!id) res.status(400).json({ error: 'bad_workspace' }); return id; };

  api.get('/story', (req, res) => { noStore(res); res.json(buildStory(castFor(req), verticalOf(req))); });
  api.get('/diagram', (req, res) => { noStore(res); res.json(buildDiagram(castFor(req), DIAGRAM_NAMES.includes(req.query.name) ? req.query.name : DIAGRAM_NAMES[0])); });
  api.get('/info', (_req, res) => { noStore(res); res.json({ mode: defaultMode(), modes: ['mock', 'live'], simulated: true, release: '2026-11-02', unverified: true }); });

  api.get('/state', (req, res) => {
    const id = ws(req, res); if (!id) return;
    noStore(res);
    const mode = modeOf(req.query.mode); if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
    const vertical = verticalOf(req);
    if (mode === 'mock') return res.json({ mode, vertical, workspace: id, ...mockState(table, vertical, req.query.scenario) });
    return res.json({ mode, vertical, workspace: id, state: liveState(id, workspaces, vertical, castFor(req)) });
  });

  // The public key set an issuer publishes now (public halves only), for the page's own WebCrypto signature check. Same origin, Live only.
  api.get('/issuers/:id/jwks', (req, res, next) => {
    const id = ws(req, res); if (!id) return;
    noStore(res);
    try {
      if (modeOf(req.query.mode) !== 'live') return res.status(409).json({ error: 'live_only', detail: 'Mock tables hold no keys: the browser check is Live only' });
      return res.json(jwksFor(id, workspaces, verticalOf(req), castFor(req), typeof req.params.id === 'string' ? req.params.id : ''));
    } catch (e) { return next(e); }
  });

  // Every write: Live only, strict top-level keys, one trace, hops, and the whole fresh state back. Refusals keep their honest HTTP status.
  const write = (method, route, { op, keys, params }) => {
    api[method](route, (req, res, next) => {
      const id = ws(req, res); if (!id) return;
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
  api.post('/reset', (req, res) => { const id = ws(req, res); if (!id) return; noStore(res); workspaces.reset(id); return res.json({ reset: 'ok', workspace: id }); });
  api.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use('/api', api);
  // Errors become short JSON. Express's default handler would send an HTML stack trace with absolute file paths, and its 404 echoes the path.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = Number(err?.status || err?.statusCode);
    if (err instanceof InputError) return res.status(err.status).json({ error: err.code });
    if (status === 413) return res.status(413).json({ error: 'payload_too_large' });
    if (status === 415) return res.status(415).json({ error: 'unsupported_charset' });
    if (status >= 400 && status < 500) return res.status(status).json({ error: 'bad_request' });
    return res.status(500).json({ error: 'internal_error' });
  });

  if (fs.existsSync(path.join(WEB_DIST, 'index.html'))) {
    app.use(express.static(WEB_DIST));
    // The page's own address (a path with no dot anywhere in it, outside /api and /assets) gets the app. A missing file (/assets/missing.js, /favicon.ico, /robots.txt), a dotfile (/.git/config) and
    // anything with an extension (/server/src/engine.js, /index.html%00) is a fixed JSON 404 below, never the page with a 200, and the path is never echoed.
    app.get(/^\/(?!(?:api|assets)(?:\/|$))[^.]*$/, (_req, res) => res.sendFile(path.join(WEB_DIST, 'index.html')));
  }
  app.use((_req, res) => res.status(404).json({ error: 'not_found' })); // never Express's default 404, which echoes the path
  return app;
}

export function startHttpServer({ port, host, app = createApp() } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}/` }));
    server.once('error', reject);
  });
}
