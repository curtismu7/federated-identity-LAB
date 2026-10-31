import http from 'node:http';
import { createApp, startHttpServer } from '../src/app.js';
import { createHealth } from '../src/health.js';
import { createWorkspaces } from '../src/workspaces.js';
import { Engine } from '../src/engine.js';
import { VERTICALS, fillDeep } from '../src/cast.js';
import { PRESETS } from '../src/data.js';
import { seededRand } from '../src/scenarios.js';

export const C = VERTICALS.finance;
export const newEngine = (cast = C) => new Engine(cast, { rand: seededRand('test') });
export const GW = `https://gateway.${C.castHost}.example`;
export const K8S_SUB = `system:serviceaccount:${C.castNs}:${C.castAgent}`;
export const GH_SUB = `repo:${C.castOrg}/${C.castRepo}:ref:refs/heads/main`;
export const PRESET = Object.fromEntries(fillDeep(PRESETS, C).map((p) => [p.id, p]));

// Mint a token for the Kubernetes identity with overrides, verify it for MCP, return the verification result.
export const k8sMint = (e, over = {}) => e.mint({ issuer: 'kube', claims: { sub: K8S_SUB, aud: GW }, ...over });
export const k8sVerify = (e, over = {}, v = {}) => e.verify({ token: k8sMint(e, over).mintedToken, identityId: 'fid-001', service: 'mcp', ...v });
export const codeOf = (fn) => { try { fn(); return null; } catch (e) { if (e.code) return e.code; throw e; } };
export const statusOf = (fn) => { try { fn(); return null; } catch (e) { if (e.status) return e.status; throw e; } };

export async function withServer(fn, { configFile = '/nonexistent/customer.config.json', workspaces = createWorkspaces({ rand: seededRand('http') }) } = {}) {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  await health.ready;
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, configFile, workspaces }) });
  try { await fn(url.replace(/\/$/, ''), { workspaces }); } finally { health.stop(); await new Promise((res) => server.close(res)); }
}
export const post = (url, path, body, headers = {}) => fetch(`${url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, ...headers }, body: JSON.stringify(body) });
export const put = (url, path, body, headers = {}) => fetch(`${url}${path}`, { method: 'PUT', headers: { 'content-type': 'application/json', origin: url, ...headers }, body: JSON.stringify(body) });
export const get = (url, path, headers = {}) => fetch(`${url}${path}`, { headers });
export const json = async (res) => res.json();

// fetch cannot set Host; node:http can.
export function rawHttp(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, agent: false }, (res) => {
      let data = ''; res.on('data', (c) => { data += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
export const W = (id) => ({ 'x-workspace': id });
export const live = (extra = {}) => ({ mode: 'live', vertical: 'finance', ...extra });

// HTTP-level helper: one live write; returns { status, body }.
export async function api(url, method, path, body, ws = 'default', headers = {}) {
  const f = method === 'PUT' ? put : post;
  const r = await f(url, path, { mode: 'live', vertical: 'finance', ...body }, { 'x-workspace': ws, ...headers });
  return { status: r.status, body: await r.json() };
}
