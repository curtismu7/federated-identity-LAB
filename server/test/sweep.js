// Shared by echo.test.js and corpus-http.test.js: types ONE text into every field, key, query, path segment and header of every endpoint and returns everything that came back.
import { C, GW, get, post, put } from './helpers.js';

export const live = (extra = {}) => ({ mode: 'live', vertical: 'finance', ...extra });
export const e = encodeURIComponent;
export const URI = 'https://kube-api.cluster-a.example/openid/v1/jwks';

// Types the text v into every field, query, path and header of every endpoint and returns everything that came back.
export async function sweepAll(url, v) {
  const fed = (x) => ({ issuer: x, subject: x, audience: x, jwksUri: x, jwks: [{ kty: x, kid: x, n: x, e: x, d: x }], pinFromIssuer: x, maxTokenLifetimeSec: x, requiredClaims: { [x]: x, a: x }, allowAnySubject: x, [x]: x });
  const ident = (x) => ({ name: x, description: x, platform: x, scopes: [x], notAfter: x, enabled: x, federation: fed(x), [x]: x });
  const bodies = [
    ['POST', '/api/tokens/mint', live({ mint: { issuer: v, alg: v, generation: v, kid: v, claims: { iss: v, sub: v, aud: v, extra: { [v]: v, a: v } }, times: { iat: v, exp: v, nbf: v }, [v]: v } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'kube', kid: v } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'kube', claims: { iss: v, sub: v, aud: [v, v], extra: { token: v, note: `x ${v}` } } } })],
    ['POST', '/api/tokens/mint', live({ mint: { issuer: 'attacker', alg: 'HS256', claims: { sub: v, aud: v } } })],
    ['POST', '/api/verify', live({ verify: { token: v, identityId: v, service: v, keyId: v, [v]: v } })],
    ['POST', '/api/verify', live({ verify: { token: v, identityId: 'fid-001', service: 'mcp' } })],
    ['POST', '/api/verify', live({ verify: { token: v, service: 'mcp' } })],
    ['POST', '/api/verify', live({ verify: { token: [v, v, v].join(" "), service: 'mcp' } })],
    ['POST', '/api/clock', live({ clock: { minutes: v, [v]: v } })],
    ['POST', `/api/issuers/${e(v)}/actions`, live({ action: { action: v, retireOld: v, [v]: v } })],
    ['POST', '/api/issuers/kube/actions', live({ action: { action: v, retireOld: v } })],
    ['POST', '/api/identities', live({ identity: ident(v) })],
    ['POST', '/api/identities', live({ identity: { name: `n ${v}`, description: `d ${v}`, scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: v, audience: GW } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: v } } })],
    ['POST', '/api/identities', live({ identity: { name: 'n', scopes: ['mcp'], platform: 'kubernetes', federation: { issuer: 'https://kube-api.cluster-a.example', jwksUri: URI, subject: 'a:b', audience: GW, requiredClaims: { repo: v } } } })],
    ['PUT', `/api/identities/${e(v)}`, live({ identity: ident(v) })],
    ['PUT', '/api/identities/fid-001', live({ identity: ident(v) })],
    ['PUT', '/api/identities/fid-001', live({ identity: { name: `r ${v}`, federation: { subject: v } } })],
    ['POST', `/api/identities/${e(v)}/remove`, live({ remove: { [v]: v } })],
    ['POST', `/api/identities/${e(v)}/refresh`, live({ refresh: { [v]: v } })],
    ['POST', '/api/keys', live({ key: { name: v, owner: { kind: v, ref: v, [v]: v }, scopes: [v], ownFederation: v, userRef: v, [v]: v } })],
    ['POST', '/api/keys', live({ key: { name: `k ${v}`, owner: { kind: 'identity', ref: 'fid-001' }, scopes: ['mcp'] } })],
    ['PUT', `/api/keys/${e(v)}`, live({ key: { enabled: v, scopes: [v], [v]: v } })],
    ['POST', `/api/keys/${e(v)}/remove`, live({ remove: {} })],
    ['POST', `/api/keys/${e(v)}/stored-call`, live({ call: { service: v, [v]: v } })],
    ['PUT', `/api/people/${e(v)}`, live({ person: { active: v, [v]: v } })],
    ['POST', '/api/sensors', live({ sensor: { name: v, [v]: v } })],
    ['POST', '/api/sensors', live({ sensor: { name: `s ${v}` } })],
    ['POST', `/api/sensors/${e(v)}/reports`, live({ report: { node: v, tokenFrom: v, token: v, body: { node: v, findings: [{ kind: v, name: v, namespace: v, pod: v, [v]: v }], [v]: v }, [v]: v } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, body: { node: v, findings: [{ kind: 'ai-agent', name: `n ${v}`, namespace: C.castNs, pod: 'p-0' }] } } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, token: v, body: { findings: [{ kind: 'ai-agent', name: 'n', namespace: C.castNs, pod: 'p-0' }] } } })],
    ['POST', '/api/sensors/fid-006/reports', live({ report: { node: C.castNode1, body: { findings: [{ kind: 'ai-agent', name: 'n', namespace: v, pod: v }] } } })],
    ['PUT', `/api/sensors/${e(v)}/policy`, live({ policy: { mode: v, scope: { all: v, namespaces: [v], [v]: v }, actions: { [v]: v, 'ai-agent': v }, [v]: v } })],
    ['PUT', '/api/sensors/fid-006/policy', live({ policy: { mode: 'audit', scope: { namespaces: [v] }, actions: { 'ai-agent': 'allow', 'mcp-server': 'allow', 'model-server': 'allow' } } })],
    ['POST', '/api/reset', { [v]: v }],
  ];
  const gets = [`/api/state?mode=${e(v)}`, `/api/state?mode=live&vertical=${e(v)}&scenario=${e(v)}`, `/api/state?mode=mock&scenario=${e(v)}`, `/api/story?vertical=${e(v)}`, `/api/diagram?name=${e(v)}&vertical=${e(v)}`, `/api/${e(v)}`, `/api/health?x=${e(v)}`, `/${e(v)}`];
  const texts = [];
  for (const [m, p, b] of bodies) { const r = await (m === 'PUT' ? put : post)(url, p, b); texts.push(`${m} #${texts.length} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  for (const g of gets) { const r = await get(url, g); texts.push(`GET ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  for (const hv of [v, `a ${v}`]) { const r = await get(url, '/api/state?mode=live', { 'x-workspace': hv.slice(0, 40).replace(/[^\x20-\x7e]/g, '?') }); texts.push(`H ${r.status} ${await r.text()}`); }
  { const r = await post(url, '/api/clock', live({ clock: { minutes: 1 } }), { traceparent: v.replace(/[^\x20-\x7e]/g, '?') }); texts.push(`T ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
  // headers, query keys, error paths: the text in every header a client controls, as a query key and value, in a body that is not JSON, in a charset, on a path with the wrong method
  const hdr = v.replace(/[^\x20-\x7e]/g, '?').slice(0, 1000);
  const small = e(v).length <= 1500;
  const seen = async (label, f) => { try { const r = await f(); texts.push(`${label} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); } catch (err) { texts.push(`${label} threw ${err?.code || err?.name}`); } };
  for (const h of ['authorization', 'cookie', 'referer', 'user-agent', 'x-forwarded-for', 'x-anything', 'accept', 'accept-language', 'if-none-match', 'x-workspace']) {
    await seen(`H ${h}`, () => get(url, '/api/state?mode=live', { [h]: hdr }));
    await seen(`H ${h}`, () => post(url, '/api/clock', live({ clock: { minutes: 1 } }), { [h]: hdr }));
  }
  if (small) {
    for (const q of [`/api/state?mode=live&${e(v)}=1`, `/api/state?mode=live&x=${e(v)}`, `/api/story?${e(v)}`, `/api/issuers/${e(v)}/jwks?mode=live`, `/api/health?${e(v)}=${e(v)}`]) await seen('Q', () => get(url, q));
    for (const [m, p] of [['GET', `/api/identities/${e(v)}`], ['DELETE', `/api/keys/${e(v)}`], ['PATCH', `/api/${e(v)}/x`], ['OPTIONS', `/api/${e(v)}`], ['HEAD', `/${e(v)}/x`], ['POST', `/${e(v)}`]]) await seen(`E ${m}`, () => fetch(`${url}${p}`, { method: m, headers: { origin: url } }));
  }
  for (const raw of [`{"clock":{"minutes":"${v}`, `[${v}]`, v, JSON.stringify({ mode: 'live', [v]: v }).slice(0, -1)]) await seen('B', () => fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: raw }));
  await seen('C', () => fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': `application/json; charset=${hdr}`, origin: url }, body: '{}' }));
  await seen('C', () => fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': hdr, origin: url }, body: JSON.stringify(live({ clock: { minutes: 1 } })) }));
  await seen('S', () => fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: JSON.stringify(live({ clock: { minutes: 1 }, vertical: v })) }));
  return texts.join('\n');
}

