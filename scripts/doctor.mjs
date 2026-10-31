// Preflight: the same checks GET /api/health reports from, plus whether the port is free, plus one real run of the engine through the HTTP API
// (mint, verify, tamper, revoke) on a throwaway port. Prints only pass/fail lines, never a setting's value. Exit 1 on failure.
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (p) => import(pathToFileURL(path.join(root, p)));
const { installNetguard } = await load('server/src/netguard.js');
installNetguard();
const { applySharedSettings } = await load('server/src/settings.js');
applySharedSettings();

const { runChecks } = await load('server/src/doctor.js');
let failed = 0;
const report = (level, name, detail) => { if (level === 'fail') failed++; console.log(`${level.toUpperCase().padEnd(4)}  ${name}: ${detail}`); };
for (const c of await runChecks()) report(c.level, c.id, c.detail);

// A real cycle through the HTTP layer, in this process, on an ephemeral loopback port: mint, verify, alter the token, revoke, verify again.
try {
  const { createApp, startHttpServer } = await load('server/src/app.js');
  const { createHealth } = await load('server/src/health.js');
  const { tamperToken } = await load('server/src/jwt.js');
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health }) });
  try {
    const base = url.replace(/\/$/, ''); const h = { 'content-type': 'application/json', origin: base, 'x-workspace': 'doctor' };
    const call = async (method, p, b) => { const r = await fetch(base + p, { method, headers: h, body: JSON.stringify({ mode: 'live', vertical: 'finance', ...b }) }); return { status: r.status, body: await r.json() }; };
    const cast = (await (await fetch(`${base}/api/story?vertical=finance`)).json()).cast;
    const minted = await call('POST', '/api/tokens/mint', { mint: { issuer: 'kube', claims: { sub: `system:serviceaccount:${cast.castNs}:${cast.castAgent}`, aud: `https://gateway.${cast.castHost}.example` } } });
    const token = minted.body.result.mintedToken;
    const ok = await call('POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'mcp' } });
    const forged = await call('POST', '/api/verify', { verify: { token: tamperToken(token), identityId: 'fid-001', service: 'mcp' } });
    await call('PUT', '/api/identities/fid-001', { identity: { enabled: false } });
    const revoked = await call('POST', '/api/verify', { verify: { token, identityId: 'fid-001', service: 'mcp' } });
    const good = ok.status === 200 && forged.status === 401 && forged.body.error === 'bad_signature' && revoked.status === 401 && revoked.body.error === 'identity_disabled';
    report(good ? 'pass' : 'fail', 'engine-cycle', good ? 'a token minted and verified over the HTTP API (200), an altered one refused (401 bad_signature) and a revoked identity refused on the next request (401 identity_disabled)' : 'the mint, verify, alter, revoke cycle did not complete');
  } finally { health.stop(); await new Promise((res) => server.close(res)); }
} catch (e) { report('fail', 'engine-cycle', `the HTTP cycle could not run (${String(e?.message).slice(0, 80)})`); }

const port = Number(process.env.PORT) || 7400;
await new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', (e) => { report('fail', 'port-free', `${port} is not free (${e.code}). Set PORT to a free port in 7400-7449`); resolve(); });
  s.listen(port, '127.0.0.1', () => s.close(() => { report('pass', 'port-free', `${port} is free`); resolve(); }));
});
process.exit(failed ? 1 : 0);
