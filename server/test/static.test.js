// The built page is served only for the page's own addresses. WEB_DIST is read when app.js loads, so it is set before the import.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'fid-dist-'));
fs.mkdirSync(path.join(dist, 'assets'));
fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>PAGE-MARKER</title>');
fs.writeFileSync(path.join(dist, 'assets', 'app.js'), 'console.log("ASSET-MARKER")');
fs.writeFileSync(path.join(dist, '.secret'), 'DOTFILE-MARKER');
process.env.WEB_DIST = dist;
const { createApp, startHttpServer } = await import('../src/app.js');
const { createHealth } = await import('../src/health.js');

const raw = (url, p) => new Promise((resolve, reject) => {
  import('node:http').then(({ default: http }) => {
    const u = new URL(url);
    http.get({ host: u.hostname, port: u.port, path: p, agent: false }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'] || '', text: d })); }).on('error', reject);
  });
});

async function withApp(fn) {
  const health = createHealth({ demoId: "federated-identity-lab", demoName: "Federated Identity LAB", version: "0.1.0", runChecks: () => [], allPassed: () => true, intervalMs: 3_600_000 }); await health.ready;
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, configFile: '/nonexistent/customer.config.json' }) });
  try { await fn(url.replace(/\/$/, '')); } finally { health.stop(); await new Promise((r) => server.close(r)); fs.rmSync(dist, { recursive: true, force: true }); }
}

test('the page answers its own addresses; a missing file, a dotfile and anything with an extension is a fixed JSON 404, never the page with a 200 (S3)', async () => {
  await withApp(async (url) => {
    for (const p of ['/', '/verify', '/identities', '/some/deep/route', '/a.b/c', '/api-docs', '/apix']) {
      const r = await raw(url, p); assert.equal(r.status, 200, p); assert.match(r.type, /text\/html/, p); assert.match(r.text, /PAGE-MARKER/, p);
    }
    const asset = await raw(url, '/assets/app.js'); assert.equal(asset.status, 200); assert.match(asset.type, /javascript/); assert.match(asset.text, /ASSET-MARKER/);
    assert.equal((await raw(url, '/index.html')).status, 200, 'a real file is still served');
    for (const p of ['/assets/missing.js', '/favicon.ico', '/robots.txt', '/index.html%00', '/.git/config', '/server/src/engine.js', '/.secret', '/assets/', '/assets/..%2f..%2fpackage.json', '/x/.env', '/package.json', '/api', '/api/', '/api/nope', '/api/x.js', '/assets', '/%', '/%zz', '/%2e%2e/etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/a//b']) {
      const r = await raw(url, p);
      assert.ok([400, 404].includes(r.status), `${p} -> ${r.status}`);
      assert.ok(!r.text.includes('PAGE-MARKER') && !r.text.includes('DOTFILE-MARKER') && !r.text.includes('ASSET-MARKER') , `${p} is not the page`);
      assert.match(r.type, /json/, `${p} answers JSON (${r.type})`);
      assert.ok(r.text.length < 60, `${p}: a short fixed body`); assert.ok(!r.text.includes('missing') && !r.text.includes('engine') && !r.text.includes('robots') && !r.text.includes('.git'), `${p} is not echoed: ${r.text}`);
      assert.doesNotMatch(r.text, /<|\/Users|node_modules|Cannot GET/);
    }
    assert.deepEqual(JSON.parse((await raw(url, '/robots.txt')).text), { error: 'not_found' });
  });
});
