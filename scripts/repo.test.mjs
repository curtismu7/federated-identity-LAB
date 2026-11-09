import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const WEB_FILES = ['App.jsx', 'components/IdentitiesTab.jsx', 'components/VerifyTab.jsx', 'components/IssuersTab.jsx', 'components/ModelsTab.jsx', 'components/SensorsTab.jsx', 'components/AuditTab.jsx', 'components/TalkTrack.jsx', 'components/ErrorBoundary.jsx', 'browserVerify.js'];

test('the files the standalone rules ask for are present', () => {
  for (const f of ['README.md', 'CLAUDE.md', 'LICENSE', 'Dockerfile', 'docker-compose.yml', '.github/workflows/ci.yml', 'docs/talk-track.md', 'docs/safety.md', 'docs/content-pack.schema.json', 'scripts/build-mock-table.mjs', 'docs/shelf-entry.json', 'customer.config.example.json', 'content-pack.json', 'scripts/doctor.mjs', 'scripts/reset.mjs', 'web/src/styles/standalone-ui.css', '.gitignore', '.env.example']) assert.ok(fs.existsSync(path.join(root, f)), f);
});

test('the shelf entry is valid and portable: relative composeFile, loopback url, health path, catalog id D107; content pack and shelf entry agree', () => {
  const e = JSON.parse(read('docs/shelf-entry.json')).demos[0];
  assert.equal(e.id, 'federated-identity-lab'); assert.equal(e.kind, 'Demo'); assert.equal(e.healthPath, '/api/health');
  assert.match(e.url, /^http:\/\/localhost:74[0-4]\d$/);
  assert.equal(e.catalogId, 'D107', 'catalog id assigned 2026-10-31 (owner delegated the choice)');
  assert.equal(JSON.parse(read('content-pack.json')).demo.catalog, e.catalogId);
  assert.equal(e.composeFile, 'federated-identity-LAB/docker-compose.yml'); assert.ok(!path.isAbsolute(e.composeFile));
  assert.ok(!/\/Users\//.test(JSON.stringify(e)), 'no absolute home path');
});

test('customer.config.json is git-ignored, and its example only sets the three cast values', () => {
  assert.match(read('.gitignore'), /^customer\.config\.json$/m);
  assert.deepEqual(Object.keys(JSON.parse(read('customer.config.example.json')).cast).sort(), ['brand', 'host', 'owner']);
});

test('no shipped text names a real customer, company or tenant', () => {
  // corpus: the shared masker's generated test data (random fragments; the short word 'uhg' occurs in them by chance), not shipped text.
  const skip = new Set(['node_modules', 'dist', '.git', 'package-lock.json', 'corpus']); const hits = [];
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir)) {
      if (skip.has(name)) continue;
      const p = path.join(dir, name);
      if (fs.statSync(p).isDirectory()) walk(p);
      else if (!['repo.test.mjs', 'story.test.js', 'content-pack.test.mjs'].some((n) => p.endsWith(n))) {
        const t = fs.readFileSync(p, 'utf8').toLowerCase();
        for (const w of ['united airlines', 'mileageplus', 'datapower', 'optum', 'unitedhealth', 'uhg', 'member benefit', 'personal-agent']) if (t.includes(w)) hits.push(`${path.relative(root, p)}: ${w}`);
      }
    }
  };
  walk(root);
  assert.deepEqual(hits, []);
});

test('the CI workflow is GitHub-hosted, Node 26 only, and carries the forbidden-strings and gitleaks jobs', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /runs-on: ubuntu-latest`?/); assert.ok(!/self-hosted/.test(ci));
  const versions = [...ci.matchAll(/node-version: (\S+)/g)].map((m) => m[1]);
  assert.ok(versions.length >= 3 && versions.every((v) => v === '26'), versions.join());
  assert.match(ci, /forbidden-strings:/); assert.match(ci, /gitleaks/); assert.match(ci, /PORT=7409 npm run doctor/);
});

test('package.json requires Node 26 and the Dockerfile uses a Node 26 base', () => {
  assert.equal(JSON.parse(read('package.json')).engines.node, '>=26');
  assert.ok((read('Dockerfile').match(/^FROM node:26-alpine/gm) || []).length === 2);
});

test('README follows the README standard: title ends in LAB, plain Tier and Repo lines, the port text, a run-from-a-clone section; no internal names', () => {
  const r = read('README.md');
  assert.match(r.split('\n')[0], /^# .* LAB$/); assert.match(r, /^Tier: Demo$/m); assert.match(r, /^Repo: https:\/\/github.com\/curtismu7\/federated-identity-LAB$/m); assert.match(r, /^Catalog: D107$/m);
  for (const h of ['Run from a clone', 'Settings file', 'What to do if the port is taken', 'Mock and live modes', 'Health, doctor and reset', 'Docker', 'Tests', 'Troubleshooting', 'Ownership', 'What is simulated']) assert.match(r, new RegExp(`^## .*${h}`, 'mi'), h);
  assert.match(r, /lsof -iTCP:7400 -sTCP:LISTEN -n -P/); assert.match(r, /PORT=<other port> npm start/);
  assert.ok(!/ping-devops|cmuir/i.test(r)); // the owner org (curtismu7) is allowed: it is the Repo line
  assert.ok(!/\bdoor\b/i.test(r));
});

test('docs never use the word "door"', () => { for (const f of ['README.md', 'CLAUDE.md', 'docs/talk-track.md', 'docs/safety.md']) assert.ok(!/\bdoor\b/i.test(read(f)), f); });
test('the lab ships no k8s manifests (deferred by the owner, 2026-10-31)', () => { assert.ok(!fs.existsSync(path.join(root, 'k8s'))); });

test('README sections follow the standard order and state the limits, the measured nuance, the naming and the lab readings; conformance is said to be run by hand', () => {
  const r = read('README.md');
  for (const limit of ['12 identities', '20 keys', '5 sensors', '200 findings', '300 changes, 300 allowed requests and 200 refusals', '180 minutes per move', '10080', '40 hops', '160 characters', '4096 characters']) assert.ok(r.includes(limit), `the README states the limit: ${limit}`);
  const at = (h) => r.indexOf(`\n## ${h}`);
  const order = ['What is simulated', 'Run from a clone', 'Settings file', 'Ports, and what to do', 'Mock and live modes', 'Health, doctor and reset', 'Docker', 'Tests', 'Troubleshooting', 'Ownership', 'Not done'].map(at);
  assert.ok(order.every((i) => i > 0), order.join());
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'sections are in order');
  assert.match(r, /### Known limits of the model/); assert.match(r, /lab-invented/i); assert.match(r, /run by hand/);
  assert.match(r, /did not prove it/); assert.match(r, /signs exactly what you type/); assert.match(r, /cooldown/); assert.match(r, /single-use|No single-use/); assert.match(r, /ambiguous_identity/); assert.match(r, /Shared lab keys/); assert.match(r, /crit/); assert.match(r, /measured, our note, 2026-10-21/); assert.match(r, /Slide 57/); assert.match(r, /\/v1\/nonhumanidentities/); assert.match(r, /token-pass/); assert.match(r, /in development/); assert.match(r, /RS256 only/); assert.match(r, /UNVERIFIED on our tenant/);
  assert.match(r, /util\.parseEnv/);
});

test('the README and CLAUDE.md describe the in-browser WebCrypto check and its limits; the browser code reaches only the lab\'s own origin and no secret', () => {
  const r = read('README.md');
  for (const w of ['WebCrypto', 'RSASSA-PKCS1-v1_5', 'ONLY', 'not the full verdict', 'Live only', 'disagreement', 'no key', 'secure context', 'no private key ever reaches the page']) assert.ok(r.includes(w), w);
  assert.match(read('CLAUDE.md'), /browserVerify\.js/);
  const b = read('web/src/browserVerify.js');
  assert.ok(!/https?:\/\//.test(b.replace(/\/\/.*$/gm, '')), 'no absolute URL: same origin only');
  assert.ok(!/privateKey|PRIVATE|"d"|\.d\b/.test(b.replace(/\/\/.*$/gm, '')), 'the page never handles private key material');
});

test('app CSS follows the CSS standard: tokens only, no dark-mode media query, no forced priority, no italics, breakpoints 600 and 900 only, no purple', () => {
  const css = read('web/src/app.css');
  assert.ok(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(css), 'no colour literal');
  assert.ok(!/prefers-color-scheme/.test(css)); assert.ok(!/!important/.test(css)); assert.ok(!/font-style:\s*italic/.test(css));
  const widths = [...css.matchAll(/@media \((?:max|min)-width: (\d+)px\)/g)].map((m) => m[1]);
  assert.ok(widths.length > 0 && widths.every((w) => w === '600' || w === '900'), widths.join());
  assert.ok(!/purple|violet|magenta|indigo/i.test(css + read('web/src/styles/standalone-ui.css').replace(/\/\*[\s\S]*?\*\//g, '').replace(/--[a-z-]+:[^;]*;/g, ''))); // comments are prose: the shared sheet says "no purple"
  const main = read('web/src/main.jsx');
  assert.ok(main.indexOf('standalone-ui.css') < main.indexOf('app.css'), 'the shared stylesheet loads before the app stylesheet');
  assert.ok(!/style=\{\{/.test(WEB_FILES.map((f) => read(`web/src/${f}`)).join('\n')), 'no style attributes outside diagram positions');
});

test('the shared stylesheet is vendored byte for byte when the canonical copy is present', () => {
  const canonical = path.join(process.env.HOME || '', 'Development/AI-DEMO-Standalone/shared/standalone-ui.css');
  if (fs.existsSync(canonical)) assert.equal(read('web/src/styles/standalone-ui.css'), fs.readFileSync(canonical, 'utf8'));
});

test('the repo carries no k8s manifests, no bare MODE, no credential field and no <em> in the web code; the web code never builds markup from text', () => {
  for (const f of WEB_FILES) { const t = read(`web/src/${f}`); assert.ok(!/type="password"|process\.env\.MODE|<em>|dangerouslySetInnerHTML|innerHTML/.test(t), f); }
});
