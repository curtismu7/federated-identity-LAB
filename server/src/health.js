// GET /api/health, contract demo-health/1 (demo-shelf docs/health-contract.md). Public, GET only, no extra fields.
// The state comes from the doctor checks, refreshed in the background every 60 s; a request never runs them.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { allPassed, runChecks as defaultChecks } from './doctor.js';

const { version } = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../package.json'), 'utf8'));
const DEMO = { id: 'federated-identity-lab', name: 'Federated Identity LAB', version };

export function createHealth({ runChecks = defaultChecks, now = () => new Date(), intervalMs = 60_000 } = {}) {
  let last = { state: 'unknown', at: null };
  async function refresh() {
    try { last = { state: allPassed(await runChecks()) ? 'ready' : 'broken', at: now().toISOString() }; }
    catch { last = { state: 'unknown', at: now().toISOString() }; }
  }
  const ready = refresh();
  const timer = setInterval(refresh, intervalMs);
  timer.unref();

  const router = express.Router();
  router.get('/', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ schema: 'demo-health/1', at: last.at || now().toISOString(), state: last.state, runtime: 'offline', demo: DEMO });
  });
  // a wrong method is answered 405 with Allow by the route table in app.js
  return { router, refresh, ready, stop: () => clearInterval(timer) };
}
