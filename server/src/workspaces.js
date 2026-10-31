// Rule 13: a workspace id keeps one visitor's state apart from another's. Server state per workspace is one Engine per vertical (identities, keys, issuers' state, the audit
// trail, sensors, findings and the lab clock). Bounded in count and age. A new workspace is REFUSED at the cap, never made by evicting someone else's; idle ones expire.
// The browser sends its id in X-Workspace (default "default"). Reset clears the current workspace only.
import crypto from 'node:crypto';
import { Engine } from './engine.js';
import { refuse } from './errors.js';

export const WORKSPACE_RE = /^[a-z0-9-]{1,40}$/;
export const DEFAULT_WORKSPACE = 'default';

export function workspaceFrom(req) {
  const raw = req.headers['x-workspace'];
  if (raw === undefined) return DEFAULT_WORKSPACE;
  return typeof raw === 'string' && WORKSPACE_RE.test(raw) && !/^[0-9a-f]{24,}$/.test(raw) ? raw : null;
}

export function createWorkspaces({ max = 500, ttlMs = 60 * 60 * 1000, now = Date.now, makeRand = () => (n) => crypto.randomBytes(n) } = {}) {
  const map = new Map(); // id -> { engines: Map(vertical -> Engine), at }
  const sweep = () => { const t = now(); for (const [id, v] of map) if (t - v.at > ttlMs) map.delete(id); };
  return {
    engine(id, vertical, cast) {
      sweep();
      let v = map.get(id);
      if (!v) { if (map.size >= max) throw refuse('workspaces_full', 'the lab is holding as many visitors as it allows: try again later', 503); v = { engines: new Map(), at: 0 }; map.set(id, v); }
      v.at = now();
      if (!v.engines.has(vertical)) v.engines.set(vertical, new Engine(cast, { rand: makeRand() }));
      return v.engines.get(vertical);
    },
    peek(id, vertical) { sweep(); return map.get(id)?.engines.get(vertical) || null; },
    reset(id) { map.delete(id); },
    size() { return map.size; },
  };
}
