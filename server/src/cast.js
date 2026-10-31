// {{token}} templating for the story and catalog data. customer.config.json (optional, git-ignored) overrides brand, host and the first key owner.
// Tokens are filled from one of three vertical packs. A test fails on any token a pack does not define.
// Every person, repository, namespace, node and host in a pack is synthetic: only .example hosts, no real company, tenant or account.
import fs from 'node:fs';
import { scanHosts } from './safety.js';

const TOKEN = /\{\{(\w+)\}\}/g;
const MAX_CAST = 40;
const ID = /^[a-z0-9.-]{1,40}$/;

export const VERTICALS = {
  finance: {
    castBrand: 'Fabrikam Bank', castHost: 'fabrikam', castOrg: 'fabrikam-eng', castAttackerOrg: 'mallory-labs', castRepo: 'ledger-agent',
    castNs: 'payments', castNs2: 'treasury', castNs3: 'ml-sandbox', castSensorNs: 'privilege-system',
    castAgent: 'agent-runner', castOtherAgent: 'batch-worker', castOwner: 'maya.chen', castOwner2: 'omar.reyes',
    castNode1: 'node-a1', castNode2: 'node-a2', castNode3: 'node-a3',
  },
  health: {
    castBrand: 'Contoso Health', castHost: 'contoso', castOrg: 'contoso-dev', castAttackerOrg: 'eve-research', castRepo: 'claims-agent',
    castNs: 'claims', castNs2: 'pharmacy', castNs3: 'research-lab', castSensorNs: 'privilege-system',
    castAgent: 'triage-agent', castOtherAgent: 'report-worker', castOwner: 'lena.ortiz', castOwner2: 'tariq.hassan',
    castNode1: 'node-b1', castNode2: 'node-b2', castNode3: 'node-b3',
  },
  retail: {
    castBrand: 'Northwind Retail', castHost: 'northwind', castOrg: 'northwind-eng', castAttackerOrg: 'trent-tools', castRepo: 'checkout-agent',
    castNs: 'checkout', castNs2: 'pricing', castNs3: 'dev-sandbox', castSensorNs: 'privilege-system',
    castAgent: 'order-agent', castOtherAgent: 'stock-worker', castOwner: 'diego.ruiz', castOwner2: 'hana.sato',
    castNode1: 'node-c1', castNode2: 'node-c2', castNode3: 'node-c3',
  },
};
export const DEFAULT_VERTICAL = 'finance';
export const DEFAULT_CAST = VERTICALS[DEFAULT_VERTICAL];

export const unfilled = (text, cast) => [...String(text).matchAll(TOKEN)].map((m) => m[1]).filter((k) => !Object.hasOwn(cast, k));
export const fill = (text, cast) => String(text).replace(TOKEN, (m, k) => (Object.hasOwn(cast, k) ? cast[k] : m));
// Iterative, so a deep structure cannot overflow the stack.
export function fillDeep(value, cast) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const outRoot = { v: clone(value) };
  const work = [[value, outRoot, 'v']];
  while (work.length) {
    const [src, dst, key] = work.pop();
    if (typeof src === 'string') { dst[key] = fill(src, cast); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src);
    dst[key] = copy;
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k]);
  }
  return outRoot.v;
}

export const verticalFrom = (id) => (typeof id === 'string' && Object.hasOwn(VERTICALS, id) ? id : DEFAULT_VERTICAL);

// Only brand, host and the first key owner, as short plain strings; anything else in the file is ignored. The owner must not collide with the second one.
export function loadCast(file, vertical = DEFAULT_VERTICAL) {
  const cast = { ...VERTICALS[verticalFrom(vertical)] };
  if (!file) return cast;
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const [short, key] of [['brand', 'castBrand'], ['owner', 'castOwner'], ['host', 'castHost']]) {
      const v = cfg?.cast?.[short];
      if (typeof v !== 'string' || !v.trim()) continue;
      const clean = v.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, ' ').trim().slice(0, MAX_CAST);
      if (/:\/\/|@/.test(clean) || scanHosts(clean).length) continue;
      if (short !== 'brand' && !ID.test(clean.toLowerCase())) continue;
      if (short === 'host' && clean.includes('.')) continue;
      const val = short === 'brand' ? clean : clean.toLowerCase();
      if (short === 'owner' && Object.entries(cast).some(([k, x]) => k !== 'castOwner' && x === val)) continue;
      cast[key] = val;
    }
  } catch { /* no file or not JSON: the defaults */ }
  return cast;
}
