// Rule 13: each browser tab gets its own workspace id, kept in sessionStorage, and sends it as X-Workspace on every API call
// that touches server state. Storage can be blocked, so a failure falls back to a per-load id.
const KEY = "fid.workspace";
let memo = null;

// Tests only: forget the id held in memory so the next call picks a new one.
export const forgetWorkspace = () => { memo = null; };

// The server's rule (server/src/workspaces.js validWorkspaceId): lowercase letters, digits and hyphens, 1 to 40; not 24 or more hex characters; not credential-shaped.
// Only the shapes that fit the character set are listed here (sk-, glpat-, xox*-); a test compares this with the server's own check on a table of ids.
export const validWorkspaceId = (s) => typeof s === "string" && /^[a-z0-9-]{1,40}$/.test(s) && !/^[0-9a-f]{24,}$/.test(s) && !/\b(?:sk-[a-z0-9_-]{12,}|glpat-[a-z0-9_-]{12,}|xox[abprs]-[a-z0-9-]{8,})/.test(s);

function freshId() {
  const bytes = new Uint8Array(8);
  (window.crypto || { getRandomValues: (a) => a.map(() => Math.floor(Math.random() * 256)) }).getRandomValues(bytes);
  return `w-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function workspaceId({ renew = false } = {}) {
  if (memo && !renew) return memo;
  if (!renew) { try { const saved = window.sessionStorage.getItem(KEY); if (saved && validWorkspaceId(saved)) return (memo = saved); } catch { /* blocked */ } }
  memo = freshId();
  try { window.sessionStorage.setItem(KEY, memo); } catch { /* blocked */ }
  return memo;
}

// One call to the lab. If the server refuses the id (400 bad_workspace: the id was saved by an older page, or edited by hand), the page makes a new id and asks once more;
// a refusal that happens before anything runs, so asking again is safe.
export async function workspaceFetch(url, opts = {}) {
  const send = () => fetch(url, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}), "x-workspace": workspaceId() } });
  const r = await send();
  if (r.status !== 400) return r;
  let refused = false;
  try { refused = (await r.clone().json())?.error === "bad_workspace"; } catch { /* not JSON */ }
  if (!refused) return r;
  workspaceId({ renew: true });
  return send();
}
