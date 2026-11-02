// Rule 13: each browser tab gets its own workspace id, kept in sessionStorage, and sends it as X-Workspace on every API call
// that touches server state. Storage can be blocked, so a failure falls back to a per-load id.
const KEY = "fid.workspace";
let memo = null;

// Tests only: forget the id held in memory so the next call picks a new one.
export const forgetWorkspace = () => { memo = null; };

// The server's rule (server/src/workspaces.js validWorkspaceId) accepts "default" and any "w-" lab name its masker finds harmless. This page keeps ONLY the ids it makes itself:
// "w-" and 16 hex digits with at least one letter (the server refuses an all-digit one). That is a subset of the server's rule; a test checks it against the server's own check.
export const validWorkspaceId = (s) => typeof s === "string" && /^w-(?=\d*[a-f])[0-9a-f]{16}$/.test(s);

function freshId() {
  const bytes = new Uint8Array(8);
  for (;;) {
    (window.crypto || { getRandomValues: (a) => a.map(() => Math.floor(Math.random() * 256)) }).getRandomValues(bytes);
    const id = `w-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    if (validWorkspaceId(id)) return id; // 16 digits and no letter is refused by the server: draw again
  }
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
