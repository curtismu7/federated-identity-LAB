# Federated Identity LAB

A simulation of Ping's Federated Identity and Self-Hosted Agents release claims, with real local token verification: platform-issued short-lived tokens bound exactly to one issuer, one subject and one audience, enforced lifetimes, key-set refresh and outage handling, a key owned by an identity, revocation, and a Kubernetes sensor that is verified, not vouched.

Tier: Demo
Repo: https://github.com/curtismu7/federated-identity-LAB
Catalog: D107

**Tier: Demo.** Source: the Ping ID4AI Workforce H2 2026 deck, slides 35, 40, 41 (and 44 for the sensor), release 2026-11-02. **Every product claim is a Ping release claim, UNVERIFIED on our tenant.** Nothing here calls a real gateway, issuer, cluster, identity provider or tenant, and nothing leaves your machine.

**Naming.** Federated Identity is the new display name of Non-Human Identity (slide 35). The console API object is still `NonHumanIdentity` at `/v1/nonhumanidentities` (console swagger, 2026-10-31, schema only), so keep the old names in API calls, `RefKind` values and log greps. Slide 57 of the deck still lists "Non-Human Identity": we follow slide 35 and flag the inconsistency. Self-Hosted Agents is the new name of "NHI Agents Discovery & Enforcement".

## What is simulated

**Mock mode (default).** Everything runs offline in one process and is read-only. Fourteen scripted scenarios (one credential and three services, exact binding, lookalikes that are different strings, a key bound to main refusing a fork pull request, enforced lifetimes, algorithms and tampering, an unknown signing key triggering a refresh, an issuer outage, a private issuer with pinned keys, revocation and attribution, a key owned by an identity, four platforms, a sensor that reports with its own token, and audit versus enforce) were run through the lab's own engine, and the tables the pages show are generated from that run (`server/src/mockTable.json`; a doctor check and a test fail on drift, and another test replays every scenario through the HTTP API and compares the final state). The table holds decoded claims and step results, never a token or key. Every write is refused with 409.

**Live mode (owner-run, still local).** The same engine acts on your own tokens and actions. Five mock issuers (a Kubernetes API server, GitHub Actions, GitLab CI, a SPIFFE/SPIRE server and a private issuer) each hold an RSA key generated in memory and publish a JWKS you can rotate and take down. You mint a token (a real RS256 signature from a mock issuer, good only in this lab), edit or tamper it, and the lab's gateway verifies it in fifteen steps with the exact refusal reason. A lab clock moves forward only, by a capped move. The banner says which mode you are in. Live never leaves loopback; no JWKS is fetched from any network.

What it shows (tabs):

1. **Federated Identity (slide 40).** Five seeded identities and your own: one issuer, one subject, one audience (mandatory), a lifetime cap (default one hour), pinned claims (repository, environment), scopes, `AllowAnySubject` as an explicit opt-in, revoke, restore, remove. Keys: a key owned by an identity versus a stored key that borrows a person (a person going inactive stops the stored key, not the identity's), and the two refusals we measured.
2. **Verify.** A token editor with 35 presets, eight of them lookalikes (a zero-width space, a fullwidth or Cyrillic letter, another case, a percent-encoded colon, a trailing space, a trailing slash on the audience or the issuer), that **signs exactly what you type**: a claim is never trimmed, decoded or normalised, hidden characters are written out as `\u{...}` in every answer, the mint adds a notice for anything that is not plain ASCII, a claim over 160 characters is refused (not cut), and a claim that looks like a credential is refused (not masked and then signed). (A second, in-browser check of the signature: see below): edit any claim (iss, sub, aud, iat, exp, nbf, extra, alg, kid), mint, tamper, verify. The result shows all fifteen steps, the exact reason, what a caller would see (the real gateway's refusals are thin: measured, our note), the principal, the deployment, and the outbound request to the backend with the application's own credential, MASKED, and the workload token not in it.
   **In-browser signature check (Live only, lab-invented UI).** Next to the server verdict the page shows "Verified in this browser (WebCrypto RS256)": it fetches the issuer's PUBLIC key set from this lab's own server (same origin, nothing else is contacted, no private key ever reaches the page), imports the key with `crypto.subtle.importKey` (RSASSA-PKCS1-v1_5, SHA-256) and verifies the signature over `header.payload`. It checks the signature ONLY: claims, audience, lifetime, subject, pinned claims, the key and the scope are the server's fifteen steps, so the browser result is not the full verdict. The two are shown side by side and any disagreement is flagged (for example a retired key the gateway still holds in its cache but the issuer no longer publishes). A kid that is not in the published set is "no key", not "invalid"; an algorithm other than RS256 and a malformed token are "refused" with the reason; an issuer that is down is "unavailable" (a browser has no last-known-good cache, the gateway does); nothing ever throws into the page. In Mock the check is disabled with the reason shown, because the Mock tables hold decoded claims only, never a token or a key.
3. **Issuers and keys.** The lab clock; rotate (retire the old key or keep it published), take down, bring up; each identity's key set (fetched or pinned), last attempt, next refresh, history; refresh now; pin again.
4. **Deployment models.** The five models of slide 40 as a table. Sidecar injection is "in development" on the slide: no behaviour is claimed. A stored agent key is the fallback.
5. **Self-Hosted Agents (slide 41).** Enrol a sensor (its own identity, a generated audience, its own key), simulate its reports (the lab runs no eBPF), see the node taken from the token's claims while a forged node in the body is ignored and recorded as ignored, revoke the identity (findings stay attributed), and bind an enforcement policy (modes off, audit, enforce; actions allow, monitor, warn, deny; named namespaces or the whole cluster). Audit mode records would-have-blocked and blocks nothing.
6. **Audit.** Every request attributed to a deployment, every refusal with its code, filters, and one-click revocation.
7. **Diagram.** ReactFlow, drawn from diagram-studio/1 data loaded by name: movable boxes, Simulate, speed, Reset (restores box positions). Three diagrams.
8. **Talk track,** with a "Why it matters" entry for each feature (challenge, technical and business lines, marked as Ping claims), what the deck, the schema and our own tests leave unresolved, and what we measured. Also in `docs/talk-track.md`. Three vertical packs (finance, health, retail) change every name.

### What is lab-invented, lab reading, deck claim, measured

Each field is tagged in the app as "deck claim", "console swagger name (schema only)", "lab reading", "lab-invented" or "measured (our note)". The main ones:

- **Accepted across the MCP and LLM gateways.** Slide 40 says so. Our own earlier test of the MCP path did not prove it (measured, our note, 2026-10-21, pre-release gateway: 401 on the MCP path and the LLM route and no accepted or rejected line in the gateway log). Not re-tested on the release. The lab implements the claim and proves nothing about the product.
- **The token is never forwarded** (deck claim). The console swagger also lists an application `AuthMode` `token-pass` that forwards the verified assertion unchanged; shown, not resolved. The lab models static, per-user from the vault (described, not demonstrated: it needs a human end user) and OAuth.
- **Swagger names (schema only).** `imodelNonHumanIdentitySpec { Description, Enabled, Federation, Scopes, SubjectBinding, UserClaim, NotAfter }`, `modelAgentWorkloadIdentity { Issuer, Subject, Audience, JwksURI, JWKS, MaxTokenLifetimeSec, RequiredClaims, Platform, AllowAnySubject }`, the key's `CustodianRef` and `WorkloadIdentity`, and `imodelShadowAIPolicySpec`. A name proves a field exists, not how it behaves. `SubjectBinding` and `UserClaim` are not modelled. The swagger names seven policy actions and a `Disabled` flag; the lab follows the deck's four actions and three modes.
- **Lab readings.** Lifetime is exp minus iat; iat is required and may not be in the future (otherwise a future iat hides a long lifetime); there is no clock-skew leeway; a kid is required; an unknown kid triggers a key-set refresh, at most one per identity per lab minute (a lab-invented cooldown; the deck does not say whether that refresh is limited); the scopes on a key are intersected with the identity's; a deployment is named from namespace, service account and pod (or repository, ref and run); the fifteen steps, their order and the reason codes are the lab's.
- **Measured (our note), never the deck's.** A key cannot carry its own workload identity and name an identity as its owner, and cannot name a person too; an identity with no key behind it authenticates nobody; a key stops when its custodian goes inactive; the gateway's refusals are thin; audiences generated for sensors look like `priv-nhi-<random>`; app and policy edits took about four minutes to reach the gateway (revocation was not measured).
- **The sensor.** The lab runs no eBPF and no sensor. Its reports are simulated; the claim names the lab reads (`node`, `pod`, `repository`, `environment`, `run_id`, `project_path`) are the lab's own flat names, not the exact shape of a real Kubernetes or GitHub token.
- **The browser check** (lab-invented UI, no deck claim) needs a secure context (localhost counts) and the lab's own server; it fetches the issuer's published key set afresh each time, so it sees a rotation at once while the gateway sees it at its next refresh.
- **Browser parser.** The page's parser is strict exactly like the server's: nothing is trimmed, a byte-order mark and invalid UTF-8 are refused, base64url must be canonical (the unused bits of a signature's last character must be zero, so a signature cannot be altered without changing its bytes), and a `crit` header is rejected (RFC 7515: the lab understands no critical extension). The browser looks the issuer up by the token's `iss` only (the lab's own five issuers); it does not model an identity's pinned custom keys beyond the issuer's published set. When the two still differ, the page says why (a parse-stage difference, or a key lookup difference such as a retired key).
- **Unknown-kid refresh cooldown (lab-invented).** The deck does not say whether refreshing on an unknown signing key is limited. The lab allows one such refresh per identity per lab minute, so a caller sending endless made-up kids cannot make the gateway hammer the issuer; inside the cooldown the token is refused without a refresh, and the page and the audit say so.
- **No single-use tokens.** The lab does not model replay protection: presenting the same valid token twice, to the gateway or as a sensor report, is accepted twice. The deck does not claim single use for these tokens.
- **Duplicate bindings.** Two identities may bind the same issuer and subject; a request that does not name the identity is then refused as `ambiguous_identity` (intentional); naming the identity resolves it. A disabled or expired identity still counts: the lookup by issuer and subject comes before the enabled and expiry checks (so the refusal can say "disabled" or "expired" for the identity it found), so a disabled or expired twin makes a token that names no identity `ambiguous_identity` (a test pins this).
- **Shared lab keys.** The RSA key pool is generated lazily in memory and shared by every workspace and vertical of one process, so a token minted in one workspace verifies in another (the keys are worthless outside the process, and only public halves are ever published). Isolating them per workspace would cost one key generation per issuer per visitor.
- **RS256 only.** Another asymmetric algorithm is refused as "unsupported by the lab", which is a lab limit, not a product claim. alg `none` and HS* are refused as the deck says.

### What the masking catches and what it misses

Masking is done by one shared module, not by this lab: the family's canonical masker, shared-masker **1.4.0** (commit 9bc664a), copied unchanged into `server/src/shared/` (`mask.js`, `hygiene.js`; only a one-line header was added). The lab's own `mask.js`, `credentials.js` and `clean.js` are thin adapters over it and hold no detector list. It is a **heuristic**, so do not type a real secret. What a visitor types is folded (NFKC, escapes, invisible and control characters, percent-encoding and the other encodings the masker decodes, look-alike letters it knows) and matched against the masker's shapes: private-key blocks, vendor tokens by prefix, JWTs, `Bearer` and `Basic` values, `user:password@host`, `Authorization:` and `Cookie:` lines, JSON and YAML keys, command lines, and keyword assignments and phrases (`password: x`, `the key is x`, `my token is x`, in the spellings the masker lists, including a keyword split by tab, U+2028, U+1680 or a control character). The shared README lists the rules; this lab adds none. Object KEYS are masked as well as values, in every answer.

What the lab itself decides:
- **Where it is applied.** Names, descriptions and notes are masked on the way in (the whole text first, then cut to 400 characters), hidden and control characters are then written out as `\u{..}` (never deleted after masking, which could join the pieces of a secret the masker left alone). Every JSON answer (state, hops, refusals, audit, path ids) is masked again on the way out, values and object keys: a second layer, so a value that reached the state by a future bug is still masked (a test breaks the first layer on purpose to prove it). The story, the diagrams and the Mock tables are text the lab wrote itself; they are masked as prose (member names are not read, secret-looking text still is).
- **Claims are refused, not masked.** A claim, or a stored value (an issuer, a subject, an audience, a namespace), that the masker flags is refused with fixed text and never signed, stored or echoed. The lab adds one policy of its own for these values: a run of 24 or more letters and digits is not an identity name (a SPIFFE ID or a Kubernetes subject has separators; a signature or a key does not). The price: a trace id or an image digest typed as a claim is refused (3 of the 1,817 ordinary plain strings in the shared corpus).
- **Shown raw on purpose** (education, rule 4): the token the lab's own mock issuer just minted (`mintedToken`), the W3C `traceparent` and trace id the lab writes, and the public half (`n`, `e`) of an RSA key in a key set. A token the visitor pastes is masked, never shown. These names are listed in `server/src/mask.js`; a visitor cannot make one of them appear on a field they type, because the engine reserves those claim names.

**False-positive trade-off.** The masker prefers to hide a value that looks like a secret (a digit, a symbol or a capital, 6 or more characters) and says so: `password=required`, `token: dolphins`, `mailto:alice@host.example`, `Basic Plan2025` and `Cookie:` lines are masked, and the word after `my password is` is masked. The 1,926 ordinary strings of the shared corpus (prose, code, paths, ids, hashes) are left unchanged by the adapters. Two sentences in the lab's own story had to be reworded because the masker read them as secrets (a list "tokens, GitHub" and "the token's claims, not the sender's"); both are masker false positives to report upstream.

**What it misses (measured, not promised).**
- A secret typed as a bare word with no keyword near it; a passphrase of plain words (`password: correct horse battery staple` keeps `staple`); a 1 or 2 character value; a loose form with no digit (`the secret is swordfish`); homoglyphs outside its table; leetspeak; ROT13; other languages than the five it reads; a secret split across two fields.
- **Known masker gap (pinned by a test): 34 of the 3,416 plain leak probes in the shared corpus are not masked when ordinary words come first in the same field** (`n ` before a JSON blob of parameters: 23; a NUL-split blob: 6; an INI section named after the credential: 4; a column list: 1). The masker finds those layouts only at the start of the text. A name or a note of this lab that starts with a word and then holds one of them shows the secret. The fix belongs in shared-masker; the lab does not paper over it.

**What was run.** `server/test/corpus.test.js` runs the shared corpora through the adapters: 3,754 leak probes in 65 families (3,416 plain, 338 structured) and 1,926 ordinary strings (1,817 plain, 109 structured). No secret survives (as a value, a list member, an object key, a structured probe; a claim of it is refused), and no ordinary string changes. `corpus-http.test.js` types 62 of them (one per family) into every field, key, path segment, query and header of every endpoint and searches every answer, the state afterwards and stdout / stderr. `known-leaks.test.js` covers the leaks found in review: raw issuer, aud and sub in `hops[0].request.body` on all 16 write endpoints and in path ids, for `the key is x`, `pass<TAB>word: x`, `pass<U+2028>word: x`, U+1680 inside a keyword, and four times percent-encoded `password: x` (clock minutes, mint issuer).

### Known limits of the model

- **The token is at most 4096 characters, on both verifiers.** The server refuses a longer one at the parse step (`malformed_token`); the in-browser check applies the same cap and refuses it too, so the two agree. The token box counts its characters, says when it is over the limit and never cuts the text.
- **Plain words, fixed answers.** The edge is boring on purpose, from one route table in `app.js`: an unknown address is the JSON `{"error":"not_found"}` (404, no `Allow`, the path is never echoed); a known path with the wrong method is 405 with the exact `Allow` header (`POST` on `/api/state` answers `GET, HEAD`); a charset other than utf-8 is 415 `unsupported_charset`, and the value is neither read into the answer nor logged; a malformed or oversize body or a bad percent-escape is a fixed 400 or 413; any other error is a fixed 500 `internal_error` (no message, no stack). The built page is the answer for page addresses only (`isPageAddress`): `/%`, `/%2e%2e/%2e%2e/etc/passwd`, `/assets`, a missing asset or any path with a dot in the last segment is the JSON 404, never a 200 page.
- **Workspace ids.** `X-Workspace` is `default` or `w-` plus a lab name of letters, digits and hyphens (at most 40 characters in all) that the shared hygiene rule (`safeWorkspaceId`) accepts. A credential-shaped id (`pw-...`, `token-...`, `sk-...`, `abcdefghijklmnop1234`, 24 or more hex characters, a keyword followed by something that looks typed) is refused with 400 `bad_workspace` before any workspace is created, and is never echoed. This is stricter than before (any lowercase id was accepted): an old saved id without the `w-` prefix is refused once and the page makes a new one. Cost: `w-password-reset` and `w-token-exchange` are fine, `w-password-abc123` is not.

- A request body is at most 32 KB and must declare charset utf-8 or none (any other charset, including the alias `utf8`, is 415 with fixed text). A claim is at most 160 characters and is never cut (credential-shaped text in a claim is refused, in a name or description it is masked: the shared masker, a heuristic, so do not type a real secret); a token at most 4096 characters; at most 12 extra claims and 5 audience values. A workspace keeps at most 12 identities, 20 keys, 5 sensors, 200 findings (10 per report), 50 reports and an audit kept in THREE rings so noise cannot push out what matters: 300 changes, 300 allowed requests and 200 refusals (refusals never evict a change or an allowed request, allowed requests never evict a change; within a ring the oldest entry is dropped and counted on the page, per ring). Each verify writes exactly one audit entry. A key set holds 20 history entries per identity. The lab clock moves at most 180 minutes per move and 10080 in total; an issuer rotates at most 5 times. One answer shows at most 40 hops. A request that would break a limit is refused whole.
- There is no real clock: time is the lab clock, starting at a fixed time. A pinned key set is never refreshed.
- Sidecar injection, the kubelet, the SPIRE agent and the CI runners that really mint tokens are not modelled.
- State is per `X-Workspace` id, 500 workspaces and one hour idle at most; a new workspace is refused when the lab is full, nobody else is evicted. The lab has no sign-in and no roles.

## Run from a clone

Prerequisites: Node 26 or newer. Docker only if you use the Docker form. Mock mode works with no setup at all: no tenant, no credentials, no settings file.

```
git clone https://github.com/curtismu7/federated-identity-LAB.git
cd federated-identity-LAB
npm ci
npm run build
npm start
```

Open http://localhost:7400/. Or in one step: `./scripts/run.sh` (installs and builds if needed, runs the doctor, starts). The first start generates five RSA keys, which takes a moment.

## Settings file

All standalone apps read one settings file, `~/Development/.env`, which must be mode 600. `STANDALONE_ENV` overrides its path. This lab needs none of it. It parses the file (`util.parseEnv`) and takes exactly one optional key; no other key from the file ever enters the server's environment:

- `FID_LAB_MODE` (optional): `mock` (default) or `live`, the mode the page opens in. The header toggle switches per visit. A bare `MODE` in the shared file is ignored, because it may belong to another app.

The shared file holds no `PORT`: the lab keeps its port default in code. Admin or worker credentials never belong in that file (they live in `~/.config/demo-kit/provisioning.json`), and this lab uses none. It holds no credential for any tenant. The doctor reports whether the file exists and its mode, and never prints a value.

## Ports, and what to do if the port is taken

```
Ports: federated-identity-LAB listens on 7400 (set with PORT, default 7400).
Port range for this app: 7400-7449.

If the port is taken:
1. Find what is using it:
   lsof -iTCP:7400 -sTCP:LISTEN -n -P
2. If it is an old copy of this app, stop that process: kill <PID>.
3. If it is something else, stop it, or start this app on another port:
   PORT=<other port> npm start
4. Do not use 8080, 5173, 3000, 4000, 4400, 4510, 4600-4601, 18080, 19080 or 19090.
```

Other variables: `VITE_PORT` (Vite dev server, default 7401, `npm run dev -w web`), `HOST_PORT` (Docker host port, default 7400). Keep all of them inside 7400-7449.

## Mock and live modes

The header has a **Mock / Live** toggle on every page, and the banner and the mode chip show the same mode. Mock reads tables generated from the engine (fourteen scripted scenarios per vertical; a scenario picker on the Verify tab) and is read-only: every write control is off and the API answers 409. Live drives this workspace's engine (one per vertical): the token editor, the issuers, the clock, identities, keys, sensors and the policy.

## Health, doctor and reset

```
npm run doctor   # 18 checks, including a real mint, verify, tamper and revoke cycle through the HTTP API; PORT=7409 npm run doctor to use a spare port
npm run reset    # clears the default workspace (identities, keys, issuers, audit, sensors, findings, the lab clock); the UI Reset also restores the diagram
```

`GET /api/health` returns `demo-health/1`. **Honest status codes.** Every write answers with the whole fresh state and the raw hops. A refusal (a bad signature, a wrong subject, a missing audience, a scope not on the key, an unknown kid, a revoked identity, a capped request) is HTTP 400, 401, 403, 404, 409, 502 or 503 with `ok: false`, an error code and, for a token, the step list; there is no flag that turns refusals into 200. The page reads a refusal as data and shows it. A browser logs a non-2xx answer in its console, so deliberately triggering a refusal in the UI leaves a console line, and so does the browser check fetching the key set of an issuer you have taken down (503); nothing else does. The workspace id comes in `X-Workspace`; every hop carries a W3C `traceparent`. Presenter mode: press `P` (Esc leaves); the simulation banner stays. `npm run mock-table`, `npm run talk-track` and `npm run content-pack` regenerate the generated files. See `docs/safety.md`.

## Docker (optional)

```
HOST_PORT=7400 docker compose up --build -d
```

The container publishes to 127.0.0.1 only (a test pins it), runs as a non-root user with a read-only file system and no capabilities. Use OrbStack, not Docker Desktop. `FID_LAB_MODE=live` opens the page in Live mode.

## Tests

```
npm test    # server (node --test), web (vitest, drives the UI against the real server), scripts
```

The shared checks are run by hand, because the scripts are not shipped into this repo's CI: `bash <AI-DEMO-Standalone>/scripts/check-drift.sh .`, `bash <AI-DEMO-Standalone>/scripts/check-css.sh .` and `node <demo-kit-base>/scripts/conformance.mjs . --new`. Conformance warns on rule 18 on purpose: the deferred SE k8s manifests.

On Node 26: 360 tests pass (259 server, 76 web, 25 scripts).

**Mutation checks.** The editable thresholds are pinned by tests written against literal numbers (N accepted, N+1 refused): the notAfter second, the 86400 lifetime cap, the 4096 token cap on both verifiers, the 31,536,000 second mint offset, the 160 character claim, the 24 character run, the 400 character free-text cap, the JWK kid (60), modulus (700) and `oth` member, and the workspace store's 500 visitors and 60 idle minutes. The adapter wiring and the HTTP edge were checked with 15 mutants, one edit at a time, against the server tests (the corpus HTTP sample not included): response mask off; hops body not scrubbed (alone, and together with the response mask); 415 gate removed; workspace credential check removed; one route missing from the 405 table; `isPageAddress` widened to every GET; error handler echoing the message; final JSON 404 removed; adapter opaque names dropped; free-text cleaner not masking; claim check without the shared masker; object keys not masked in the answer; 405 without `Allow`; a refused workspace id still taking a slot. All 15 were killed. The response mask and the input cleaners overlap on purpose (defence in depth): with the response mask off, nothing else notices unless a test breaks the cleaners first, which `the answer mask is a net under the input cleaners` does.

**Known equivalent mutants** (the edit cannot change any answer):
- `refreshKeyset` in `engine.js`: replacing `c.keys = r.keys...` by `c.keys = r.ok ? r.keys... : []` sits in the branch where `r.ok` is already true.

## Troubleshooting

- **The page says "Could not load the lab".** The server is not running, or it is on another port. Start it (`npm start`) and check `PORT`.
- **Port is taken.** See "Ports, and what to do if the port is taken" above.
- **`npm start` refuses to start.** Run `npm run doctor`; the first failing line says why (Node older than 26, a port outside 7400-7449, a drifting mock table).
- **A button is greyed out.** Mock is read-only. Switch to Live in the header.
- **A token is refused.** The verdict names the step and the reason; the lab clock may have moved past the token's expiry, or an issuer may have rotated (mint a fresh token).
- **The mock table is out of date after an engine change.** Run `npm run mock-table`; the doctor and a test tell you when it drifts.

## Ownership

- Owner: the Ping demo family owner (Demo tier).
- License: MIT (see `LICENSE`).
- Found a problem? Open an issue on the repo.

## Not done

No SE k8s build (deferred by the owner, 2026-10-31). Every product claim stays UNVERIFIED until it is measured on a tenant that has the release, in particular that the MCP gateway accepts a workload token (our own earlier test did not prove it). Sidecar injection, SubjectBinding and UserClaim, token-pass and per-user vault credentials for workload callers are not modelled. The deck's slide 35 versus 57 naming conflict is flagged, not resolved.
