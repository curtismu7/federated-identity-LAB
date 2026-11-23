# Federated Identity LAB

A simulation of Ping's Federated Identity and Self-Hosted Agents release claims, with real local token verification: platform-issued short-lived tokens bound exactly to one issuer, one subject and one audience, enforced lifetimes, key-set refresh and outage handling, a key owned by an identity, revocation, and a Kubernetes sensor that is verified, not vouched.

Tier: Demo
Repo: https://github.com/curtismu7/federated-identity-LAB
Catalog: D107

**Tier: Demo.** Source: the Ping ID4AI Workforce H2 2026 deck, slides 35, 40, 41 (and 44 for the sensor), release 2026-11-02. **Every product claim is a Ping release claim, UNVERIFIED on our tenant.** Nothing here calls a real issuer, cluster, identity provider or tenant. The one call that leaves your machine is the optional Real-mode Privilege gateway check, and only when you run it with a gateway configured.

**Naming.** Federated Identity is the new display name of Non-Human Identity (slide 35). The console API object is still `NonHumanIdentity` at `/v1/nonhumanidentities` (console swagger, 2026-10-31, schema only), so keep the old names in API calls, `RefKind` values and log greps. Slide 57 of the deck still lists "Non-Human Identity": we follow slide 35 and flag the inconsistency. Self-Hosted Agents is the new name of "NHI Agents Discovery & Enforcement".

## What is simulated

**Mock mode (default).** Everything runs offline in one process and is read-only. Fifteen scripted scenarios (one credential and three services, exact binding, lookalikes that are different strings, a key bound to main refusing a fork pull request, enforced lifetimes, algorithms and tampering, an unknown signing key triggering a refresh, an issuer outage, a private issuer with pinned keys, revocation and attribution, a key owned by an identity, four platforms, a SPIFFE binding story (valid, mismatched, untrusted), a sensor that reports with its own token, and audit versus enforce) were run through the lab's own engine, and the tables the pages show are generated from that run (`server/src/mockTable.json`; a doctor check and a test fail on drift, and another test replays every scenario through the HTTP API and compares the final state). The table holds decoded claims and step results, never a token or key. Every write is refused with 409.

**Live mode (owner-run, still local).** The same engine acts on your own tokens and actions. Five mock issuers (a Kubernetes API server, GitHub Actions, GitLab CI, a SPIFFE/SPIRE server and a private issuer) each hold an RSA key generated in memory and publish a JWKS you can rotate and take down. You mint a token (a real RS256 signature from a mock issuer, good only in this lab), edit or tamper it, and the lab's gateway verifies it in fifteen steps with the exact refusal reason. A lab clock moves forward only, by a capped move. The banner says which mode you are in. Live's own engine never leaves loopback; no JWKS is fetched from any network (the Real-mode gateway check, below, is the one call that goes out).

What it shows (tabs):

1. **Federated Identity (slide 40).** Five seeded identities and your own: one issuer, one subject, one audience (mandatory), a lifetime cap (default one hour), pinned claims (repository, environment), scopes, `AllowAnySubject` as an explicit opt-in, revoke, restore, remove. Keys: a key owned by an identity versus a stored key that borrows a person (a person going inactive stops the stored key, not the identity's), and the two refusals we measured.
2. **Verify.** A token editor with 37 presets, eight of them lookalikes (a zero-width space, a fullwidth or Cyrillic letter, another case, a percent-encoded colon, a trailing space, a trailing slash on the audience or the issuer), that **signs exactly what you type**: a claim is never trimmed, decoded or normalised, hidden characters are written out as `\u{...}` in every answer, the mint adds a notice for anything that is not plain ASCII, a claim over 160 characters is refused (not cut), and a claim that looks like a credential is refused (not masked and then signed). (A second, in-browser check of the signature: see below): edit any claim (iss, sub, aud, iat, exp, nbf, extra, alg, kid), mint, tamper, verify. The result shows all fifteen steps, the exact reason, what a caller would see (the real gateway's refusals are thin: measured, our note), the principal, the deployment, and the outbound request to the backend with the application's own credential, MASKED, and the workload token not in it.
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
- **Shown raw on purpose** (education, rule 4): the token the lab's own mock issuer just minted (`mintedToken`), the W3C `traceparent` and trace id the lab writes, and the public half (`n`, `e`) of an RSA key in a key set. A token the visitor pastes is masked, never shown. These names are listed in `server/src/mask.js`; a visitor cannot make one of them appear on a field they type, because the engine reserves those claim names. One more value is shown by path, not by name: in the Real "What Privilege did" trace the hop's shortened session id (the first 8 characters plus `… (shortened)`) under `trace.(listing|refusal).(request|response).headers.Mcp-Session-Id`. The same member name anywhere else in an answer, or a longer value there, is still masked.

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

All standalone apps read one settings file, `~/Development/.env`, which must be mode 600. `STANDALONE_ENV` overrides its path. This lab needs none of it. It parses the file (`util.parseEnv`) and takes exactly one optional key into its environment; no other key from the file ever enters it (the Real-mode gateway check reads its own `FID_GW_*` keys from the file or the environment, see Real mode):

- `FID_LAB_MODE` (optional): `mock` (default) or `live`, the mode the page opens in. The header toggle switches per visit. A bare `MODE` in the shared file is ignored, because it may belong to another app.

The shared file holds no `PORT`: the lab keeps its port default in code. Admin or worker credentials never belong in that file (they live in `~/.config/demo-kit/provisioning.json`), and this lab uses none. It holds no tenant credential; the one key it reads for the Real-mode gateway check is an agent access key. The doctor reports whether the file exists and its mode, and never prints a value.

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

The header has a **Mock / Live** toggle on every page, and the banner and the mode chip show the same mode. Mock reads tables generated from the engine (fifteen scripted scenarios per vertical; a scenario picker on the Verify tab) and is read-only: every write control is off and the API answers 409. Live drives this workspace's engine (one per vertical): the token editor, the issuers, the clock, identities, keys, sensors and the policy.

**What Privilege did (Rule 25).** Under the Verify result (and under each scripted verify step in Mock) the page shows the call to the gateway through the family's shared `GatewayTrace`: the exact request, the exact response (both in the shared JSON pane) and the fifteen decisions between them. On the Verify tab this lab never contacts a real Privilege gateway: the gateway is its own simulation, so every decision is marked **checked** (the engine computed it) and a step the verification never reached is "not reached". The visitor's token is never in the trace, only its length. Files: `web/src/gateway-trace/` and `server/src/gatewayTrace.js` (vendored byte-for-byte, pinned by `gateway-trace.sha256`), the lab's own builder is `server/src/verifyTrace.js`. The stored-key call and the sensor report are not traced.

## Run observability (rule 27)

**What each layer logged for this run** is the family's shared panel (`web/src/run-observability/`, vendored byte for byte with a sha256 pin that `scripts/run-observability.pin.test.mjs` checks; the collector is `server/src/runObservability.js`). It is an **excerpt**: addresses, ids, emails and credential-shaped text are masked, and a token, an agent key or a gateway address is never part of a row. In Mock it sits under the scripted scenarios on the Verify tab; in Real it sits under the gateway card and its "What Privilege did" trace, which it complements and does not replace. It follows the toggle: it never shows a record made in the other mode.

| Layer | Mock: the recorded scenario (`simulated`) | Real: the page's gateway check (`response`) |
|---|---|---|
| Person | the custodian of a stored key, and a person set active or inactive, as information: the lab has no sign-in, the person is a stand-in | not logged: no person signs in, the call is made with an agent access key |
| Agent | a mock issuer signing a token, and the Federated Identity the lab's gateway checked a token against, as information: there is no OBO token | not logged: the caller is an agent access key, and the gateway's log of it is not read |
| Authorize | not logged: this lab does not call PingOne Authorize | not logged |
| Privilege | the lab's own Federated Identity model and sensor policy (not PingOne Privilege): a change to the model is information; the sensor policy's effect on a finding is **blocked** only in enforce mode, and information in audit mode, for monitor and warn, and outside the policy's namespaces | not logged: Privilege's policy log is not read, and the lab's own model and policy stay in its local engine in Real too |
| Agent gateway | the lab's own simulated gateway (a stand-in, not the Privilege gateway): its verdict on a workload token, a stored key or a sensor's report token, **allowed**, or **refused** at the check it stopped at (check N of 15) | what the lab received from the gateway: `tools/list` (allowed when it returns tools, refused on 401 or 403) and one probe for a tool nothing grants (refused on 401, 403, a JSON-RPC error or `isError`; allowed if the gateway lets it through). Another status, or an answer that cannot be read as a tool result, is information |
| Resource server | not logged: this lab has no resource server; the request its gateway would send on, with the application's own credential masked, is modelled and nothing answers it | not logged: the tool behind the gateway wrote nothing the lab can read |

- **What a run is.** In Mock, one recorded scenario: its rows are read when the page asks, from the steps the generated table already holds (the table itself is untouched, like the gateway trace), and each message starts with the number of the scripted step it came from. The counts are rows, not calls: a verification gives an Agent row and an Agent gateway row. In Real, one gateway check (`POST /api/gateway-check`), kept under the run id the answer carries (a counter plus random bits, so ids are unique within a process and, probabilistically, across restarts and visitors). The lab's own engine in Real (the Verify, Issuers and Self-Hosted Agents tabs, which the toggle calls "real" but which are the lab's local simulation) is not a Real record: its decisions are stdout lines only.
- **Time is when the lab recorded it.** Mock rows carry the **lab clock** of the recorded scenario (it starts at 2026-11-02 09:00 UTC and moves only when a step moves it), so the steps of one scenario can share a time; their order is kept. Real rows carry the wall-clock time of the gateway's reply (the call's start plus its own measured time, not the moment the helper finished closing its session). Nothing is given an invented spacing.
- **Where a run leaves logs.** The container's stdout. In Live, each decision the engine makes is one line, written when the action ran: `<iso> federated-identity-lab decision step=<step> layer=<layer> actor=<id> result=<passed|stopped|unclear|no-reply> cause=<cause> labtime=<lab clock> run=<id>`. In Real, each answer from the gateway is one line with the same shape (no `labtime`); a call that got no reply is `result=no-reply` and has no row. A request turned away before any decision (a bad field, an unknown id, a cap) is one line under `run=-`. A line never holds a credential, a claim, a name you typed or a gateway address (the actor is an id the lab wrote, such as `fid-001` or `key-0006`), and uses none of the words the family's log matchers read. Mock reads recorded tables: nothing runs, so it writes no line. The audit log (Audit tab) lives in memory and is gone on a restart or Reset.
- **Where the logs can stream.** The family log collector (`shared/ping-log-collector`) does not list this container today, so nothing ships these lines until its source list names it; the SIEM time would then be Docker's wall-clock time for the line, and the lab clock stays inside the line as `labtime`. Privilege's own records of the agent key (its gateway log, its SIEM index, the console Activity Logs) are not read by this lab.
- **Not logged today, and why.** PingOne Authorize has no container log (and this lab does not call it); the PingFederate `audit.log` is not shipped; the gateway's refusal and block line shapes are unconfirmed; the PingOne audit reader does not exist. Real therefore shows only what the lab received, as `response` rows, never as `logged`.
- **What the panel leaves out.** A request the lab turned away before any decision (a key form the console model refuses, a bad field, a cap), and a clock move, an issuer's key rotation or a key-set refresh, have no row: they are not a decision of one of the six layers. A sensor's findings are weighed only when its report was taken.
- **Reset.** Reset clears your workspace's engines and nothing else: the gateway checks the lab kept stay (the last five, one list for the lab, because the page's gateway card sends no workspace id). The check has nothing to do with the engine.
- **Inherited.** The "Show what Privilege did" trace under the card is this lab's own component and keeps the previous check's trace on screen until the next check answers; the run panel does not: it waits for the new check's run.
- **Not verified.** Nothing here was run against a real gateway: Real was exercised only against an in-process fake. The reading of each reply (401 and 403, a JSON-RPC error, `isError`, another status) is the lab's own. The shared gateway client does not say which of its requests (the opening handshake or the call itself) got a status or a JSON-RPC error, so such a row says "while the lab was opening or making" the call and does not name a step. A failure carrying exactly the client's "unreachable" or "timed out" words is read as no connection and shown as no reply (and the record is marked partial); a gateway refusal that used those exact words could, in rare cases, be read this way. It is never shown as allowed.
- **Settings.** None. This lab reads no logs, so it has no `RUN_OBS_*` variable, vendors the core only, and the compose file never mounts the Docker socket (a test pins all three).

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

On Node 26: 589 tests pass (325 server, 228 web, 36 scripts; 25 of the web tests are the vendored run-observability panel's own).

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

---

## Real mode: through the PingOne Privilege gateway

Real mode here is one live call through a PingOne Privilege gateway
(the origin you set in `FID_GW_URL`) with an agent access key from the shared settings
file (`~/Development/.env`, or the file `STANDALONE_ENV` names) or the environment, which wins.

**Privilege objects this lab uses:**

| Object | Value |
|---|---|
| Gateway | the origin in `FID_GW_URL` (a PingOne Privilege gateway you can reach) |
| Agentic App | one named in `FID_GW_APPS` (for example `aggregate-limited`), client path `/<app>/mcp` |
| Caller | agent access key `FID_GW_KEY_LAB_AGENT` (write-only, never shown) |
| Backend | `aggregate` = the gateway's MCP aggregate over `opensearch` (9 tools) + `banking-mcp` (33 tools); `aggregate-limited` = the same members with a tool filter |

**What runs in Real:** the **Privilege gateway check** (`POST /api/gateway-check`, card on the
page) — one live `tools/list` through the Agentic App with the key, then one `tools/call` probe of a
tool no policy grants, so you see the gateway's own refusal shape. The gateway's words come
back unaltered (keys scrubbed). Settings keys: `FID_GW_URL`, `FID_GW_APPS`,
`FID_GW_KEY_<NAME>` (optional `FID_GW_VERSION`).

In Real mode the same panel (source `real`) also shows the gateway check's two calls, `tools/list` and the refusal probe, from the shared hop's own capture (button **Show what Privilege did**, which draws the trace the card's own check already captured, with no second gateway call). A real gateway reports no per-check detail, so each decision there is **observed** (read from the response) or **inferred** (read from the outcome), never **checked**; the agent key is redacted at capture and never appears.
