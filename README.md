# Federated Identity LAB

A simulation of Ping's Federated Identity and Self-Hosted Agents release claims, with real local token verification: platform-issued short-lived tokens bound exactly to one issuer, one subject and one audience, enforced lifetimes, key-set refresh and outage handling, a key owned by an identity, revocation, and a Kubernetes sensor that is verified, not vouched.

Tier: Demo
Repo: https://github.com/ping-sandbox/federated-identity-LAB
Catalog: D107

**Tier: Demo.** Source: the Ping ID4AI Workforce H2 2026 deck, slides 35, 40, 41 (and 44 for the sensor), release 2026-11-02. **Every product claim is a Ping release claim, UNVERIFIED on our tenant.** Nothing here calls a real gateway, issuer, cluster, identity provider or tenant, and nothing leaves your machine.

**Naming.** Federated Identity is the new display name of Non-Human Identity (slide 35). The console API object is still `NonHumanIdentity` at `/v1/nonhumanidentities` (console swagger, 2026-10-31, schema only), so keep the old names in API calls, `RefKind` values and log greps. Slide 57 of the deck still lists "Non-Human Identity": we follow slide 35 and flag the inconsistency. Self-Hosted Agents is the new name of "NHI Agents Discovery & Enforcement".

## What is simulated

**Mock mode (default).** Everything runs offline in one process and is read-only. Thirteen scripted scenarios (one credential and three services, exact binding, a key bound to main refusing a fork pull request, enforced lifetimes, algorithms and tampering, an unknown signing key triggering a refresh, an issuer outage, a private issuer with pinned keys, revocation and attribution, a key owned by an identity, four platforms, a sensor that reports with its own token, and audit versus enforce) were run through the lab's own engine, and the tables the pages show are generated from that run (`server/src/mockTable.json`; a doctor check and a test fail on drift, and another test replays every scenario through the HTTP API and compares the final state). The table holds decoded claims and step results, never a token or key. Every write is refused with 409.

**Live mode (owner-run, still local).** The same engine acts on your own tokens and actions. Five mock issuers (a Kubernetes API server, GitHub Actions, GitLab CI, a SPIFFE/SPIRE server and a private issuer) each hold an RSA key generated in memory and publish a JWKS you can rotate and take down. You mint a token (a real RS256 signature from a mock issuer, good only in this lab), edit or tamper it, and the lab's gateway verifies it in fifteen steps with the exact refusal reason. A lab clock moves forward only, by a capped move. The banner says which mode you are in. Live never leaves loopback; no JWKS is fetched from any network.

What it shows (tabs):

1. **Federated Identity (slide 40).** Five seeded identities and your own: one issuer, one subject, one audience (mandatory), a lifetime cap (default one hour), pinned claims (repository, environment), scopes, `AllowAnySubject` as an explicit opt-in, revoke, restore, remove. Keys: a key owned by an identity versus a stored key that borrows a person (a person going inactive stops the stored key, not the identity's), and the two refusals we measured.
2. **Verify.** A token editor with 27 presets (and a second, in-browser check of the signature: see below): edit any claim (iss, sub, aud, iat, exp, nbf, extra, alg, kid), mint, tamper, verify. The result shows all fifteen steps, the exact reason, what a caller would see (the real gateway's refusals are thin: measured, our note), the principal, the deployment, and the outbound request to the backend with the application's own credential, MASKED, and the workload token not in it.
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
- **Lab readings.** Lifetime is exp minus iat; iat is required and may not be in the future (otherwise a future iat hides a long lifetime); there is no clock-skew leeway; a kid is required; every unknown kid triggers a refresh (the deck does not say whether that is rate-limited); the scopes on a key are intersected with the identity's; a deployment is named from namespace, service account and pod (or repository, ref and run); the fifteen steps, their order and the reason codes are the lab's.
- **Measured (our note), never the deck's.** A key cannot carry its own workload identity and name an identity as its owner, and cannot name a person too; an identity with no key behind it authenticates nobody; a key stops when its custodian goes inactive; the gateway's refusals are thin; audiences generated for sensors look like `priv-nhi-<random>`; app and policy edits took about four minutes to reach the gateway (revocation was not measured).
- **The sensor.** The lab runs no eBPF and no sensor. Its reports are simulated; the claim names the lab reads (`node`, `pod`, `repository`, `environment`, `run_id`, `project_path`) are the lab's own flat names, not the exact shape of a real Kubernetes or GitHub token.
- **The browser check** (lab-invented UI, no deck claim) needs a secure context (localhost counts) and the lab's own server; it fetches the issuer's published key set afresh each time, so it sees a rotation at once while the gateway sees it at its next refresh.
- **RS256 only.** Another asymmetric algorithm is refused as "unsupported by the lab", which is a lab limit, not a product claim. alg `none` and HS* are refused as the deck says.

### Known limits of the model

- A request body is at most 32 KB and must be UTF-8 (any other declared charset is 415). A claim string is at most 160 characters (credential-shaped text is masked: a lab-written heuristic, so do not type a real secret); a token at most 4096 characters; at most 12 extra claims and 5 audience values. A workspace keeps at most 12 identities, 20 keys, 5 sensors, 200 findings (10 per report), 50 reports and 500 audit entries (a ring: the oldest is dropped and counted on the page). A key set holds 20 history entries per identity. The lab clock moves at most 180 minutes per move and 10080 in total; an issuer rotates at most 5 times. One answer shows at most 40 hops. A request that would break a limit is refused whole.
- There is no real clock: time is the lab clock, starting at a fixed time. A pinned key set is never refreshed.
- Sidecar injection, the kubelet, the SPIRE agent and the CI runners that really mint tokens are not modelled.
- State is per `X-Workspace` id, 500 workspaces and one hour idle at most; a new workspace is refused when the lab is full, nobody else is evicted. The lab has no sign-in and no roles.

## Run from a clone

Prerequisites: Node 26 or newer. Docker only if you use the Docker form. Mock mode works with no setup at all: no tenant, no credentials, no settings file.

```
git clone https://github.com/ping-sandbox/federated-identity-LAB.git
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

The header has a **Mock / Live** toggle on every page, and the banner and the mode chip show the same mode. Mock reads tables generated from the engine (thirteen scripted scenarios per vertical; a scenario picker on the Verify tab) and is read-only: every write control is off and the API answers 409. Live drives this workspace's engine (one per vertical): the token editor, the issuers, the clock, identities, keys, sensors and the policy.

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

On Node 26: 266 tests pass (187 server, 54 web, 25 scripts).

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
