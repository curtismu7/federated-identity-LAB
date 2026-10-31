# Talk track

<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->

> Ping release claim, UNVERIFIED on our tenant: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 35, 40 and 41 (release 2026-11-02). Nothing here ran against a real gateway, issuer, cluster or tenant.

## Why it matters: Federated Identity (slide 40)

Challenge: Agents hold stored API keys that outlive workloads and stay valid from anywhere if they leak. Standing-secret findings block agent rollout, and unattended operation is held back by key risk. Technical: Secretless, exactly bound, short-lived tokens verified per request against the issuer, instantly revocable. Business: Standing-secret audit findings close, and unattended agents can be approved at all: lower breach risk, faster adoption. (Ping claims, unverified on our tenant.)

## One platform-issued credential, three services

Start on Verify. Pick the Kubernetes identity for agent-runner and mint the right token: it is allowed. Call MCP, then the peer agent, then the LLM provider. The same identity reaches the first two and the LLM call is refused with "key not scoped for llm access": the services are distinguished only by the scopes on the key. Nothing long-lived is stored in the workload: the platform issues the token and rotates it. Fabrikam Bank loses a standing secret.

## Exact binding, and why a fork cannot use main

The identity names one issuer, one subject and one audience, and each is an exact match. Try the wrong subject, the wrong issuer, no audience: each is refused at its own step with the exact reason. Then the GitHub Actions identity bound to fabrikam-eng/ledger-agent on main: a token from main is allowed, a pull request token (even from mallory-labs's fork) is refused because the subject is different, and a right-branch token from the wrong environment is refused by the pinned claim.

## Enforced lifetimes and algorithms

A workload that signs its own tokens could choose its own validity window, so expiry is required and the lifetime is capped at one hour. Mint a token whose exp is still in the future but was issued to live two hours: refused. Try alg none and HS256: refused before any key is looked at. The lab verifies RS256 only, which is a lab limit.

## Resilient key handling

On Issuers and keys, rotate the Kubernetes issuer. The gateway still holds the old key set, so a token signed by the new key has an unknown kid: the gateway refreshes on sight of it and the token verifies. Take the issuer down and rotate again: the unknown kid cannot be resolved and the token is refused, yet tokens signed by the key the gateway already holds keep working: the last known good set is kept through the outage. Move the lab clock fifteen minutes and watch the scheduled refresh. The private issuer has no address: its keys are pinned.

## A key owned by an identity

On the Federated Identity tab a key can name an identity as its owner instead of borrowing maya.chen. Make maya.chen inactive: the stored key that borrowed them stops working, while the keys owned by identities carry on, and the audit names the identity as the principal. The console refuses a key that has its own workload identity and an identity owner, or that names a person too (measured, our note).

## Backend isolation, revocation and attribution

Open the last allowed call: the outbound request to the backend carries the application's own credential, masked, and the workload token is not in it. Revoke the identity and send the very next request: refused. The Audit tab names every request's deployment (namespace and service account and pod, or repository and ref and run), and every refusal.

## Five deployment models

Direct token read, per-job CI/CD tokens and SPIFFE/SPIRE are all modelled. A stored agent key is the fallback where no verifiable token exists, and it stays a standing secret owned by a person. Sidecar injection is in development on the slide: the lab claims no behaviour for it.

## Why it matters: Self-Hosted Agents (slide 41)

Challenge: Platform components are implicitly trusted infrastructure: trusted by network position, not verified per request, and outside policy. That trust model fails modern platform reviews and blocks the platform's own adoption. Technical: Every component authenticates per request with a platform-issued token, is policy-bound, and is cut off the moment its identity is removed. Business: Materially reduces insider and compromise risk on privileged components and simplifies compliance evidence. (Ping claims, unverified on our tenant.)

## The sensor reports with its own token

Enrol a sensor: Privilege generates an audience nobody can guess and the pod receives a short-lived token for it. The sensor reports findings (AI agents, MCP servers and model servers in pods). The controller verifies issuer, subject, audience and scope on every report and takes the node from the token, so a forged node field in the body is ignored and recorded as ignored. A token minted for another audience is refused. Revoke the identity and the next report is refused while every earlier finding stays attributed to its node. The lab runs no eBPF: the reports are simulated.

## Enforcement: audit first, then enforce

A policy bound to the sensor's identity names the namespaces in scope (or the whole cluster), a mode (off, audit, enforce) and an action per kind (allow, monitor, warn, deny). In audit mode a denied finding is recorded as would-have-blocked and nothing is blocked; switch to enforce and the same report is blocked. A finding in a namespace outside the scope is not evaluated.

## What we measured, and what we did not

Everything here is a Ping release claim, unverified on our tenant. Two things to say out loud. First, the deck says Federated Identity is accepted across the MCP and LLM gateways; our own earlier test of the MCP path did not prove it (measured, our note). Second, the deck calls the object Federated Identity on slide 35 but slide 57 still says Non-Human Identity, and the console API still says NonHumanIdentity: confirm before correcting a customer.

## What the deck, the schema and our own tests leave unresolved (shown, not resolved)

- **Slide 35 retires Non-Human Identity; slide 57 still uses it.** Slide 35 says Federated Identity is the updated term and Non-Human Identity is retired. Slide 57 of the deck still lists "Non-Human Identity". The lab follows slide 35. The console API did not rename: the object is still NonHumanIdentity at /v1/nonhumanidentities (console swagger, 2026-10-31), and so are RefKind values and log lines. Self-Hosted Agents is the new name of "NHI Agents Discovery & Enforcement".
- **Accepted across the MCP and LLM gateways: the deck says so, our test did not prove it.** Slide 40 says Federated Identity is accepted across the MCP and LLM gateways with identical verification. Measured (our note, 2026-10-21, pre-release gateway): with a token whose issuer, subject, audience and lifetime all matched, the MCP path answered 401 "Bearer token required" and the LLM route 401 "invalid virtual key", and the gateway logged no "workload token accepted" or "rejected" line for either, so the check was never reached. We could not tell whether that image evaluates workload tokens on those routes. Not re-tested on the release. The lab implements the deck's claim and proves nothing about the product.
- **The token is never forwarded, but the schema lists token-pass.** Slide 40 says the token stops at the gateway and is never forwarded. The console swagger (2026-10-31, schema only) lists an application AuthMode token-pass, whose description says it forwards the verified inbound workload assertion unchanged. The deck's list of backend credentials (static, per-user from the vault, OAuth) does not include it. Measured (our note): a key caller cannot satisfy token-pass. The lab models only the three deck modes and never forwards the token; whether token-pass is a deliberate opt-in is not stated.
- **Modes and actions: the deck and the schema name different sets.** The deck names modes off, audit and enforce and actions allow, monitor, warn and deny. The console swagger policy object (imodelShadowAIPolicySpec, schema only) has a Disabled flag and an Action enum of seven names (Monitor, Allow, Warn, RequireApproval, Deny, Enforce, Exempt). The lab follows the deck and does not claim to know how the two map.
- **Scopes on the key, or on the identity?.** The deck says the scopes are on the key. The swagger also gives the identity a Scopes list ("what this identity may do"). The lab keeps both and applies the intersection (lab reading): a key can only narrow what its identity may do.
- **"Immediately": ours was not measured.** The deck says revoking the identity cuts the workload off immediately. Measured (our note): app and policy edits took about four minutes to reach the gateway; we did not measure revocation. The lab refuses on the very next request because that is the deck's claim, not because it models propagation.
- **The slides say GA; the release is not on our tenant.** Slides 40 and 41 carry a GA tag. The release is dated 2026-11-02 and is not on our tenant, so nothing here has been measured against it.

## What we measured ourselves (our notes, never the deck's)

- Measured (our note, 2026-10-21, pre-release gateway): workload-token acceptance on the MCP path and on the LLM route was NOT proven; both answered 401 and no accepted or rejected line was logged.
- Measured (our note, 2026-10-21, console API): a key cannot carry its own workload identity and also name an identity as its owner ("mutually exclusive"), and the owner and the user reference must not name different principals.
- Measured (our note): an identity with no key behind it authenticates nobody; the gateway log said it was "rebuilding 0 keys".
- Measured (our note): a key that borrows a person stops working when that person's account goes inactive.
- Measured (our note): the gateway's refusals are thin. A bare 401 or 403 carries no reason; the only self-describing refusal was "key not scoped for mcp access". The lab names the exact reason so you can learn from it; the caller would see only the status.
- Measured (our note): audiences the console generated for sensor identities look like priv-nhi-<random>, and sensor identities carried the scopes shadowai:write and policy:read. The lab copies that shape; its random values are its own.
- Measured (our note): app and policy edits took about four minutes to reach the gateway; new keys were picked up at once. Revocation was not measured.

## Availability

- **Federated Identity (slide 40)** (GA (slide tag)): Modelled: five issuers, exact binding, lifetime cap, key-set handling, keys owned by an identity, backend isolation, revocation, per-deployment audit.
- **Self-Hosted Agents (slide 41)** (GA (slide tag)): Modelled: enrolment with a generated audience, verified reports, node from the token claims, revocation, enforcement policy with modes and actions.
- **The Kubernetes eBPF sensor (slides 41 and 44)** (first self-hosted agent): Not run. The lab simulates the sensor's reports; there is no eBPF and no process on any node.
- **Sidecar injection for agents you cannot modify (slide 40)** (in development): Not modelled. No behaviour is claimed.
- **SubjectBinding and UserClaim (console swagger names)** (schema only): Not modelled: the schema says they decide how an end user named in a presented token is treated; the deck does not describe them.

## The scripted scenarios (Mock mode)

1. **One credential, three services.** The Kubernetes identity for one ServiceAccount: a token the platform issued is allowed to the MCP server and to the peer agent, and refused for the LLM provider because the scope is not on the key.
2. **Exact binding: subject, issuer, audience.** Another ServiceAccount, the same name in another namespace, a token from another issuer, no audience and the wrong audience are each refused at their own step.
3. **A key bound to main cannot be used by a pull request.** GitHub Actions: main of the right repository is allowed; a pull request, a pull request from a fork, the wrong environment and a missing pinned claim are refused.
4. **Enforced lifetimes.** Expired, unexpired but minted to live two hours, no expiry, issued in the future and not valid yet are refused; a good token is allowed, and refused once the lab clock passes its expiry.
5. **Algorithms and tampering.** alg none, HS256 signed with the public key, an ES256 header, an attacker's key (under the issuer's kid and under its own), no kid, and a payload altered after signing.
6. **An unknown signing key triggers a refresh.** The issuer rotates. A token signed by the new key has a kid the gateway does not know: it refreshes the key set and the token verifies. A token signed by the retired key does not.
7. **The issuer is down: the last known good key set carries on.** With the issuer down, a token signed by a key the gateway already holds still verifies. A token signed by a key rotated in during the outage cannot be resolved. When the issuer returns it is.
8. **A private issuer with pinned keys.** The private issuer has no address to fetch from. After it rotates its key the pinned set has no such kid and nothing to refresh from, until the keys are pinned again.
9. **Revocation and per-deployment attribution.** Two pods of one ServiceAccount are attributed separately. Revoke the identity: the very next request is refused. Restore it, then remove it: the gateway can find no identity for the token.
10. **A key owned by an identity, or by a person.** A key can name an identity as its owner; the console refuses two contradictory forms. When the person who owns a stored key goes inactive that key stops, and the identity-owned key does not. An identity with no key behind it authenticates nobody.
11. **Four platforms, one gateway.** GitHub Actions to MCP, GitLab CI to the LLM provider, a SPIFFE JWT-SVID to a peer agent, and a private issuer with pinned keys: each verified the same way.
12. **The sensor reports with its own token.** Enrol a sensor and it reports with a token minted for a generated audience. The node comes from the token: a forged node in the body is ignored. A token for another audience is refused. Revoke the identity and the next report is refused; the findings stay.
13. **Enforcement: audit first, then enforce.** A policy bound to the sensor's identity: in audit mode a denied finding is recorded as would-have-blocked; in enforce mode the same report is blocked; a finding outside the named namespaces is not evaluated.

## Not demonstrated

- Anything about how the real gateway, console, controller or a real issuer behaves: nothing here ran against one. All issuers are in-process, on .example hosts, and no key set is fetched from the network.
- That a real gateway accepts a workload token on the MCP path or the LLM route (the deck claims it; our own earlier test did not prove it).
- Sidecar injection (in development), and the kubelet, the SPIRE agent and the CI runners that really mint tokens.
- The eBPF sensor. The reports are simulated, and the claim names the lab reads (node, pod, repository and so on) are the lab's flat names, not the exact shape of a real Kubernetes or GitHub token.
- How the real gateway treats clock skew, key-set rate limits on unknown-kid refreshes, JWKS caching headers, algorithm families other than RS256, or end-user binding (SubjectBinding and UserClaim).
- Per-user credentials from the vault for a workload caller (that needs a human end user), and token-pass.
- Real credentials. The lab holds none. Anything credential-shaped you type is masked and never kept (a lab-written heuristic).
