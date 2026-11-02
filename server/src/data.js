// Story data. Every string may carry {{cast}} tokens; cast.js fills them from a vertical pack. Every product claim is "Ping release claim, UNVERIFIED on our tenant":
// the 2026-11-02 release is not on our tenant. Shapes marked lab-invented are ours. Lines marked "measured (our note)" come from our own earlier tests on the
// pre-release gateway, never from the deck.
export const TITLE = 'Federated Identity LAB';
export const RELEASE = '2026-11-02';
export const CLAIM_LABEL = 'Ping release claim, UNVERIFIED on our tenant';
export const INTRO = 'Agents hold stored API keys that outlive the workload and stay valid if they leak. The claim (Federated Identity, slide 40, and Self-Hosted Agents, slide 41 of the Ping ID4AI Workforce H2 2026 deck): the workload authenticates with the short-lived token its own platform issues, bound exactly to one issuer, one subject and one audience, with an enforced lifetime, and nothing long-lived is stored in the workload. Federated Identity is the new display name of Non-Human Identity (slide 35); the console API object is still NonHumanIdentity at /v1/nonhumanidentities (swagger 2026-10-31).';

export const BANNER = {
  mock: `SIMULATED, MOCK mode: tables generated from the lab's own engine and read-only. Every product claim is a ${CLAIM_LABEL} (release ${RELEASE}). No tenant, gateway, issuer or cluster is touched. The issuers, keys and sensor are the lab's own.`,
  live: `SIMULATED, LIVE mode: the lab's own local engine does real RS256 signing and verification on your tokens, loopback only, zero outbound network. Every product claim is a ${CLAIM_LABEL} (release ${RELEASE}). No tenant, gateway, issuer or cluster is touched.`,
};

export const CLAIMS = [
  { id: 'platforms', slide: 40, claim: 'Platforms: Kubernetes service-account tokens, plus GitHub Actions and GitLab CI job tokens, SPIFFE JWT-SVIDs, and any platform that issues OIDC tokens with published keys.' },
  { id: 'one-credential', slide: 40, claim: 'One credential, three service families: the same identity reaches MCP servers, peer agents (A2A) and LLM providers, distinguished only by the scopes on the key, verified identically across the MCP and LLM gateways.' },
  { id: 'exact-binding', slide: 40, claim: 'Exact identity binding: issuer and subject are matched exactly (one ServiceAccount in one namespace, or one repository on one branch) and the audience is mandatory, so a key bound to main cannot be used by a pull request from a fork. Additional claims (repository, workflow, environment) can be pinned.' },
  { id: 'lifetimes', slide: 40, claim: 'Enforced lifetimes: expiry is required and the lifetime is capped (default one hour), so a workload that signs its own tokens cannot choose its own validity window. Only asymmetric signature algorithms are accepted.' },
  { id: 'models', slide: 40, claim: 'Five deployment models: direct token read (a Kubernetes projected volume); per-job CI/CD tokens; SPIFFE/SPIRE for mixed estates; a stored agent key as the fallback where no verifiable token exists; and sidecar injection for agents you cannot modify, which is in development.' },
  { id: 'resilient', slide: 40, claim: 'Resilient key handling: the issuer\'s key set is validated when the key is created, refreshed every fifteen minutes and on sight of an unknown signing key, and the last known good set is kept through issuer outages. Private issuers are supported with pinned key material.' },
  { id: 'key-owned', slide: 40, claim: 'A key owned by an identity: an agent access key can name a Federated Identity as the principal it acts as, instead of borrowing a human owner. A fully autonomous agent gets a real principal in audit and policy, and that identity supplies the verification material for the key.' },
  { id: 'isolation', slide: 40, claim: 'Backend isolation: the token stops at the gateway and is never forwarded. Backends receive the application\'s own configured credential (static, per-user from the vault, or OAuth). Revoking the identity cuts the workload off immediately, and every request is attributed to a specific deployment.' },
  { id: 'availability', slide: 40, claim: 'Availability: Federated Identity is accepted across the MCP and LLM gateways, covering MCP servers, peer agents (A2A) and LLM providers, with identical verification. The slide carries a GA tag.' },
  { id: 'what-sha', slide: 41, claim: 'What a self-hosted agent is: a Privilege platform component acting as its own non-human principal. It holds an identity the platform issued for it, authenticates every operation with a short-lived token minted for a Privilege-generated audience, and is verified, attributed, auditable and revocable like any other identity in the platform.' },
  { id: 'no-secret', slide: 41, claim: 'No standing secret. Each component authenticates with a short-lived, audience-scoped token minted for a Privilege-generated audience at enrollment and projected into the pod. Nothing long-lived is stored on the node.' },
  { id: 'verified', slide: 41, claim: 'Verified, not vouched: the controller verifies issuer, subject, audience and scope on every report. The reporting node is taken from the claims in the token, not the sender\'s word; a compromised agent cannot misattribute its findings.' },
  { id: 'revocable', slide: 41, claim: 'Instantly revocable: removing the identity cuts the sensor off immediately, and every finding remains attributable to the node that reported it.' },
  { id: 'enforcement', slide: 41, claim: 'Enforcement: a policy bound to a Federated Identity decides what that agent may do, scoped to named namespaces or to the whole cluster, with modes of off, audit and enforce, and actions of allow, monitor, warn and deny. Audit mode records every decision that would have blocked, without blocking.' },
  { id: 'k8s-sensor', slide: 41, claim: 'First self-hosted agent, the Kubernetes sensor: the eBPF sensor that discovers AI agents, MCP servers and self-hosted model servers inside Kubernetes pods is enrolled as a self-hosted agent rather than shipping with a static credential. (Slide 44 adds that it attributes each finding to the owning pod.) The lab runs no eBPF and no real sensor: it simulates the reports.' },
];

// What the deck itself, our own measurements and the schema leave unresolved. Shown, not resolved.
export const DISCREPANCIES = [
  { id: 'naming', title: 'Slide 35 retires Non-Human Identity; slide 57 still uses it', text: 'Slide 35 says Federated Identity is the updated term and Non-Human Identity is retired. Slide 57 of the deck still lists "Non-Human Identity". The lab follows slide 35. The console API did not rename: the object is still NonHumanIdentity at /v1/nonhumanidentities (console swagger, 2026-10-31), and so are RefKind values and log lines. Self-Hosted Agents is the new name of "NHI Agents Discovery & Enforcement".' },
  { id: 'mcp-acceptance', title: 'Accepted across the MCP and LLM gateways: the deck says so, our test did not prove it', text: 'Slide 40 says Federated Identity is accepted across the MCP and LLM gateways with identical verification. Measured (our note, 2026-10-21, pre-release gateway): with a token whose issuer, subject, audience and lifetime all matched, the MCP path answered 401 "Bearer token required" and the LLM route 401 "invalid virtual key", and the gateway logged no "workload token accepted" or "rejected" line for either, so the check was never reached. We could not tell whether that image evaluates workload tokens on those routes. Not re-tested on the release. The lab implements the deck\'s claim and proves nothing about the product.' },
  { id: 'token-pass', title: 'The token is never forwarded, but the schema lists token-pass', text: 'Slide 40 says the token stops at the gateway and is never forwarded. The console swagger (2026-10-31, schema only) lists an application AuthMode token-pass, whose description says it forwards the verified inbound workload assertion unchanged. The deck\'s list of backend credentials (static, per-user from the vault, OAuth) does not include it. Measured (our note): a key caller cannot satisfy token-pass. The lab models only the three deck modes and never forwards the token; whether token-pass is a deliberate opt-in is not stated.' },
  { id: 'modes-actions', title: 'Modes and actions: the deck and the schema name different sets', text: 'The deck names modes off, audit and enforce and actions allow, monitor, warn and deny. The console swagger policy object (imodelShadowAIPolicySpec, schema only) has a Disabled flag and an Action enum of seven names (Monitor, Allow, Warn, RequireApproval, Deny, Enforce, Exempt). The lab follows the deck and does not claim to know how the two map.' },
  { id: 'scopes', title: 'Scopes on the key, or on the identity?', text: 'The deck says the scopes are on the key. The swagger also gives the identity a Scopes list ("what this identity may do"). The lab keeps both and applies the intersection (lab reading): a key can only narrow what its identity may do.' },
  { id: 'revocation-speed', title: '"Immediately": ours was not measured', text: 'The deck says revoking the identity cuts the workload off immediately. Measured (our note): app and policy edits took about four minutes to reach the gateway; we did not measure revocation. The lab refuses on the very next request because that is the deck\'s claim, not because it models propagation.' },
  { id: 'ga-tag', title: 'The slides say GA; the release is not on our tenant', text: 'Slides 40 and 41 carry a GA tag. The release is dated 2026-11-02 and is not on our tenant, so nothing here has been measured against it.' },
];

export const AVAILABILITY = [
  { capability: 'Federated Identity (slide 40)', availability: 'GA (slide tag)', lab: 'Modelled: five issuers, exact binding, lifetime cap, key-set handling, keys owned by an identity, backend isolation, revocation, per-deployment audit.' },
  { capability: 'Self-Hosted Agents (slide 41)', availability: 'GA (slide tag)', lab: 'Modelled: enrolment with a generated audience, verified reports, node from the token claims, revocation, enforcement policy with modes and actions.' },
  { capability: 'The Kubernetes eBPF sensor (slides 41 and 44)', availability: 'first self-hosted agent', lab: 'Not run. The lab simulates the sensor\'s reports; there is no eBPF and no process on any node.' },
  { capability: 'Sidecar injection for agents you cannot modify (slide 40)', availability: 'in development', lab: 'Not modelled. No behaviour is claimed.' },
  { capability: 'SubjectBinding and UserClaim (console swagger names)', availability: 'schema only', lab: 'Not modelled: the schema says they decide how an end user named in a presented token is treated; the deck does not describe them.' },
];

// Our own measurements, labelled as such. Read-only notes from the privilege-nhi-setup skill; not presented as the deck's.
export const MEASURED = [
  { id: 'mcp-llm-not-proven', note: 'Measured (our note, 2026-10-21, pre-release gateway): workload-token acceptance on the MCP path and on the LLM route was NOT proven; both answered 401 and no accepted or rejected line was logged.' },
  { id: 'exclusive', note: 'Measured (our note, 2026-10-21, console API): a key cannot carry its own workload identity and also name an identity as its owner ("mutually exclusive"), and the owner and the user reference must not name different principals.' },
  { id: 'no-key-behind', note: 'Measured (our note): an identity with no key behind it authenticates nobody; the gateway log said it was "rebuilding 0 keys".' },
  { id: 'custodian-inactive', note: 'Measured (our note): a key that borrows a person stops working when that person\'s account goes inactive.' },
  { id: 'thin-refusals', note: 'Measured (our note): the gateway\'s refusals are thin. A bare 401 or 403 carries no reason; the only self-describing refusal was "key not scoped for mcp access". The lab names the exact reason so you can learn from it; the caller would see only the status.' },
  { id: 'audience-format', note: 'Measured (our note): audiences the console generated for sensor identities look like priv-nhi-<random>, and sensor identities carried the scopes shadowai:write and policy:read. The lab copies that shape; its random values are its own.' },
  { id: 'edit-lag', note: 'Measured (our note): app and policy edits took about four minutes to reach the gateway; new keys were picked up at once. Revocation was not measured.' },
];

export const NOT_DEMONSTRATED = [
  'Anything about how the real gateway, console, controller or a real issuer behaves: nothing here ran against one. All issuers are in-process, on .example hosts, and no key set is fetched from the network.',
  'That a real gateway accepts a workload token on the MCP path or the LLM route (the deck claims it; our own earlier test did not prove it).',
  'Sidecar injection (in development), and the kubelet, the SPIRE agent and the CI runners that really mint tokens.',
  'The eBPF sensor. The reports are simulated, and the claim names the lab reads (node, pod, repository and so on) are the lab\'s flat names, not the exact shape of a real Kubernetes or GitHub token.',
  'How the real gateway treats clock skew, key-set rate limits on unknown-kid refreshes, JWKS caching headers, algorithm families other than RS256, or end-user binding (SubjectBinding and UserClaim).',
  'Per-user credentials from the vault for a workload caller (that needs a human end user), and token-pass.',
  'Real credentials. The lab holds none. Anything credential-shaped you type is masked and never kept (a lab-written heuristic).',
];

export const FIELD_SOURCE_NAMES = { deck: 'deck claim', swagger: 'console swagger name (schema only)', reading: 'lab reading', invented: 'lab-invented', measured: 'measured (our note)' };
export const FIELD_SOURCES = [
  { field: 'Federated Identity is the display name; the API object is NonHumanIdentity', source: 'deck', note: 'Slide 35 retires Non-Human Identity. /v1/nonhumanidentities and imodelNonHumanIdentity are console swagger names (2026-10-31, schema only); the API did not rename.' },
  { field: 'imodelNonHumanIdentitySpec { Description, Enabled, Federation, Scopes, SubjectBinding, UserClaim, NotAfter }', source: 'swagger', note: 'Names from the console swagger. Enabled is described as the only kill switch; NotAfter as an RFC 3339 expiry, empty meaning none. The lab models Description, Enabled, Federation, Scopes and NotAfter; SubjectBinding and UserClaim are not modelled.' },
  { field: 'modelAgentWorkloadIdentity { Issuer, Subject, Audience, JwksURI, JWKS, MaxTokenLifetimeSec, RequiredClaims, Platform, AllowAnySubject }', source: 'swagger', note: 'Names from the console swagger. Its descriptions say: issuer and subject matched exactly, audience mandatory, JWKS is a pinned public set used when the address is unset or unreachable, MaxTokenLifetimeSec rejects tokens whose exp minus iat exceeds it (0 means the gateway default, 3600), Platform is a UI hint never used for verification. A description is a source comment, not a measured behaviour.' },
  { field: 'Issuer and subject matched exactly; the audience is mandatory', source: 'deck', note: 'Slide 40. Exact means exact string equality in the lab: no case folding, no trailing-slash tolerance, no wildcard.' },
  { field: 'Pinned extra claims (repository, workflow, environment)', source: 'deck', note: 'Slide 40. The claim names the lab uses (repository, environment, ref, run_id, project_path, pod, node) are the lab\'s flat names (lab-invented).' },
  { field: 'AllowAnySubject', source: 'swagger', note: 'A console swagger name. The lab lets an identity opt in (lab reading); the deck describes exact binding only.' },
  { field: 'Expiry required; lifetime capped at one hour by default', source: 'deck', note: 'Slide 40. "Lifetime" is exp minus iat (the swagger description of MaxTokenLifetimeSec: lab reading), so a token that is still unexpired is refused if it was minted to live longer than the cap.' },
  { field: 'iat required and not in the future; exp after iat', source: 'reading', note: 'Needed so the lifetime check cannot be dodged by a future iat. The deck does not say; the lab\'s rule. The lab applies no clock-skew leeway.' },
  { field: 'Only asymmetric algorithms accepted; none and HS* refused', source: 'deck', note: 'Slide 40. The lab verifies RS256 only: another asymmetric algorithm (ES256 and so on) is refused as "unsupported by the lab", which is a lab limit, not a product claim.' },
  { field: 'Key set validated at creation, refreshed every fifteen minutes and on an unknown kid, last known good kept through outages', source: 'deck', note: 'Slide 40. Time is the lab clock (fifteen LAB minutes). A kid is required (lab reading). The lab refreshes on an unknown kid, but only once per identity per lab minute (a lab-invented cooldown: the deck does not say whether that refresh is limited).' },
  { field: 'Pinned key material for private issuers', source: 'deck', note: 'Slide 40; the swagger JWKS field. Public keys only: the lab refuses a key set that carries private material (the swagger says public material only).' },
  { field: 'A key owned by an identity: CustodianRef names a NonHumanIdentity', source: 'swagger', note: 'imodelAgentAccessKeySpec.CustodianRef (console swagger description: names a NonHumanIdentity as the principal this key acts as) and .WorkloadIdentity (a key authenticates by that OR a stored key). The two refusals shown are measured (our note, 2026-10-21).' },
  { field: 'Key scopes are a subset of the identity\'s; effective scopes are the intersection', source: 'reading', note: 'See the scopes note under what the deck leaves unresolved.' },
  { field: 'Backends receive the application\'s own credential; the token is not forwarded', source: 'deck', note: 'Slide 40. The credential shown is a masked placeholder: the lab holds no secret. The three backends, their URLs and their auth modes are lab-invented.' },
  { field: 'Revoking the identity cuts the workload off at once; every request attributed to a deployment', source: 'deck', note: 'Slide 40. How a deployment is named (namespace and service account, or repository and ref, plus pod or run) is the lab\'s reading.' },
  { field: 'Gateway refusal reasons and the step list', source: 'invented', note: 'The fifteen steps, their order and the reason codes are the lab\'s. The real gateway\'s order is not known.' },
  { field: 'Self-hosted agent: its own principal, audience generated at enrolment, no standing secret', source: 'deck', note: 'Slide 41. The audience format is measured (our note); the value is the lab\'s random.' },
  { field: 'Node taken from the token claim, the body\'s node ignored', source: 'deck', note: 'Slide 41. The claim is named node here (lab-invented flat name). A body node that differs is recorded as ignored.' },
  { field: 'Findings: AI agents, MCP servers and self-hosted model servers, attributed to the owning pod', source: 'deck', note: 'Slides 41 and 44. The finding fields (kind, name, namespace, pod) are lab-invented.' },
  { field: 'Policy: modes off, audit, enforce; actions allow, monitor, warn, deny; named namespaces or the whole cluster', source: 'deck', note: 'Slide 41. imodelShadowAIPolicySpec (WorkloadIdentities, Namespaces, AllNamespaces, Action, Disabled) are swagger names; the policy shape the lab uses is lab-invented.' },
  { field: 'Audit mode records decisions that would have blocked; enforce terminates (simulated)', source: 'deck', note: 'Slides 41 and 44. Nothing is terminated: the effect is a recorded outcome.' },
  { field: 'Scopes shadowai:write and policy:read on sensor identities', source: 'measured', note: 'Seen on identities on our tenant. The lab requires shadowai:write to report.' },
  { field: 'The in-browser WebCrypto signature check (Verify tab)', source: 'invented', note: 'Lab-invented UI, not a deck claim. RSASSA-PKCS1-v1_5 with SHA-256 over header.payload, against the public key set the lab\'s own server publishes for the issuer. It checks the signature only; the fifteen steps stay the server\'s. It needs a secure context (localhost counts).' },
  { field: 'The lab clock, ids, the five mock issuers, the keys and the audit format', source: 'invented', note: 'The clock starts at a fixed time, only moves forward by a capped move, and is never the real time. Keys are RSA, in memory, shared by this process, never shown.' },
];

// Slide 40 and 41 value panels, as the deck words them (paraphrased in the prompt file); Ping claims.
export const WHY_TEXT = {
  'federated-identity': {
    challenge: 'Agents hold stored API keys that outlive workloads and stay valid from anywhere if they leak. Standing-secret findings block agent rollout, and unattended operation is held back by key risk.',
    technical: 'Secretless, exactly bound, short-lived tokens verified per request against the issuer, instantly revocable.',
    business: 'Standing-secret audit findings close, and unattended agents can be approved at all: lower breach risk, faster adoption.',
  },
  'self-hosted-agents': {
    challenge: 'Platform components are implicitly trusted infrastructure: trusted by network position, not verified per request, and outside policy. That trust model fails modern platform reviews and blocks the platform\'s own adoption.',
    technical: 'Every component authenticates per request with a platform-issued token, is policy-bound, and is cut off the moment its identity is removed.',
    business: 'Materially reduces insider and compromise risk on privileged components and simplifies compliance evidence.',
  },
};
export const whyLine = (k) => `Challenge: ${WHY_TEXT[k].challenge} Technical: ${WHY_TEXT[k].technical} Business: ${WHY_TEXT[k].business} (Ping claims, unverified on our tenant.)`;
export const WHY = [
  { id: 'why-federated-identity', title: 'Why it matters: Federated Identity (slide 40)', say: whyLine('federated-identity') },
  { id: 'why-self-hosted-agents', title: 'Why it matters: Self-Hosted Agents (slide 41)', say: whyLine('self-hosted-agents') },
];

export const TALK_TRACK = [
  { id: 'why-federated-identity', title: 'Why it matters: Federated Identity (slide 40)', say: whyLine('federated-identity') },
  { id: 'one-credential', title: 'One platform-issued credential, three services', say: 'Start on Verify. Pick the Kubernetes identity for {{castAgent}} and mint the right token: it is allowed. Call MCP, then the peer agent, then the LLM provider. The same identity reaches the first two and the LLM call is refused with "key not scoped for llm access": the services are distinguished only by the scopes on the key. Nothing long-lived is stored in the workload: the platform issues the token and rotates it. {{castBrand}} loses a standing secret.' },
  { id: 'exact-binding', title: 'Exact binding, and why a fork cannot use main', say: 'The identity names one issuer, one subject and one audience, and each is an exact match. Try the wrong subject, the wrong issuer, no audience: each is refused at its own step with the exact reason. Then the GitHub Actions identity bound to {{castOrg}}/{{castRepo}} on main: a token from main is allowed, a pull request token (even from {{castAttackerOrg}}\'s fork) is refused because the subject is different, and a right-branch token from the wrong environment is refused by the pinned claim. Then the lookalike presets: a zero-width space in the subject, a fullwidth or Cyrillic letter, another case, a percent-encoded colon, a trailing space, a trailing slash on the audience or the issuer. The editor signs exactly what is typed (it never trims, decodes or normalises a claim, and says so in a notice), so each lookalike is a different string and is refused at its own step.' },
  { id: 'lifetimes', title: 'Enforced lifetimes and algorithms', say: 'A workload that signs its own tokens could choose its own validity window, so expiry is required and the lifetime is capped at one hour. Mint a token whose exp is still in the future but was issued to live two hours: refused. Try alg none and HS256: refused before any key is looked at. The lab verifies RS256 only, which is a lab limit.' },
  { id: 'keys', title: 'Resilient key handling', say: 'On Issuers and keys, rotate the Kubernetes issuer. The gateway still holds the old key set, so a token signed by the new key has an unknown kid: the gateway refreshes on sight of it and the token verifies. Take the issuer down and rotate again: the unknown kid cannot be resolved and the token is refused, yet tokens signed by the key the gateway already holds keep working: the last known good set is kept through the outage. Move the lab clock fifteen minutes and watch the scheduled refresh. The private issuer has no address: its keys are pinned.' },
  { id: 'key-owner', title: 'A key owned by an identity', say: 'On the Federated Identity tab a key can name an identity as its owner instead of borrowing {{castOwner}}. Make {{castOwner}} inactive: the stored key that borrowed them stops working, while the keys owned by identities carry on, and the audit names the identity as the principal. The console refuses a key that has its own workload identity and an identity owner, or that names a person too (measured, our note).' },
  { id: 'browser-check', title: 'Check the signature in your own browser', say: 'After the server\'s fifteen steps, the page re-checks only the signature in your browser with WebCrypto (RS256), against the issuer\'s public key set fetched from this lab\'s own server: nothing else is contacted and no private key ever reaches the page. Tamper a token and both fail. Rotate the issuer and keep an old token. The gateway still verifies from the key set it holds, the browser finds no key in the set the issuer publishes now, and the page flags the disagreement. Take the issuer down: the gateway carries on from its last known good set, the browser has no such cache. The browser result is the signature only, never the full verdict: claims, audience, lifetime and scope are the server\'s steps. Live only: the Mock tables hold no keys.' },
  { id: 'backend', title: 'Backend isolation, revocation and attribution', say: 'Open the last allowed call: the outbound request to the backend carries the application\'s own credential, masked, and the workload token is not in it. Revoke the identity and send the very next request: refused. The Audit tab names every request\'s deployment (namespace and service account and pod, or repository and ref and run), and every refusal.' },
  { id: 'models', title: 'Five deployment models', say: 'Direct token read, per-job CI/CD tokens and SPIFFE/SPIRE are all modelled. A stored agent key is the fallback where no verifiable token exists, and it stays a standing secret owned by a person. Sidecar injection is in development on the slide: the lab claims no behaviour for it.' },
  { id: 'why-self-hosted-agents', title: 'Why it matters: Self-Hosted Agents (slide 41)', say: whyLine('self-hosted-agents') },
  { id: 'sensor', title: 'The sensor reports with its own token', say: 'Enrol a sensor: Privilege generates an audience nobody can guess and the pod receives a short-lived token for it. The sensor reports findings (AI agents, MCP servers and model servers in pods). The controller verifies issuer, subject, audience and scope on every report and takes the node from the token, so a forged node field in the body is ignored and recorded as ignored. A token minted for another audience is refused. Revoke the identity and the next report is refused while every earlier finding stays attributed to its node. The lab runs no eBPF: the reports are simulated.' },
  { id: 'enforcement', title: 'Enforcement: audit first, then enforce', say: 'A policy bound to the sensor\'s identity names the namespaces in scope (or the whole cluster), a mode (off, audit, enforce) and an action per kind (allow, monitor, warn, deny). In audit mode a denied finding is recorded as would-have-blocked and nothing is blocked; switch to enforce and the same report is blocked. A finding in a namespace outside the scope is not evaluated.' },
  { id: 'honesty', title: 'What we measured, and what we did not', say: 'Everything here is a Ping release claim, unverified on our tenant. Two things to say out loud. First, the deck says Federated Identity is accepted across the MCP and LLM gateways; our own earlier test of the MCP path did not prove it (measured, our note). Second, the deck calls the object Federated Identity on slide 35 but slide 57 still says Non-Human Identity, and the console API still says NonHumanIdentity: confirm before correcting a customer.' },
];

export const PRESENTER_TALK = {
  identities: ['why-federated-identity', 'one-credential', 'key-owner'],
  verify: ['exact-binding', 'lifetimes', 'browser-check', 'backend'],
  issuers: ['keys'],
  models: ['models'],
  sensors: ['why-self-hosted-agents', 'sensor', 'enforcement'],
  audit: ['backend'],
  diagram: ['one-credential'],
};

// The token editor presets (and the scripted scenarios reuse them). mint = the arguments of the mint operation; times are seconds from the lab clock.
// Identities are the seeded ones in order: fid-001 Kubernetes, fid-002 GitHub Actions, fid-003 GitLab CI, fid-004 SPIFFE, fid-005 private issuer.
const GW = 'https://gateway.{{castHost}}.example';
const ZW = String.fromCharCode(0x200b); const FULLWIDTH_S = String.fromCharCode(0xff53); const CYRILLIC_A = String.fromCharCode(0x0430);
const K8S_SUB = 'system:serviceaccount:{{castNs}}:{{castAgent}}';
const GH_SUB = 'repo:{{castOrg}}/{{castRepo}}:ref:refs/heads/main';
const GH_EXTRA = { repository: '{{castOrg}}/{{castRepo}}', environment: 'production', ref: 'refs/heads/main', run_id: '4821' };
const k8s = (over = {}) => ({ issuer: 'kube', claims: { sub: K8S_SUB, aud: GW, extra: { pod: '{{castAgent}}-7d9f' } }, ...over });
const gh = (over = {}) => ({ issuer: 'github', claims: { sub: GH_SUB, aud: GW, extra: GH_EXTRA }, ...over });
export const PRESETS = [
  { id: 'k8s-right', title: 'Kubernetes: the right ServiceAccount', identityId: 'fid-001', service: 'mcp', expect: 'ok', mint: k8s() },
  { id: 'k8s-a2a', title: 'Kubernetes: the same token to a peer agent (A2A)', identityId: 'fid-001', service: 'a2a', expect: 'ok', mint: k8s() },
  { id: 'k8s-llm', title: 'Kubernetes: the same token to an LLM provider (scope not on the key)', identityId: 'fid-001', service: 'llm', expect: 'scope_not_on_key', mint: k8s() },
  { id: 'k8s-wrong-subject', title: 'Kubernetes: another ServiceAccount in the same namespace', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: 'system:serviceaccount:{{castNs}}:{{castOtherAgent}}', aud: GW } }) },
  { id: 'k8s-wrong-namespace', title: 'Kubernetes: the same ServiceAccount name in another namespace', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: 'system:serviceaccount:{{castNs3}}:{{castAgent}}', aud: GW } }) },
  { id: 'k8s-wrong-issuer', title: 'Kubernetes: a token from a different issuer', identityId: 'fid-001', service: 'mcp', expect: 'issuer_mismatch', mint: { issuer: 'github', claims: { sub: K8S_SUB, aud: GW } } },
  { id: 'k8s-no-aud', title: 'Kubernetes: no audience', identityId: 'fid-001', service: 'mcp', expect: 'aud_missing', mint: k8s({ claims: { sub: K8S_SUB, aud: null } }) },
  { id: 'k8s-wrong-aud', title: 'Kubernetes: the audience of another service', identityId: 'fid-001', service: 'mcp', expect: 'aud_mismatch', mint: k8s({ claims: { sub: K8S_SUB, aud: 'https://other.{{castHost}}.example' } }) },
  { id: 'k8s-expired', title: 'Kubernetes: expired', identityId: 'fid-001', service: 'mcp', expect: 'expired', mint: k8s({ times: { iat: -3700, exp: -100 } }) },
  { id: 'k8s-long-lived', title: 'Kubernetes: unexpired, but minted to live two hours', identityId: 'fid-001', service: 'mcp', expect: 'lifetime_exceeds_cap', mint: k8s({ times: { iat: 0, exp: 7200 } }) },
  { id: 'k8s-no-exp', title: 'Kubernetes: no expiry', identityId: 'fid-001', service: 'mcp', expect: 'exp_missing', mint: k8s({ times: { exp: null } }) },
  { id: 'k8s-future-iat', title: 'Kubernetes: issued in the future (hides a long lifetime)', identityId: 'fid-001', service: 'mcp', expect: 'iat_in_future', mint: k8s({ times: { iat: 86400, exp: 86460 } }) },
  { id: 'k8s-nbf', title: 'Kubernetes: not valid yet', identityId: 'fid-001', service: 'mcp', expect: 'not_yet_valid', mint: k8s({ times: { nbf: 600 } }) },
  { id: 'alg-none', title: 'Algorithm none (unsigned)', identityId: 'fid-001', service: 'mcp', expect: 'alg_none', mint: k8s({ alg: 'none' }) },
  { id: 'alg-hs256', title: 'HS256 signed with the issuer\'s public key (algorithm confusion)', identityId: 'fid-001', service: 'mcp', expect: 'alg_symmetric', mint: k8s({ alg: 'HS256' }) },
  { id: 'alg-es256', title: 'ES256 header (asymmetric, but the lab verifies RS256 only)', identityId: 'fid-001', service: 'mcp', expect: 'alg_unsupported_by_lab', mint: k8s({ alg: 'ES256' }) },
  { id: 'attacker-forged-kid', title: 'Signed by an attacker\'s key, claiming the issuer\'s kid', identityId: 'fid-001', service: 'mcp', expect: 'bad_signature', mint: { issuer: 'attacker', kid: 'kube-key-1', claims: { iss: 'https://kube-api.cluster-a.example', sub: K8S_SUB, aud: GW } } },
  { id: 'attacker-own-kid', title: 'Signed by an attacker\'s key under its own kid', identityId: 'fid-001', service: 'mcp', expect: 'unknown_kid', mint: { issuer: 'attacker', claims: { iss: 'https://kube-api.cluster-a.example', sub: K8S_SUB, aud: GW } } },
  { id: 'no-kid', title: 'No kid in the header', identityId: 'fid-001', service: 'mcp', expect: 'kid_missing', mint: k8s({ kid: null }) },
  // Lookalikes: the gateway compares claims EXACTLY, and the lab signs exactly what is typed (a hidden or lookalike character is not normalised away), so each of these is refused.
  { id: 'lk-zero-width-sub', title: 'Lookalike: a zero-width space inside the subject', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: `system:serviceaccount:{{castNs}}:${ZW}{{castAgent}}`, aud: GW } }) },
  { id: 'lk-fullwidth-sub', title: 'Lookalike: a fullwidth s at the start of the subject', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: `${FULLWIDTH_S}ystem:serviceaccount:{{castNs}}:{{castAgent}}`, aud: GW } }) },
  { id: 'lk-cyrillic-sub', title: 'Lookalike: a Cyrillic a in the namespace', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: `system:serviceaccount:${CYRILLIC_A}{{castNs}}:{{castAgent}}`, aud: GW } }) },
  { id: 'lk-case-sub', title: 'Lookalike: the subject in another case', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: 'System:ServiceAccount:{{castNs}}:{{castAgent}}', aud: GW } }) },
  { id: 'lk-percent-sub', title: 'Lookalike: a percent-encoded colon in the subject (not decoded)', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: 'system:serviceaccount:{{castNs}}%3A{{castAgent}}', aud: GW } }) },
  { id: 'lk-trailing-space-sub', title: 'Lookalike: a trailing space after the subject', identityId: 'fid-001', service: 'mcp', expect: 'subject_mismatch', mint: k8s({ claims: { sub: `${K8S_SUB} `, aud: GW } }) },
  { id: 'lk-trailing-slash-aud', title: 'Lookalike: a trailing slash on the audience', identityId: 'fid-001', service: 'mcp', expect: 'aud_mismatch', mint: k8s({ claims: { sub: K8S_SUB, aud: `${GW}/` } }) },
  { id: 'lk-trailing-slash-iss', title: 'Lookalike: a trailing slash on the issuer', identityId: 'fid-001', service: 'mcp', expect: 'issuer_mismatch', mint: k8s({ claims: { iss: 'https://kube-api.cluster-a.example/', sub: K8S_SUB, aud: GW } }) },
  { id: 'gh-right', title: 'GitHub Actions: the main branch of the right repository', identityId: 'fid-002', service: 'mcp', expect: 'ok', mint: gh() },
  { id: 'gh-pr', title: 'GitHub Actions: a pull request in the same repository', identityId: 'fid-002', service: 'mcp', expect: 'subject_mismatch', mint: gh({ claims: { sub: 'repo:{{castOrg}}/{{castRepo}}:pull_request', aud: GW, extra: { repository: '{{castOrg}}/{{castRepo}}', environment: 'production', run_id: '4822' } } }) },
  { id: 'gh-fork-pr', title: 'GitHub Actions: a pull request from a fork', identityId: 'fid-002', service: 'mcp', expect: 'subject_mismatch', mint: gh({ claims: { sub: 'repo:{{castAttackerOrg}}/{{castRepo}}:pull_request', aud: GW, extra: { repository: '{{castAttackerOrg}}/{{castRepo}}', run_id: '4823' } } }) },
  { id: 'gh-staging', title: 'GitHub Actions: main, but the staging environment', identityId: 'fid-002', service: 'mcp', expect: 'required_claim_mismatch', mint: gh({ claims: { sub: GH_SUB, aud: GW, extra: { ...GH_EXTRA, environment: 'staging' } } }) },
  { id: 'gh-no-env', title: 'GitHub Actions: main, with no environment claim', identityId: 'fid-002', service: 'mcp', expect: 'required_claim_missing', mint: gh({ claims: { sub: GH_SUB, aud: GW, extra: { repository: '{{castOrg}}/{{castRepo}}', ref: 'refs/heads/main' } } }) },
  { id: 'gitlab-right', title: 'GitLab CI: the main branch of the right project', identityId: 'fid-003', service: 'llm', expect: 'ok', mint: { issuer: 'gitlab', claims: { sub: 'project_path:{{castOrg}}/{{castRepo}}:ref_type:branch:ref:main', aud: GW, extra: { project_path: '{{castOrg}}/{{castRepo}}', ref: 'main', pipeline_id: '311' } } } },
  { id: 'spiffe-right', title: 'SPIFFE: the right SPIFFE ID (a JWT-SVID)', identityId: 'fid-004', service: 'a2a', expect: 'ok', mint: { issuer: 'spire', claims: { sub: 'spiffe://trust.example/ns/{{castNs}}/sa/{{castAgent}}', aud: GW } } },
  { id: 'private-right', title: 'Private issuer: a token checked against pinned keys', identityId: 'fid-005', service: 'mcp', expect: 'ok', mint: { issuer: 'private', claims: { sub: 'agent:{{castAgent}}', aud: GW } } },
];
