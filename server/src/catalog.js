// The lab's fixed world: five mock issuers, the platforms, the scopes, the three backends and the seeded Federated Identities.
// Every host is .example and every name is synthetic. Shapes here are lab-invented unless a comment says otherwise.
export const BASE_SECONDS = Date.parse('2026-11-02T09:00:00.000Z') / 1000;
export const DEFAULT_MAX_LIFETIME = 3600; // slide 40: "lifetime is capped (default one hour)"; swagger MaxTokenLifetimeSec: 0 means the gateway default (3600)
export const REFRESH_SECONDS = 900;       // slide 40: "refreshed every fifteen minutes"

// slot = key-pool slot (slot x GENERATIONS + generation). jwksUri is null for the private issuer: its keys are pinned, never fetched.
export const ISSUERS = [
  { id: 'kube', slot: 0, name: 'Kubernetes API server (cluster-a)', platform: 'kubernetes', url: 'https://kube-api.cluster-a.example', jwksUri: 'https://kube-api.cluster-a.example/openid/v1/jwks', standsFor: 'a Kubernetes API server issuing projected service-account tokens' },
  { id: 'github', slot: 1, name: 'GitHub Actions', platform: 'github_actions', url: 'https://token.actions.gha.example', jwksUri: 'https://token.actions.gha.example/.well-known/jwks', standsFor: 'the GitHub Actions OIDC issuer (a .example stand-in; nothing is fetched)' },
  { id: 'gitlab', slot: 2, name: 'GitLab CI', platform: 'gitlab_ci', url: 'https://gitlab.ci.example', jwksUri: 'https://gitlab.ci.example/oauth/discovery/keys', standsFor: 'the GitLab CI job-token issuer (a .example stand-in)' },
  { id: 'spire', slot: 3, name: 'SPIFFE/SPIRE server', platform: 'spiffe', url: 'https://spire.trust.example', jwksUri: 'https://spire.trust.example/keys', standsFor: 'a SPIRE server issuing JWT-SVIDs' },
  { id: 'private', slot: 4, name: 'Private issuer (pinned keys)', platform: 'oidc', url: 'https://issuer.private.example', jwksUri: null, standsFor: 'an issuer on a private network whose key set is not reachable: its public keys are pinned in the identity' },
];
export const ISSUER = Object.fromEntries(ISSUERS.map((i) => [i.id, i]));
export const ATTACKER = { id: 'attacker', slot: 5, name: 'Attacker (not a registered issuer)', url: 'https://attacker.invalid' };
export const ATTACKER_SLOT = 5;

export const PLATFORMS = ['kubernetes', 'github_actions', 'gitlab_ci', 'spiffe', 'oidc']; // swagger Platform is a UI hint ("never used for verification")
export const SCOPES = ['mcp', 'a2a', 'llm', 'shadowai:write', 'policy:read'];
export const SERVICE_SCOPES = ['mcp', 'a2a', 'llm'];
export const MINT_ALGS = ['RS256', 'HS256', 'none', 'ES256'];
export const ASYMMETRIC_ALGS = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);
export const SYMMETRIC_ALGS = new Set(['HS256', 'HS384', 'HS512']);
export const FINDING_KINDS = ['ai-agent', 'mcp-server', 'model-server']; // slide 41: AI agents, MCP servers and self-hosted model servers inside pods
export const POLICY_MODES = ['off', 'audit', 'enforce'];
export const POLICY_ACTIONS = ['allow', 'monitor', 'warn', 'deny'];

// Three backends, one per service family. The credential each application is configured with is a MASKED placeholder: the lab holds no secret.
export function backends(cast) {
  return [
    { id: 'ledger-mcp', service: 'mcp', label: `${cast.castBrand} ledger MCP server`, url: `https://ledger.mcp.${cast.castHost}.example/mcp`, authMode: 'static-token', credential: '[masked: the application\'s own static credential]' },
    { id: 'reconcile-agent', service: 'a2a', label: `${cast.castBrand} reconcile agent (peer, A2A)`, url: `https://reconcile.agents.${cast.castHost}.example/a2a`, authMode: 'oauth', credential: '[masked: an OAuth token the application obtains for this backend]' },
    { id: 'llm-provider', service: 'llm', label: 'LLM provider', url: 'https://api.llm-provider.example/v1', authMode: 'static-token', credential: '[masked: the provider key the gateway holds; the agent never sees it]' },
  ];
}
export const BACKEND_AUTH_MODES = [
  { mode: 'static-token', source: 'deck', text: 'Static: an application-wide credential the application is configured with.' },
  { mode: 'user-token', source: 'deck', text: 'Per-user from the vault: the credential an end user stored for the application. Needs a human end user, so the lab does not demonstrate it for workload callers.' },
  { mode: 'oauth', source: 'deck', text: 'OAuth: the gateway obtains a token for the backend itself.' },
];

// The five deployment models of slide 40. The lab shows what it models; the sidecar row claims no behaviour.
export const DEPLOYMENT_MODELS = [
  { id: 'direct-read', name: 'Direct token read', example: 'A Kubernetes projected volume', deck: 'Direct token read (Kubernetes projected volume).', lab: 'Modelled: the Kubernetes issuer mints the token the workload presents; the Verify tab and the sensor enrolment use it.', modelled: true, preset: 'k8s-right' },
  { id: 'per-job', name: 'Per-job CI/CD tokens', example: 'GitHub Actions and GitLab CI job tokens', deck: 'Per-job CI/CD tokens.', lab: 'Modelled: two issuers, with the repository and branch bound exactly and the fork-PR refusal.', modelled: true, preset: 'gh-right' },
  { id: 'spiffe', name: 'SPIFFE/SPIRE', example: 'Mixed estates', deck: 'SPIFFE/SPIRE for mixed estates.', lab: 'Modelled: a SPIRE issuer minting JWT-SVIDs; the subject is the SPIFFE ID.', modelled: true, preset: 'spiffe-right' },
  { id: 'stored-key', name: 'A stored agent key (fallback)', example: 'Where no verifiable token exists', deck: 'A stored agent key as the fallback where no verifiable token exists.', lab: 'Shown as a contrast: a stored key is owned by a person and is a standing secret. Compare the key owned by a person with the key owned by an identity on the Federated Identity tab.', modelled: true, preset: null },
  { id: 'sidecar', name: 'Sidecar injection', example: 'Agents you cannot modify', deck: 'Sidecar injection for agents you cannot modify: "in development" on the slide.', lab: 'Not modelled. No behaviour is claimed.', modelled: false, preset: null },
];

// Seeded identities. Subjects follow each platform's published shape (lab reading); claim names are the lab's flat names.
export function seedIdentities(cast) {
  const gateway = `https://gateway.${cast.castHost}.example`;
  return [
    { key: 'k8s', name: `${cast.castAgent} (Kubernetes)`, description: 'One ServiceAccount in one namespace.', platform: 'kubernetes', scopes: ['mcp', 'a2a', 'llm'], keyScopes: ['mcp', 'a2a'],
      federation: { issuer: ISSUER.kube.url, jwksUri: ISSUER.kube.jwksUri, subject: `system:serviceaccount:${cast.castNs}:${cast.castAgent}`, audience: gateway } },
    { key: 'github', name: `${cast.castRepo} on main (GitHub Actions)`, description: 'One repository on one branch, with the repository and environment pinned.', platform: 'github_actions', scopes: ['mcp', 'llm'], keyScopes: ['mcp'],
      federation: { issuer: ISSUER.github.url, jwksUri: ISSUER.github.jwksUri, subject: `repo:${cast.castOrg}/${cast.castRepo}:ref:refs/heads/main`, audience: gateway, requiredClaims: { repository: `${cast.castOrg}/${cast.castRepo}`, environment: 'production' } } },
    { key: 'gitlab', name: `${cast.castRepo} on main (GitLab CI)`, description: 'One project on one branch.', platform: 'gitlab_ci', scopes: ['mcp', 'llm'], keyScopes: ['mcp', 'llm'],
      federation: { issuer: ISSUER.gitlab.url, jwksUri: ISSUER.gitlab.jwksUri, subject: `project_path:${cast.castOrg}/${cast.castRepo}:ref_type:branch:ref:main`, audience: gateway } },
    { key: 'spiffe', name: `${cast.castAgent} (SPIFFE)`, description: 'One SPIFFE ID.', platform: 'spiffe', scopes: ['mcp', 'a2a'], keyScopes: ['mcp', 'a2a'],
      federation: { issuer: ISSUER.spire.url, jwksUri: ISSUER.spire.jwksUri, subject: `spiffe://trust.example/ns/${cast.castNs}/sa/${cast.castAgent}`, audience: gateway } },
    { key: 'private', name: `${cast.castAgent} (private issuer)`, description: 'An issuer whose keys are pinned, not fetched.', platform: 'oidc', scopes: ['mcp'], keyScopes: ['mcp'],
      federation: { issuer: ISSUER.private.url, pinFromIssuer: 'private', subject: `agent:${cast.castAgent}`, audience: gateway } },
  ];
}

export const HUMAN_ID_KEYS = ['castOwner', 'castOwner2'];
