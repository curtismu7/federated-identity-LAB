// What the Help dialog says. Plain, and as hedged as the rest of the lab (rule 2): what was measured, what is simulated, what is UNVERIFIED.
export const HELP_SECTIONS = [
  {
    heading: "What this lab is",
    body: [
      "A simulation of Ping's Federated Identity and Self-Hosted Agents release claims, with real local token verification: platform-issued short-lived tokens bound exactly to one issuer, one subject and one audience, enforced lifetimes, key-set refresh and outage handling, revocation, and a Kubernetes sensor that is verified, not vouched.",
      "Source: the Ping ID4AI Workforce H2 2026 deck (slides 35, 40, 41, 44), release 2026-11-02. Federated Identity is the new display name of Non-Human Identity; the console API object is still NonHumanIdentity."
    ]
  },
  {
    heading: "Measured, simulated, UNVERIFIED",
    body: [
      "Every product claim is a Ping release claim, UNVERIFIED on our tenant. Nothing here calls a real issuer, cluster, identity provider or tenant.",
      "Mock mode (default): everything runs offline, read-only, from scripted scenario tables. Live mode (owner-run, still local): the lab's own engine acts on your tokens — five mock issuers with real RS256 keys, a lab clock, a fifteen-step gateway verification with the exact refusal reason. The engine never leaves loopback.",
      "The one call that can leave your machine is the optional Real-mode Privilege gateway check, and only when you run it with a gateway configured. Where we say the real gateway's refusals are thin, that is measured on our setup, not a product statement."
    ]
  },
  {
    heading: "How to use the page",
    body: [
      "Sections across the top: Federated Identity, Verify, Issuers and keys, Deployment models, Self-Hosted Agents, Audit, Diagram, Talk track. The top menu holds the mode picker, vertical (for example finance), theme, font size, Present, Talk track, Help and Reset.",
      "Verify is the heart: a token editor with 37 presets (eight are lookalikes — a zero-width space, a fullwidth or Cyrillic letter, another case, a percent-encoded colon, a trailing space, a trailing slash). Edit any claim, mint, tamper, verify. The token is signed exactly as typed: nothing is trimmed or normalised, hidden characters are written out, and a claim that looks like a credential is refused, not masked.",
      "In Live mode the page also shows \"Verified in this browser (WebCrypto RS256)\" next to the server verdict — it checks the signature only, over the lab's own public keys; the server's fifteen steps remain the full verdict. In Mock that check is disabled with the reason shown.",
      "Issuers and keys runs the lab clock, key rotation, takedown and refresh. Deployment models shows the five models from slide 40 as a table (sidecar injection is \"in development\" — no behaviour is claimed). Reset in the top menu clears this workspace's identities, keys, issuers, audit log, sensors, findings and clock."
    ]
  }
];
