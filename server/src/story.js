import { fillDeep, VERTICALS } from './cast.js';
import { AVAILABILITY, BANNER, CLAIMS, CLAIM_LABEL, DISCREPANCIES, FIELD_SOURCES, FIELD_SOURCE_NAMES, INTRO, MEASURED, NOT_DEMONSTRATED, PRESENTER_TALK, PRESETS, RELEASE, TALK_TRACK, TITLE, WHY } from './data.js';
import { BACKEND_AUTH_MODES, DEPLOYMENT_MODELS, FINDING_KINDS, ISSUERS, MINT_ALGS, PLATFORMS, POLICY_ACTIONS, POLICY_MODES, SCOPES } from './catalog.js';
import { LIMITS, STEPS } from './engine.js';
import { scenarioList } from './scenarios.js';

export const rawStory = () => ({ title: TITLE, intro: INTRO, banner: BANNER, claims: CLAIMS, talkTrack: TALK_TRACK, why: WHY, discrepancies: DISCREPANCIES, availability: AVAILABILITY, measured: MEASURED, presets: PRESETS, deploymentModels: DEPLOYMENT_MODELS });

// The story with the cast filled in.
export function buildStory(cast, vertical) {
  const s = fillDeep(rawStory(), cast);
  return {
    title: s.title, intro: s.intro, release: RELEASE, claimLabel: CLAIM_LABEL, banner: s.banner, claims: s.claims, why: s.why, discrepancies: s.discrepancies, availability: s.availability, measured: s.measured,
    notDemonstrated: NOT_DEMONSTRATED, fieldSources: FIELD_SOURCES.map((f) => ({ ...f, sourceLabel: FIELD_SOURCE_NAMES[f.source] })), limits: LIMITS, steps: STEPS,
    presets: s.presets, deploymentModels: s.deploymentModels, backendAuthModes: BACKEND_AUTH_MODES, platforms: PLATFORMS, scopes: SCOPES, mintAlgs: MINT_ALGS, findingKinds: FINDING_KINDS, policyModes: POLICY_MODES, policyActions: POLICY_ACTIONS,
    issuers: ISSUERS.map((i) => ({ id: i.id, name: i.name, platform: i.platform, url: i.url, jwksUri: i.jwksUri })),
    scenarios: scenarioList(cast).map((sc) => ({ id: sc.id, title: sc.title, say: sc.say })),
    talkTrack: s.talkTrack, presenterTalk: PRESENTER_TALK, cast, vertical, verticals: Object.keys(VERTICALS),
  };
}

// docs/talk-track.md is generated from the same data the UI reads (`npm run talk-track`); a test fails if they drift.
export function renderTalkTrackMarkdown(cast) {
  const s = buildStory(cast, 'finance');
  const parts = ['# Talk track', '', '<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->', '', `> ${s.claimLabel}: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 35, 40 and 41 (release ${s.release}). Nothing here ran against a real gateway, issuer, cluster or tenant.`, ''];
  for (const t of s.talkTrack) parts.push(`## ${t.title}`, '', t.say, '');
  parts.push('## What the deck, the schema and our own tests leave unresolved (shown, not resolved)', '');
  for (const d of s.discrepancies) parts.push(`- **${d.title}.** ${d.text}`);
  parts.push('', '## What we measured ourselves (our notes, never the deck\'s)', '');
  for (const m of s.measured) parts.push(`- ${m.note}`);
  parts.push('', '## Availability', '');
  for (const a of s.availability) parts.push(`- **${a.capability}** (${a.availability}): ${a.lab}`);
  parts.push('', '## The scripted scenarios (Mock mode)', '');
  s.scenarios.forEach((sc, i) => parts.push(`${i + 1}. **${sc.title}.** ${sc.say}`));
  parts.push('', '## Not demonstrated', '');
  for (const n of s.notDemonstrated) parts.push(`- ${n}`);
  return `${parts.join('\n')}\n`;
}
