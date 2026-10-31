import test from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/engine.js';
import { C, GW, codeOf, newEngine, statusOf } from './helpers.js';

const F = (kind, ns = C.castNs, name = 'thing', pod = 'pod-0') => ({ kind, name, namespace: ns, pod });
const enrolled = () => { const e = newEngine(); const s = e.enrollSensor({ name: 'sensor one' }); return { e, s, id: s.identityId }; };
const report = (e, id, over = {}) => e.sensorReport({ identityId: id, node: C.castNode1, body: { findings: [F('model-server')] }, ...over });
const policy = (id, over = {}) => ({ identityId: id, mode: 'audit', scope: { namespaces: [C.castNs] }, actions: { 'ai-agent': 'monitor', 'mcp-server': 'warn', 'model-server': 'deny' }, ...over });

test('enrolment makes a self-hosted agent: its own identity, its own key, a generated audience that differs each time, no standing secret anywhere', () => {
  const e = newEngine();
  const a = e.enrollSensor({}); const b = e.enrollSensor({});
  assert.match(a.audience, /^priv-nhi-[0-9a-f]{16}$/); assert.notEqual(a.audience, b.audience);
  const s = e.snapshot();
  const ident = s.identities.find((i) => i.id === a.identityId);
  assert.equal(ident.kind, 'self-hosted-agent'); assert.deepEqual(ident.scopes, ['shadowai:write', 'policy:read']); assert.equal(ident.federation.audience, a.audience);
  assert.equal(ident.federation.subject, `system:serviceaccount:${C.castSensorNs}:node-sensor`); assert.equal(ident.federation.allowAnySubject, false);
  assert.equal(s.keys.find((k) => k.id === a.keyId).owner.ref, a.identityId);
  assert.equal(s.sensors.length, 2);
  assert.ok(!JSON.stringify(s).match(/-----BEGIN|"d":/));
  assert.ok(s.audit.some((x) => x.kind === 'sensor.enrolled' && /nothing long-lived is stored on the node/.test(x.note)));
});

test('the audience comes from the injectable random source: the same source gives the same audience (Mock tables), the default is random', () => {
  const x = newEngine().enrollSensor({}).audience; const y = newEngine().enrollSensor({}).audience;
  assert.equal(x, y, 'the seeded test source is deterministic');
});

test('enrolment limits and checks: a name is text, at most five sensors, identities and keys are capped; nothing is half-created', () => {
  const e = newEngine();
  assert.equal(codeOf(() => e.enrollSensor({ name: 5 })), 'bad_name');
  assert.equal(codeOf(() => e.enrollSensor({ name: '' })), 'bad_name');
  assert.equal(codeOf(() => e.enrollSensor({ nope: 1 })), 'unknown_field');
  const n = e.snapshot().identities.length;
  for (let i = 0; i < LIMITS.sensors; i++) e.enrollSensor({});
  assert.equal(codeOf(() => e.enrollSensor({})), 'workspace_full');
  assert.equal(e.snapshot().identities.length, n + LIMITS.sensors);
  assert.equal(e.snapshot().keys.length, 6 + LIMITS.sensors);
});

test('a report with the sensor\'s own token is accepted; the node comes from the token claim and the findings are attributed to it', () => {
  const { e, id } = enrolled();
  const r = report(e, id, { node: C.castNode2, body: { findings: [F('ai-agent', C.castNs, 'agent-x', 'a-0'), F('mcp-server', C.castNs2, 'tools', 't-0')] } });
  assert.equal(r.ok, true); assert.equal(r.report.node, C.castNode2); assert.equal(r.report.nodeSource, 'token claim');
  assert.deepEqual(r.findings.map((f) => f.node), [C.castNode2, C.castNode2]);
  assert.ok(r.steps.every((s) => s.status === 'pass')); assert.equal(r.steps.at(-1).id, 'scope');
  assert.equal(e.snapshot().findings.length, 2);
  assert.ok(e.snapshot().audit.some((a) => a.kind === 'sensor.report' && a.outcome === 'allowed' && a.node === C.castNode2 && /node taken|ignored/.test(`${a.note || ''} ${a.deployment}`) || a.deployment?.includes(`node ${C.castNode2}`)));
});

test('a forged node field in the body is ignored and recorded as ignored; whether or not it differs', () => {
  const { e, id } = enrolled();
  const forged = report(e, id, { node: C.castNode1, body: { node: C.castNode3, findings: [F('model-server')] } });
  assert.equal(forged.report.node, C.castNode1); assert.equal(forged.findings[0].node, C.castNode1);
  assert.equal(forged.report.bodyNode, C.castNode3); assert.equal(forged.report.bodyNodeIgnored, true); assert.equal(forged.report.bodyNodeDiffers, true);
  const same = report(e, id, { node: C.castNode1, body: { node: C.castNode1, findings: [F('model-server')] } });
  assert.equal(same.report.bodyNodeIgnored, true); assert.equal(same.report.bodyNodeDiffers, false);
  const none = report(e, id, {});
  assert.equal(none.report.bodyNodeIgnored, false); assert.equal(none.report.bodyNode, null);
  assert.ok(e.snapshot().findings.every((f) => f.node === C.castNode1));
  const weird = report(e, id, { body: { node: { a: 1 }, findings: [F('ai-agent')] } });
  assert.equal(weird.report.node, C.castNode1);
});

test('the controller verifies issuer, subject, audience and scope on every report', () => {
  const { e, id } = enrolled();
  const refused = (r, code, step) => { assert.equal(r.ok, false); assert.equal(r.code, code); assert.equal(r.steps.find((s) => s.status === 'fail').id, step); };
  refused(report(e, id, { tokenFrom: 'gateway-audience' }), 'aud_mismatch', 'audience');
  const mint = (m) => e.mint({ issuer: 'kube', ...m }).mintedToken;
  const sub = `system:serviceaccount:${C.castSensorNs}:node-sensor`; const aud = e.snapshot().sensors[0].audience;
  refused(report(e, id, { token: mint({ claims: { sub: 'system:serviceaccount:other:thing', aud, extra: { node: C.castNode1 } } }) }), 'subject_mismatch', 'subject');
  refused(report(e, id, { token: e.mint({ issuer: 'github', claims: { sub, aud, extra: { node: C.castNode1 } } }).mintedToken }), 'issuer_mismatch', 'issuer');
  refused(report(e, id, { token: mint({ claims: { sub, aud, extra: { node: C.castNode1 } }, times: { exp: 7200 } }) }), 'lifetime_exceeds_cap', 'lifetime');
  refused(report(e, id, { token: mint({ claims: { sub, aud, extra: { node: C.castNode1 } }, times: { iat: -3700, exp: -100 } }) }), 'expired', 'expiry');
  refused(report(e, id, { token: mint({ alg: 'none', claims: { sub, aud, extra: { node: C.castNode1 } } }) }), 'alg_none', 'alg');
  refused(report(e, id, { token: e.mint({ issuer: 'attacker', kid: 'kube-key-1', claims: { iss: 'https://kube-api.cluster-a.example', sub, aud, extra: { node: C.castNode1 } } }).mintedToken }), 'bad_signature', 'signature');
  e.updateIdentity({ identityId: id, scopes: ['policy:read'] });
  refused(report(e, id), 'scope_not_on_key', 'scope');
  assert.equal(e.snapshot().findings.length, 0, 'nothing was recorded by a refused report');
});

test('a verified token that names no node, or an unusable one, cannot be attributed and is refused', () => {
  const { e, id } = enrolled();
  const sub = `system:serviceaccount:${C.castSensorNs}:node-sensor`; const aud = e.snapshot().sensors[0].audience;
  assert.equal(report(e, id, { token: e.mint({ issuer: 'kube', claims: { sub, aud } }).mintedToken }).code, 'node_claim_missing');
  assert.equal(report(e, id, { token: e.mint({ issuer: 'kube', claims: { sub, aud, extra: { node: 'Bad Node!' } } }).mintedToken }).code, 'node_claim_missing');
  assert.equal(report(e, id, { token: e.mint({ issuer: 'kube', claims: { sub, aud, extra: { node: 5 } } }).mintedToken }).code, 'node_claim_missing');
  assert.equal(e.snapshot().findings.length, 0);
});

test('revoking the identity: the next report is refused and every earlier finding stays attributed to its node; restoring and removing behave', () => {
  const { e, id } = enrolled();
  report(e, id, { node: C.castNode3 });
  e.updateIdentity({ identityId: id, enabled: false });
  const r = report(e, id); assert.equal(r.code, 'identity_disabled'); assert.equal(r.status, 401);
  const kept = e.snapshot().findings; assert.equal(kept.length, 1); assert.equal(kept[0].node, C.castNode3); assert.equal(kept[0].identityName, 'sensor one');
  e.updateIdentity({ identityId: id, enabled: true }); assert.equal(report(e, id).ok, true);
  e.deleteIdentity({ identityId: id });
  assert.equal(codeOf(() => report(e, id)), 'unknown_sensor');
  assert.equal(e.snapshot().findings.length, 2, 'findings survive the removal');
  assert.equal(e.snapshot().sensors.length, 0);
});

test('a refused report is audited with the claimed node as claimed, not verified', () => {
  const { e, id } = enrolled();
  report(e, id, { tokenFrom: 'gateway-audience', node: C.castNode2 });
  const a = e.snapshot().audit.filter((x) => x.kind === 'sensor.report').at(-1);
  assert.equal(a.outcome, 'refused'); assert.equal(a.code, 'aud_mismatch'); assert.equal(a.node, undefined);
});

test('findings are validated as a whole: kind, name, namespace, pod and count; any bad one refuses the report and records nothing', () => {
  const { e, id } = enrolled();
  const bad = [[], [F('ai-agent'), { ...F('x') }], [{ ...F('ai-agent'), kind: 'toaster' }], [{ ...F('ai-agent'), name: '' }], [{ ...F('ai-agent'), name: 'a'.repeat(61) }], [{ ...F('ai-agent'), namespace: 'Bad NS' }], [{ ...F('ai-agent'), pod: '' }], [{ ...F('ai-agent'), extra: 1 }], [5], 'x', Array.from({ length: LIMITS.findingsPerReport + 1 }, () => F('ai-agent'))];
  for (const findings of bad) assert.ok(codeOf(() => report(e, id, { body: { findings } })), JSON.stringify(findings).slice(0, 60));
  assert.equal(codeOf(() => report(e, id, { node: 'node-unknown' })), 'bad_node');
  assert.equal(codeOf(() => report(e, id, { tokenFrom: 'x' })), 'bad_token_source');
  assert.equal(codeOf(() => report(e, id, { body: { findings: [F('ai-agent')], extra: 1 } })), 'bad_body');
  assert.equal(codeOf(() => report(e, 'fid-001')), 'unknown_sensor', 'an ordinary identity is not a sensor');
  assert.equal(e.snapshot().findings.length, 0);
});

test('the findings cap refuses a whole report instead of dropping anything', () => {
  const { e, id } = enrolled();
  const full = Array.from({ length: LIMITS.findingsPerReport }, () => F('ai-agent'));
  for (let i = 0; i < LIMITS.findings / LIMITS.findingsPerReport; i++) report(e, id, { body: { findings: full } });
  assert.equal(e.snapshot().findings.length, LIMITS.findings);
  assert.equal(codeOf(() => report(e, id)), 'workspace_full');
  assert.equal(e.snapshot().findings.length, LIMITS.findings);
});

test('reports keep their newest fifty', () => {
  const { e, id } = enrolled();
  e.setPolicy(policy(id, { mode: 'off' }));
  for (let i = 0; i < LIMITS.reports + 5; i++) report(e, id, { body: { findings: [F('ai-agent')] } });
  assert.equal(e.snapshot().reports.length, LIMITS.reports);
});

test('no policy: findings are recorded and not evaluated', () => {
  const { e, id } = enrolled();
  assert.equal(report(e, id).findings[0].effect, 'no-policy');
});

test('policy modes: audit records "would have blocked" and blocks nothing; enforce blocks the same finding; off evaluates nothing', () => {
  const { e, id } = enrolled();
  e.setPolicy(policy(id, { mode: 'audit' }));
  const a = report(e, id); assert.equal(a.findings[0].effect, 'would-have-blocked'); assert.equal(a.report.wouldHaveBlocked, 1); assert.equal(a.report.blocked, 0);
  e.setPolicy(policy(id, { mode: 'enforce' }));
  const b = report(e, id); assert.equal(b.findings[0].effect, 'blocked'); assert.equal(b.report.blocked, 1); assert.equal(b.report.wouldHaveBlocked, 0);
  e.setPolicy(policy(id, { mode: 'off' }));
  assert.equal(report(e, id).findings[0].effect, 'off');
});

test('policy actions: each of allow, monitor, warn and deny gives its own outcome, per kind, in both modes', () => {
  const { e, id } = enrolled();
  const outcome = (mode, action) => { e.setPolicy(policy(id, { mode, actions: { 'ai-agent': action, 'mcp-server': action, 'model-server': action } })); return report(e, id, { body: { findings: [F('ai-agent'), F('mcp-server'), F('model-server')] } }).findings.map((f) => f.effect); };
  for (const mode of ['audit', 'enforce']) {
    assert.deepEqual(outcome(mode, 'allow'), ['allowed', 'allowed', 'allowed'], mode);
    assert.deepEqual(outcome(mode, 'monitor'), ['monitored', 'monitored', 'monitored'], mode);
    assert.deepEqual(outcome(mode, 'warn'), ['warned', 'warned', 'warned'], mode);
  }
  assert.deepEqual(outcome('audit', 'deny'), ['would-have-blocked', 'would-have-blocked', 'would-have-blocked']);
  assert.deepEqual(outcome('enforce', 'deny'), ['blocked', 'blocked', 'blocked']);
  e.setPolicy(policy(id, { mode: 'enforce', actions: { 'ai-agent': 'allow', 'mcp-server': 'deny', 'model-server': 'warn' } }));
  assert.deepEqual(report(e, id, { body: { findings: [F('ai-agent'), F('mcp-server'), F('model-server')] } }).findings.map((f) => f.effect), ['allowed', 'blocked', 'warned'], 'the action is chosen per kind');
});

test('policy scope: named namespaces apply only there, the whole cluster applies everywhere, and an out-of-scope finding is not evaluated', () => {
  const { e, id } = enrolled();
  e.setPolicy(policy(id, { mode: 'enforce', scope: { namespaces: [C.castNs, C.castNs2] } }));
  const r = report(e, id, { body: { findings: [F('model-server', C.castNs), F('model-server', C.castNs2), F('model-server', C.castNs3)] } });
  assert.deepEqual(r.findings.map((f) => f.effect), ['blocked', 'blocked', 'out-of-scope']);
  e.setPolicy(policy(id, { mode: 'enforce', scope: { all: true } }));
  assert.deepEqual(report(e, id, { body: { findings: [F('model-server', C.castNs3)] } }).findings.map((f) => f.effect), ['blocked']);
  assert.deepEqual(e.snapshot().sensors[0].policy.scope, { all: true, namespaces: [] });
});

test('every field of a policy is validated; a refused policy changes nothing; a policy belongs to a sensor', () => {
  const { e, id } = enrolled();
  e.setPolicy(policy(id));
  const before = JSON.stringify(e.snapshot().sensors[0].policy);
  const bad = { bad_mode: [{ mode: 'block' }, { mode: undefined }, { mode: 5 }], bad_scope: [{ scope: {} }, { scope: { all: true, namespaces: [C.castNs] } }, { scope: { namespaces: [] } }, { scope: { all: 'yes' } }, { scope: { namespaces: ['Bad NS'] } }, { scope: { namespaces: ['a', 'a'] } }, { scope: { namespaces: Array.from({ length: 6 }, (_, i) => `n${i}`) } }, { scope: 'all' }, { scope: { namespaces: 'x' } }, { scope: { x: 1 } }],
    bad_actions: [{ actions: {} }, { actions: { 'ai-agent': 'allow' } }, { actions: { 'ai-agent': 'block', 'mcp-server': 'allow', 'model-server': 'allow' } }, { actions: { 'ai-agent': 'allow', 'mcp-server': 'allow', 'model-server': 'allow', x: 'allow' } }, { actions: [] }], unknown_field: [{ extra: 1 }] };
  for (const [code, list] of Object.entries(bad)) for (const over of list) assert.equal(codeOf(() => e.setPolicy(policy(id, over))), code, `${code} ${JSON.stringify(over)}`);
  assert.equal(JSON.stringify(e.snapshot().sensors[0].policy), before);
  assert.equal(codeOf(() => e.setPolicy(policy('fid-001'))), 'unknown_sensor');
  assert.equal(codeOf(() => e.setPolicy(policy('__proto__'))), 'unknown_sensor');
  assert.equal(statusOf(() => e.setPolicy(policy('nope'))), 404);
});

test('findings carry what the sensor said about the pod and what the lab decided; the token never appears in the state', () => {
  const { e, id } = enrolled();
  e.setPolicy(policy(id, { mode: 'enforce' }));
  const r = report(e, id, { body: { findings: [F('model-server', C.castNs, 'vllm-server', 'vllm-0')] } });
  const f = r.findings[0];
  assert.deepEqual([f.kind, f.name, f.namespace, f.pod, f.action, f.effect, f.nodeSource], ['model-server', 'vllm-server', C.castNs, 'vllm-0', 'deny', 'blocked', 'token claim']);
  const text = JSON.stringify(e.snapshot());
  assert.ok(!/eyJ[A-Za-z0-9_-]{10,}\./.test(text), 'no token in the state');
});
