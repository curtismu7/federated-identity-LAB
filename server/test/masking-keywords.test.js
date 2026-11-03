// Keyword-shaped secrets that are not written "keyword: value" (S1), user:password@host without a scheme (S2), a bearer value that contains the word bearer (N5), and the
// literal thresholds of every masking rule (boundary N masked, N-1 left alone). Ordinary sentences must stay readable: that is the price of masking the loose forms.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanFree, MAX_FREE } from '../src/credentials.js';
import { credentialProblem, reveal } from '../src/clean.js';
import { maskDeep, maskResponseText, maskStatic } from '../src/mask.js';
import { buildStory } from '../src/story.js';
import { buildDiagram, DIAGRAM_NAMES } from '../src/diagramData.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { VERTICALS } from '../src/cast.js';
import { PRESETS } from '../src/data.js';
import { fillDeep } from '../src/cast.js';
import { findCredentials, newEngine } from './helpers.js';

const CLEANERS = [['cleanFree', (x) => cleanFree(x, 2000)], ['reveal', (x) => reveal(x, 2000)], ['maskResponseText', (x) => maskResponseText(x)]];
const ids = (text) => findCredentials(text).map((s) => s.id);
const masked = (text, id) => findCredentials(text).some((s) => s.id === id);
const V = 'CANARYhunter2xyz';

test('keyword plus value in the looser spellings is masked by every cleaner (S1)', () => {
  const forms = [
    `password ${V}`, `Password   ${V}`, `pass: ${V}`, `pass ${V}`, `my token is ${V}`, `the secret is ${V}`, `api key: ${V}`, `API KEY ${V}`, `passcode: ${V}`, `passcode ${V}`,
    `password - ${V}`, `password – ${V}`, `password — ${V}`, `password => ${V}`, `password -> ${V}`, `password := ${V}`, `login: bob / ${V}`, `user: bob | ${V}`, `username=bob/${V}`,
    `pw is ${V}`, `pwd are ${V}`, `passphrase was ${V}`, `client secret: ${V}`, `private key = ${V}`, `access key ${V}`, `credential ${V}`, `credentials: ${V}`, `tokens ${V}`,
    `password "${V}"`, `password '${V}'`, `Secret is ${V}`, `the api_key is ${V}`,
  ];
  for (const text of forms) for (const [name, fn] of CLEANERS) assert.ok(!fn(`please note ${text} thanks`).includes(V), `${text} through ${name}`);
});

test('vertical tab and form feed are written out like the other controls (a keyword split by one is found); tab, line feed and carriage return are separators', () => {
  for (const ch of ['\u000b', '\u000c']) {
    for (const [name, fn] of CLEANERS) assert.ok(!fn(`pass${ch}word: CANARYvtff12`).includes('CANARYvtff12'), `U+${ch.charCodeAt(0).toString(16)} through ${name}`);
    assert.equal(cleanFree(`a${ch}b`), `a\\u{${ch.charCodeAt(0).toString(16)}}b`, 'written out, not deleted');
  }
  assert.equal(cleanFree('a\tb'), 'a b'); assert.equal(cleanFree('a\nb'), 'a b'); assert.equal(cleanFree('a\rb'), 'a b');
  for (const ch of ['\t', '\n', '\r']) assert.ok(!cleanFree(`password${ch}CANARYtab123`).includes('CANARYtab123'), 'a separator still separates the keyword from its value');
});

test('the looser spellings are masked when the keyword is disguised with hidden characters, controls or percent-encoding too', () => {
  const woven = (w, ch) => [...w].join(ch);
  for (const text of [`${woven('password', '​')} ${V}`, `${woven('password', '\u0001')} ${V}`, `${woven('pass', '\u0085')}: ${V}`, `${woven('token', '\u007f')} is ${V}`, encodeURIComponent(`password ${V}`), encodeURIComponent(encodeURIComponent(`login: bob / ${V}`))]) {
    for (const [name, fn] of CLEANERS) assert.ok(!fn(text).includes(V), `${JSON.stringify(text)} through ${name}`);
  }
});

test('ordinary sentences stay readable: the loose forms need a value that looks like a secret (6 or more characters with a digit), "is" after a password word excepted', () => {
  const plain = [
    'password reset', 'Reset your password and sign in again', 'the password policy is documented', 'a password manager', 'password issue', 'the token is accepted', 'The token stops at the gateway.',
    'This token is short-lived and signed by the issuer', 'token limit 4096 characters', 'token 4096 chars', 'secret santa', 'a shared secret is never forwarded', 'pass the audience check',
    'bypass: allowed', 'compass: north', 'bypass 1234567', 'compass 1234567', 'Pass or fail', 'passes: 3', 'access key owned by an identity', 'api key rotation is manual', 'the credential is injected by the gateway',
    'credentials expire', 'user: bob', 'login: bob', 'username: alice, role: admin', 'account: acme', 'user: /home/bob/notes', 'token for the pod', 'The key stops when its custodian goes inactive',
    'system:serviceaccount:payments:agent-runner', 'payments/agent-runner pod agent-runner-7d9f', 'secret 2026', 'password 12345', 'the token 12345 is short',
  ];
  for (const text of plain) {
    assert.equal(cleanFree(text, 2000), text, `cleanFree leaves ${JSON.stringify(text)}`);
    assert.equal(maskResponseText(text), text, `the response mask leaves ${JSON.stringify(text)}`);
    assert.equal(credentialProblem(text), false, `a claim ${JSON.stringify(text)} is not refused`);
  }
});

test('boundaries of the loose forms, literally (the shared masker): a value of 6 characters with a digit is masked, 5 is not, six without a digit is not; the strict forms need 3', () => {
  const none = (text) => ids(text).length === 0;
  assert.ok(masked('password abc123', 'shape'), '6 characters with a digit after a space');
  assert.ok(none('password abc12'), '5 characters');
  assert.ok(none('password abcdef'), '6 letters, no digit');
  assert.ok(masked('token is abc123', 'phrase') && none('token is abcdef'));
  assert.ok(masked('password - abc123', 'shape') && none('password - abc12'));
  assert.ok(masked('login: bob / abc123', 'pair') && none('login: bob / abcdef'));
  assert.ok(masked('password: abc', 'assignment'), 'a separator: 3 characters are enough');
  assert.ok(none('password: ab'), 'a 2-character value is not masked (documented)');
  assert.ok(masked('password is abc', 'phrase') && none('password is ab'), '"is" after a password word: 3');
  assert.ok(masked('pw are abc', 'phrase') && none('pw are ab'), '"are" too');
  assert.ok(masked('secret=abc', 'assignment') && none('secret=ab'));
  assert.ok(masked('password => abc', 'assignment'));
  assert.ok(masked('{"passcode":"x"}', 'assignment') && masked('{"api key":"x"}', 'assignment'));
  // documented gaps of the shared masker (README "Known limits"): the short word "pass" alone and a bare number after a keyword are not found
  assert.ok(none('pass: abc') && none('{"pass":"x"}') && none('token: 7'));
});

test('a user name and password in a URL without a scheme are masked (S2)', () => {
  for (const text of ['bob:CANARYhunter2xyz@host.example', '//bob:CANARYhunter2xyz@host.example', 'see bob:CANARYhunter2xyz@host.example/x for it', 'at (bob:CANARYhunter2xyz@host.example)', 'ftp://bob:CANARYhunter2xyz@host.example', 'bob:CANARYhunter2xyz@localhost:8080', 'https%3A%2F%2Fbob%3ACANARYhunter2xyz%40host.example', 'https://bob:CANARYhunter2xyz@10.0.0.1/x']) {
    for (const [name, fn] of CLEANERS) assert.ok(!fn(text).includes('CANARYhunter2xyz'), `${text} through ${name}`);
  }
  for (const ok of ['alice@host.example', 'contact: alice@host.example', 'ratio 3:4@noon', 'a user@host and a note: here', 'time 10:30@home']) assert.equal(cleanFree(ok, 2000), ok, ok);
  assert.ok(masked(`bob:${'p'.repeat(128)}@host.example`, 'userinfo'), 'a 128 character password');
  // documented gaps: a scheme-less pair before an address that is an IPv4 address plus a domain, and a path segment that reads as user:pw@ (a false positive, README)
  assert.equal(cleanFree('//bob:CANARYhunter2xyz@10.0.0.1.example', 2000), '//bob:CANARYhunter2xyz@10.0.0.1.example');
  assert.equal(cleanFree('http://host.example/a:b@c', 2000), 'http://host.example/[masked:userinfo]c');
});

test('a bearer value that is Bearer or Basic plus a secret-looking run is masked whole, and the second of two glued values is a documented gap (N5)', () => {
  for (const v of ['CANARYbearer1234', 'Abcdefghi1x']) {
    for (const lead of ['Bearer', 'Authorization: Bearer']) for (const [name, fn] of CLEANERS) assert.ok(!fn(`${lead} ${v}`).includes(v.slice(0, 8)), `${lead} ${v} through ${name}`);
  }
  assert.ok(masked('Basic dXNlcjpwYXNzd29yZA==', 'bearer'), 'a Basic credential');
  assert.ok(masked('Bearer Abcdefghi1', 'bearer') && ids('Bearer abcdefghij').length === 0, 'a value that is all lower-case letters reads as a word');
  // the glued second value: the shared masker masks the first and leaves the second (reported to shared-masker; README "Known limits")
  assert.equal(cleanFree('Bearer aB3dEf6hIjK9Bearer cD4eFg7hJkL0 end', 2000), '[masked:bearer] cD4eFg7hJkL0 end');
  assert.equal(cleanFree('standard bearer of the house', 2000), 'standard bearer of the house');
});

test('the free-text cap is 400; a claim is refused from 24 letters and digits without a separator, and a refused value shows only its masked form', () => {
  assert.equal(MAX_FREE, 400);
  assert.equal(cleanFree('ab '.repeat(300)).length, 400, 'default cap: exactly 400');
  assert.equal(cleanFree('ab '.repeat(300), 399).length, 399);
  // a claim: 23 letters pass, 24 are refused
  assert.equal(credentialProblem('a'.repeat(23)), false); assert.equal(credentialProblem('a'.repeat(24)), true);
  // what is shown of a refused value: it is never the value
  assert.equal(reveal('a'.repeat(23)), 'a'.repeat(23));
  assert.equal(reveal('a'.repeat(24)), '[masked:long-run]');
  assert.equal(reveal(`${'a'.repeat(24)} password: abc`), '[masked:long-run] [masked:assignment]');
  assert.equal(reveal(`${'a'.repeat(23)} password: abc`), `${'a'.repeat(23)} [masked:assignment]`);
});

test('the response mask scans a long text to its end (past the 40,000 character fold cap) and leaves ordinary generated text, ids and hashes alone', () => {
  const secret = ['pass', 'word: CANARYhunter2xyz'].join(''); // assembled at run time, like the other fixtures
  const long = `${'a '.repeat(30000)}${secret}`;
  assert.ok(long.length > 40000);
  assert.ok(!maskResponseText(long).includes('CANARYhunter2xyz'), 'a secret after 60,000 characters');
  assert.ok(!maskResponseText(`${'a '.repeat(25000)}${secret}`).includes('CANARYhunter2xyz'), 'and one that straddles the cap');
  assert.ok(!maskResponseText(`${'b '.repeat(19000)}${secret}`).includes('CANARYhunter2xyz'), 'and one under the cap');
});

test('everything the lab itself writes passes through the response mask unchanged: the story, the diagrams, the mock tables and every preset verdict in all three verticals', () => {
  for (const [vertical, cast] of Object.entries(VERTICALS)) {
    const story = buildStory(cast, vertical);
    assert.deepEqual(maskStatic(story), story, `story ${vertical}`);
    for (const n of DIAGRAM_NAMES) { const d = buildDiagram(cast, n); assert.deepEqual(maskStatic(d), d, `${n} ${vertical}`); }
    const e = newEngine(cast);
    for (const p of fillDeep(PRESETS, cast)) {
      const m = e.mint(p.mint); const r = e.verify({ token: m.mintedToken, identityId: p.identityId, service: p.service });
      assert.deepEqual(maskDeep({ ...m, mintedToken: undefined }), { ...m, mintedToken: undefined }, `${p.id} mint ${vertical}`);
      assert.deepEqual(maskDeep(r), r, `${p.id} verdict ${vertical}`);
    }
    assert.deepEqual(maskDeep(e.snapshot()), e.snapshot(), `state ${vertical}`);
  }
  assert.deepEqual(maskStatic(MOCK_TABLE), MOCK_TABLE, 'mock table');
});

test('a \\uXXXX escape written out as text is read as the character it names when matching ({"\\u0070assword":"x"})', () => {
  const U = (cp) => `\\u${cp.toString(16).padStart(4, '0')}`; // the escape as TEXT, assembled at run time (a scanner decodes escapes it finds in source)
  const V = 'CANARYuesc123';
  const forms = [`{"${U(0x70)}assword":"${V}"}`, `{"\\u{70}assword":"${V}"}`, `${U(0x70)}assword: ${V}`, `{"${U(0x70)}${U(0x61)}ssword":"${V}"}`, `pass${U(0x200b)}word: ${V}`, `pass${U(1)}word: ${V}`, `${U(0x62)}earer ${V}4`, `password${U(0x3a)} ${V}`, `passw${U(0x6f)}rd: ${V}`, `passw\\u006Frd: ${V}`, `passw\\u{6F}rd: ${V}`];
  for (const text of forms) for (const [name, fn] of CLEANERS) assert.ok(!fn(text).includes('CANARYuesc123'), `${text} through ${name}`);
  assert.equal(credentialProblem('{"\\u0070assword":"x"}'), true, 'a claim shaped like that is refused');
  for (const ok of ['a\\u12 b', 'path C:\\users\\bob', '\\u{110000}', '\\uZZZZ']) assert.equal(cleanFree(ok, 100), ok, ok);
});
