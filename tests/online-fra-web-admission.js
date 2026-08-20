'use strict';

// The web admission dance: a leaked lease without the browser's key admits
// nothing; the browser with its key admits exactly once per challenge.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }
function code(fn, expected) {
  assertions += 1;
  try { fn(); } catch (error) { assert.equal(error.code, expected); return; }
  assert.fail(`expected ${expected}`);
}

const browser = crypto.generateKeyPairSync('ed25519');
const browserSpki = browser.publicKey.export({ type: 'spki', format: 'der' });
const browserWire = browserSpki.toString('base64url');
const fingerprint = crypto.createHash('sha256').update(browserSpki).digest('hex');
const webLease = { endpointRole: 'web-client', deviceId: `web-${'a'.repeat(24)}`, mtlsFingerprint: fingerprint };

function harness() {
  const connects = [];
  let nowMs = 1_800_000_000_000;
  const admission = createOnlineFraWebAdmission({
    relay: { connect: request => { connects.push(request); return Object.freeze({ connectionId: 'conn_1', ...request.lease }); } },
    clock: () => nowMs
  });
  return { admission, connects, advance: ms => { nowMs += ms; } };
}

function signed(nonce, key = browser.privateKey) {
  return crypto.sign(null, Buffer.from(nonce, 'base64url'), key).toString('base64url');
}

// The happy dance: challenge -> sign -> admit, and the relay sees web-lease.
{
  const { admission, connects } = harness();
  const { nonce } = admission.challenge();
  const receipt = admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) });
  equal(receipt.connectionId, 'conn_1');
  equal(connects[0].identity.authType, 'web-lease');
  equal(connects[0].identity.mtlsFingerprint, fingerprint);
}

// Single use: the same nonce cannot admit twice -- even after a SUCCESS.
{
  const { admission } = harness();
  const { nonce } = admission.challenge();
  admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) });
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
}

// A leaked lease without the key is NOTHING: wrong key, junk signature, and a
// signature by a different key all refuse -- and a failed attempt burns the
// nonce, so it cannot be brute-forced against.
{
  const { admission, connects } = harness();
  const other = crypto.generateKeyPairSync('ed25519');
  const first = admission.challenge();
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce: first.nonce, signature: signed(first.nonce, other.privateKey) }),
    'ONLINE_FRA_WEB_ADMISSION_PROOF_INVALID');
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce: first.nonce, signature: signed(first.nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
  // A key that does not match the lease's committed fingerprint refuses even
  // with a valid possession proof for THAT key.
  const second = admission.challenge();
  const otherWire = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: otherWire, nonce: second.nonce, signature: signed(second.nonce, other.privateKey) }),
    'ONLINE_FRA_WEB_ADMISSION_KEY_MISMATCH');
  equal(connects.length, 0, 'nothing reached the relay');
}

// Expiry: a stale challenge refuses by name.
{
  const { admission, advance } = harness();
  const { nonce } = admission.challenge();
  advance(61_000);
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_EXPIRED');
}

// The store is bounded: hammering challenge() cannot grow memory past the cap.
{
  const { admission } = harness();
  for (let index = 0; index < 3000; index += 1) admission.challenge();
  ok(admission.pendingChallenges() <= 1024, `bounded (${admission.pendingChallenges()})`);
}

// A machine lease cannot come through the web door.
{
  const { admission } = harness();
  const { nonce } = admission.challenge();
  code(() => admission.admit({ lease: { ...webLease, endpointRole: 'machine-a' }, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_ROLE_INVALID');
}

console.log(`online-fra-web-admission: ${assertions} assertions passed`);
