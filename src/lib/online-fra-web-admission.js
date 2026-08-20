'use strict';

// Admission for the web-client role -- the piece that makes "no client
// certificate" acceptable rather than merely convenient.
//
// Machines prove identity with mTLS; a browser cannot, so its lease alone
// would be a bearer token: anyone holding the bytes could connect. This
// module closes that: the edge issues a nonce, the browser signs it with the
// non-extractable WebCrypto key whose SPKI SHA-256 the lease's fingerprint
// slot commits to, and only a verified signature reaches relay.connect() --
// which then re-checks the same fingerprint consistency the mTLS path checks.
// A leaked lease without the browser's key admits nothing.
//
// Zero dependencies, no listener: the web edge (an nginx location WITHOUT
// ssl_verify_client, proxying to the same adapter) calls challenge() and
// admit(); this module owns only the cryptographic dance and its bounds.

const crypto = require('node:crypto');

const NONCE_TTL_MS = 60_000;
const NONCE_STORE_MAX = 1024;
const NONCE_BYTES = 32;

class OnlineFraWebAdmissionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'OnlineFraWebAdmissionError';
    this.code = code;
  }
}

function fail(code) { throw new OnlineFraWebAdmissionError(code); }

function createOnlineFraWebAdmission({ relay, clock = () => Date.now() } = {}) {
  if (!relay || typeof relay.connect !== 'function') fail('ONLINE_FRA_WEB_ADMISSION_OPTIONS_INVALID');
  if (typeof clock !== 'function') fail('ONLINE_FRA_WEB_ADMISSION_OPTIONS_INVALID');

  // nonce (base64url) -> expiresAtMs. Bounded and single-use: a nonce store
  // that grows with refused attempts is a memory lever, so the oldest entry
  // dies when the cap is hit -- costing that oldest challenger a retry,
  // nothing else.
  const nonces = new Map();

  function sweep(atMs) {
    for (const [nonce, expiresAtMs] of nonces) {
      if (expiresAtMs <= atMs) nonces.delete(nonce);
    }
  }

  function challenge() {
    const atMs = clock();
    sweep(atMs);
    if (nonces.size >= NONCE_STORE_MAX) {
      const oldest = nonces.keys().next().value;
      nonces.delete(oldest);
    }
    const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64url');
    nonces.set(nonce, atMs + NONCE_TTL_MS);
    return Object.freeze({ nonce, expiresAtMs: atMs + NONCE_TTL_MS });
  }

  /**
   * Admit one browser. Everything is verified BEFORE relay.connect(), so a
   * failed possession proof consumes neither the lease's nonce (the durable
   * one, in the lease state) nor a challenge replay window beyond its own.
   */
  function admit({ lease, browserPublicKeySpki, nonce, signature } = {}) {
    if (!lease || lease.endpointRole !== 'web-client') fail('ONLINE_FRA_WEB_ADMISSION_ROLE_INVALID');

    // The nonce: known, unexpired, and SINGLE-USE -- deleted before any
    // verification, so even a verification crash cannot leave it replayable.
    if (typeof nonce !== 'string' || !nonces.has(nonce)) fail('ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
    const expiresAtMs = nonces.get(nonce);
    nonces.delete(nonce);
    if (expiresAtMs <= clock()) fail('ONLINE_FRA_WEB_ADMISSION_NONCE_EXPIRED');

    // The key: canonical base64url SPKI Ed25519, and its digest must be the
    // one the SIGNED lease committed to -- the same "fingerprint of the
    // presented identity" the mTLS path enforces, presented differently.
    let publicKey;
    let der;
    try {
      der = Buffer.from(String(browserPublicKeySpki), 'base64url');
      publicKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    } catch { fail('ONLINE_FRA_WEB_ADMISSION_KEY_INVALID'); }
    if (publicKey.asymmetricKeyType !== 'ed25519'
      || publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') !== browserPublicKeySpki) {
      fail('ONLINE_FRA_WEB_ADMISSION_KEY_INVALID');
    }
    const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
    if (fingerprint !== lease.mtlsFingerprint) fail('ONLINE_FRA_WEB_ADMISSION_KEY_MISMATCH');

    // The possession proof: the browser signed OUR nonce with THAT key.
    let proven = false;
    try {
      proven = crypto.verify(null, Buffer.from(nonce, 'base64url'), publicKey, Buffer.from(String(signature), 'base64url'));
    } catch { proven = false; }
    if (proven !== true) fail('ONLINE_FRA_WEB_ADMISSION_PROOF_INVALID');

    return relay.connect({
      identity: Object.freeze({ verified: true, authType: 'web-lease', deviceId: lease.deviceId, mtlsFingerprint: lease.mtlsFingerprint }),
      lease
    });
  }

  return Object.freeze({ challenge, admit, pendingChallenges: () => nonces.size });
}

module.exports = Object.freeze({ OnlineFraWebAdmissionError, createOnlineFraWebAdmission, NONCE_TTL_MS });
