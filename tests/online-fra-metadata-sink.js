'use strict';

// Proves the sentence, not the intention: "Nothing accumulates a log of your
// connections." The sink is fed real relay traffic carrying marker identifiers
// and the test then searches the sink's entire reachable state for them --
// the same prove-by-marker method the relay's own no-logging test uses.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createOnlineFraMetadataSink, EVENT_TYPES } = require('../src/lib/online-fra-metadata-sink');
const { createOnlineFraRendezvousRelay, leaseSigningBytes, LEASE_SCHEMA_VERSION } = require('../src/lib/online-fra-rendezvous-relay');

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }

// --- static half: the module is structurally incapable of durability --------
{
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'lib', 'online-fra-metadata-sink.js'), 'utf8');
  const codeOnly = source.split(/\r?\n/).filter(line => !/^\s*\/\//.test(line)).join('\n');
  ok(!/require\(/.test(codeOnly), 'the sink must import NOTHING -- no fs, no net, no sqlite, nothing');
  for (const forbidden of ['pairId', 'deviceId', 'peerDeviceId', 'connectionId', 'leaseId']) {
    ok(!new RegExp(`event\\.${forbidden}`).test(codeOnly), `the sink must never read event.${forbidden}: an identifier it never reads is one it cannot retain`);
  }
}

// --- dynamic half: real relay traffic, marker identifiers, then search ------
{
  const MARKER = 'zmarkerpairzz';
  const authority = crypto.generateKeyPairSync('ed25519');
  const metadataSink = createOnlineFraMetadataSink();
  const pair = { pairId: `pair-${MARKER}`, machineAId: `machine-${MARKER}a`, machineBId: `machine-${MARKER}b`, capabilityDigest: '1'.repeat(64) };
  const nowMs = 1_700_000_000_000;
  let counter = 0;

  const leaseState = {
    admitLease: () => ({ ok: true, outcome: 'accepted' }),
    pairState: () => ({ ok: true, revoked: false }),
    revokePair: () => ({ ok: true, revoked: true })
  };
  const relay = createOnlineFraRendezvousRelay({
    enabled: true,
    authorityPublicKey: authority.publicKey,
    generation: 1,
    pairs: [pair],
    clock: () => nowMs,
    randomBytes: size => { const b = Buffer.alloc(size); b.writeUInt32BE(++counter, size - 4); return b; },
    eventSink: metadataSink.sink,
    leaseState
  });

  function lease(role) {
    const deviceId = role === 'machine-a' ? pair.machineAId : pair.machineBId;
    const base = {
      schemaVersion: LEASE_SCHEMA_VERSION,
      leaseId: `lease-${MARKER}${++counter}`,
      pairId: pair.pairId,
      deviceId,
      peerDeviceId: role === 'machine-a' ? pair.machineBId : pair.machineAId,
      endpointRole: role,
      mtlsFingerprint: 'f'.repeat(64),
      generation: 1,
      issuedAtMs: nowMs - 10,
      expiresAtMs: nowMs + 60_000,
      nonce: crypto.randomBytes(24).toString('base64url'),
      ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      capabilityDigest: pair.capabilityDigest,
      signature: Buffer.alloc(64).toString('base64url')
    };
    base.signature = crypto.sign(null, leaseSigningBytes(base), authority.privateKey).toString('base64url');
    return base;
  }

  const aLease = lease('machine-a');
  const bLease = lease('machine-b');
  const a = relay.connect({ identity: { verified: true, authType: 'mtls', deviceId: aLease.deviceId, mtlsFingerprint: aLease.mtlsFingerprint }, lease: aLease });
  const b = relay.connect({ identity: { verified: true, authType: 'mtls', deviceId: bLease.deviceId, mtlsFingerprint: bLease.mtlsFingerprint }, lease: bLease });

  const FRAMES = 100;
  for (let index = 0; index < FRAMES; index += 1) {
    relay.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.from(`frame-${MARKER}`) });
    relay.take(b.connectionId);
  }
  relay.close(a.connectionId);

  const snap = metadataSink.snapshot();
  // Preconditions: traffic really flowed and really was counted.
  equal(snap.countsByType['online_fra.connection.accepted'], 2, 'precondition: both connections were seen');
  equal(snap.routedFrames, FRAMES, 'precondition: every routed frame was counted');
  equal(snap.routedBytes, FRAMES * Buffer.byteLength(`frame-${MARKER}`), 'precondition: bytes were counted');
  ok(snap.firstEventAtMs === nowMs && snap.lastEventAtMs === nowMs, 'only first/last timestamps exist, not one per event');

  // THE CLAIM: after 100 routed frames between marker-named endpoints, no
  // identifier survives anywhere in the sink's reachable state.
  const everything = JSON.stringify(snap);
  ok(!everything.includes(MARKER), 'no pair, device, or lease identifier may survive in the sink');
  ok(!everything.includes(pair.pairId), 'the pairing identifier -- the one that crosses from the account database -- must not be retained');

  // O(1) in traffic: another thousand frames must not grow the state.
  const sizeBefore = everything.length;
  for (let index = 0; index < 1000; index += 1) {
    metadataSink.sink({ schemaVersion: 'online-fra-rendezvous-event.v1', sequence: index, type: 'online_fra.frame.routed', atMs: nowMs + index, pairId: `pair-${MARKER}`, deviceId: `machine-${MARKER}a`, peerDeviceId: `machine-${MARKER}b`, bytes: 64 });
  }
  const after = JSON.stringify(metadataSink.snapshot());
  ok(!after.includes(MARKER), 'a thousand more identified events retain nothing');
  ok(after.length <= sizeBefore + 32, `state must be O(1) in traffic (was ${sizeBefore}, now ${after.length})`);

  // A hostile emitter cannot grow it by inventing type names either.
  for (let index = 0; index < 500; index += 1) {
    metadataSink.sink({ type: `invented.${MARKER}.${index}`, atMs: nowMs });
  }
  const hostile = JSON.stringify(metadataSink.snapshot());
  ok(!hostile.includes(MARKER), 'unknown type strings are counted, never stored');
  equal(metadataSink.snapshot().otherEvents, 500, 'and they are still counted');

  // The sink never throws -- a throwing sink closes customer pairs.
  for (const junk of [null, undefined, 42, 'text', {}, { type: 17 }, { type: 'online_fra.frame.routed', bytes: 'many' }]) {
    metadataSink.sink(junk);
  }
  ok(true, 'junk events are absorbed without a throw');

  // Every event type the relay emits is in the sink's vocabulary -- a new
  // relay event landing in `otherEvents` should be a deliberate choice, and
  // this stays true only while the two files agree.
  const relaySource = fs.readFileSync(path.join(__dirname, '..', 'src', 'lib', 'online-fra-rendezvous-relay.js'), 'utf8');
  for (const match of relaySource.matchAll(/sink\('([a-z_.]+)'/g)) {
    ok(EVENT_TYPES.includes(match[1]), `relay event ${match[1]} must be in the sink vocabulary`);
  }
}

console.log(`online-fra-metadata-sink: ${assertions} assertions passed`);
