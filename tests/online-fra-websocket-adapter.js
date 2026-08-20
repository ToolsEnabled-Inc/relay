'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createOnlineFraWebSocketAdapter, DEFAULTS } = require('../src/lib/online-fra-websocket-adapter');
const {
  LEASE_SCHEMA_VERSION, createOnlineFraRendezvousRelay, leaseSigningBytes
} = require('../src/lib/online-fra-rendezvous-relay');
let assertions = 0;
const equal = (...a) => { assertions += 1; return assert.equal(...a); };
const ok = (...a) => { assertions += 1; return assert.ok(...a); };
function throws(run, predicate) { assertions += 1; return assert.throws(run, predicate); }

class FakeTimers {
  constructor() { this.now = 1_000_000; this.next = 1; this.items = new Map(); }
  set = (fn, ms) => { const id = this.next++; this.items.set(id, { fn, at: this.now + ms }); return id; };
  clear = id => this.items.delete(id);
  advance(ms) { this.now += ms; for (const [id, item] of [...this.items]) if (item.at <= this.now) { this.items.delete(id); item.fn(); } }
}
class FakeSocket { constructor() { this.destroyed = false; } destroy() { this.destroyed = true; } }
class FakeWs {
  constructor() { this.handlers = new Map(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; this.closed = []; this.pings = 0; }
  on(name, fn) { const list = this.handlers.get(name) || []; list.push(fn); this.handlers.set(name, list); }
  once(name, fn) { this.on(name, fn); }
  emit(name, ...args) { for (const fn of [...(this.handlers.get(name) || [])]) fn(...args); }
  send(data, options) { this.sent.push({ data: Buffer.from(data), options }); }
  ping() { this.pings += 1; }
  close(code) { this.closed.push(code); this.readyState = 3; this.emit('close'); }
}
class FakeWss {
  constructor(options) { this.options = options; this.closed = false; FakeWss.instances.push(this); }
  handleUpgrade(req, socket, head, callback) { this.last = { req, socket, head }; callback(socket.ws); }
  close() { this.closed = true; }
}
FakeWss.instances = [];

function fixture(overrides = {}) {
  const timers = new FakeTimers(); const events = []; const routes = []; const outbound = [];
  const httpServer = { handlers: new Map(), on(name, fn) { this.handlers.set(name, fn); }, off(name) { this.handlers.delete(name); } };
  const relay = {
    connect(input) { relay.connects.push(input); return { connectionId: 'connection-1' }; },
    connectionMetadata(id) { relay.metadata.push(id); return { peerConnectionId: 'peer-1' }; },
    route(input) { routes.push(input); },
    take(id) { relay.takes.push(id); return outbound.shift() ?? null; },
    close(id, reason) { relay.closes.push({ id, reason }); },
    connects: [], metadata: [], takes: [], closes: []
  };
  const base = {
    WebSocketServer: FakeWss, enabled: true, httpServer, relay, hostname: 'fra-relay.devices.example.net',
    eventSink: event => events.push(event), verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '10.0.0.2' }),
    clock: () => timers.now, setTimer: timers.set, clearTimer: timers.clear,
    maxFrameBytes: 1024, maxAdmissionBytes: 128, maxSockets: 2, maxSocketsPerIp: 1, maxAdmissionsPerIp: 2,
    admissionWindowMs: 100, admissionTimeoutMs: 20, pingIntervalMs: 10, idleTimeoutMs: 30, maxBufferedBytes: 1024, maxDrainPerTick: 3,
    ...overrides
  };
  return { timers, events, routes, outbound, httpServer, relay, base, adapter: createOnlineFraWebSocketAdapter(base) };
}
function upgrade(test, request = { method: 'GET', url: '/v1/rendezvous' }, ws = new FakeWs(), head = Buffer.alloc(0)) {
  const socket = new FakeSocket(); socket.ws = ws; test.httpServer.handlers.get('upgrade')(request, socket, head); return { socket, ws };
}

(() => {
  throws(() => createOnlineFraWebSocketAdapter({}), error => error && error.code === 'ONLINE_FRA_WS_OPTIONS_INVALID');
  const inert = fixture({ enabled: false });
  equal(inert.adapter.snapshot().started, false); equal(inert.adapter.start(), false); equal(FakeWss.instances.length, 0);
  const test = fixture(); equal(test.adapter.start(), true); equal(test.adapter.start(), false);
  const settings = FakeWss.instances.at(-1).options; equal(settings.noServer, true); equal(settings.maxPayload, 1024); equal(settings.perMessageDeflate, false);
  for (const request of [{ method: 'POST', url: '/v1/rendezvous' }, { method: 'GET', url: '/v1/rendezvous?x=1' }]) { const result = upgrade(test, request); equal(result.socket.destroyed, true); }
  equal(upgrade(test, { method: 'GET', url: '/v1/rendezvous' }, new FakeWs(), Buffer.from('x')).socket.destroyed, true);
  for (const bad of [
    { tlsSni: 'other.example' }, { clientVerify: 'NONE' }, { clientVerify: 'FAILED:bad' }, { deviceId: 'X' }, { fingerprint: 'nothex' }, { ip: 'not-ip' }
  ]) { const badTest = fixture({ verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '10.0.0.2', ...bad }) }); badTest.adapter.start(); equal(upgrade(badTest).socket.destroyed, true); }
  { const ipv6 = fixture({ verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '2001:db8::2' }) }); ipv6.adapter.start(); equal(upgrade(ipv6).socket.destroyed, false); }
  { const asyncTest = fixture({ verifyProxyRequest: () => Promise.resolve({}) }); asyncTest.adapter.start(); equal(upgrade(asyncTest).socket.destroyed, true); }
  throws(() => fixture({ eventSink: async () => {} }), error => error && error.code === 'ONLINE_FRA_WS_EVENT_SINK');
  { const thenable = { then(resolve, reject) { reject(new Error('later')); } }; const sink = fixture({ eventSink: () => thenable }); sink.adapter.start(); const result = upgrade(sink); equal(result.ws.closed.length, 1); }
  const first = upgrade(test); equal(first.socket.destroyed, false); equal(test.adapter.snapshot().sockets, 1); equal(test.events.at(-1).type, 'online_fra.ws.connected');
  first.ws.emit('message', Buffer.from('{"lease":{"id":"PRIVATE-MARKER"}}'), false);
  equal(test.relay.connects.length, 1); equal(test.relay.metadata.length, 2); equal(test.events.at(-1).type, 'online_fra.ws.admitted'); ok(!JSON.stringify(test.events).includes('PRIVATE-MARKER'));
  equal(test.relay.connects[0].identity.authType, 'mtls');
  first.ws.emit('message', Buffer.from('abc'), true); equal(test.routes.length, 1); equal(test.routes[0].peerConnectionId, 'peer-1'); ok(Buffer.isBuffer(test.routes[0].frame));
  test.outbound.push(Buffer.from('out-1'), Buffer.from('out-2')); test.adapter.drain(); equal(first.ws.sent.length, 2); ok(first.ws.sent.every(item => item.options.binary === true));
  first.ws.bufferedAmount = 2000; test.outbound.push(Buffer.from('blocked')); test.adapter.drain(); equal(first.ws.sent.length, 2);
  first.ws.bufferedAmount = 0; test.timers.advance(10); equal(first.ws.pings, 1); first.ws.emit('pong'); test.timers.advance(10); equal(first.ws.pings, 2);
  const sameIp = upgrade(test); equal(sameIp.socket.destroyed, true, 'per-IP active cap rejects while first is live');
  first.ws.emit('close'); equal(test.adapter.snapshot().sockets, 0); equal(test.relay.closes.length, 1); first.ws.emit('error', new Error('late')); equal(test.adapter.snapshot().sockets, 0, 'late events are ignored');
  const rateLimited = upgrade(test); rateLimited.ws.emit('close'); const rateAgain = upgrade(test); equal(rateAgain.socket.destroyed, true, 'admission rate persists after close'); test.timers.advance(101); const recovered = upgrade(test); equal(recovered.socket.destroyed, false, 'admission window recovers'); recovered.ws.emit('close');
  { const admission = fixture(); admission.adapter.start(); const { ws } = upgrade(admission); ws.emit('message', Buffer.from('{"bad":1}'), false); equal(ws.closed.length, 1); equal(admission.adapter.snapshot().sockets, 0); }
  { const timeout = fixture(); timeout.adapter.start(); const { ws } = upgrade(timeout); timeout.timers.advance(21); equal(ws.closed.length, 1); equal(timeout.adapter.snapshot().sockets, 0); }
  { const idle = fixture(); idle.adapter.start(); const { ws } = upgrade(idle); ws.emit('message', Buffer.from('{"lease":1}'), false); idle.timers.advance(31); equal(ws.closed.at(-1), 1001); }
  { const frame = fixture(); frame.adapter.start(); const { ws } = upgrade(frame); ws.emit('message', Buffer.from('{"lease":1}'), false); ws.emit('message', Buffer.alloc(1025), true); equal(ws.closed.length, 1); }
  {
    let paired = false; const routes = [];
    const relay = {
      connect: () => ({ connectionId: 'connection-1' }),
      connectionMetadata: () => ({ peerConnectionId: paired ? 'peer-1' : null }),
      route: input => routes.push(input), take: () => null, close() {}
    };
    const awaiting = fixture({ relay }); awaiting.adapter.start(); const { ws } = upgrade(awaiting);
    ws.emit('message', Buffer.from('{"lease":1}'), false); equal(ws.closed.length, 0, 'first endpoint remains admitted while its peer connects');
    paired = true; ws.emit('message', Buffer.from('opaque'), true); equal(routes.length, 1);
  }
  { const badRelay = fixture({ relay: { connect: () => Promise.resolve({}), route() {}, take() { return null; }, close() {}, connectionMetadata() { return { peerConnectionId: 'peer-1' }; } } }); badRelay.adapter.start(); const { ws } = upgrade(badRelay); ws.emit('message', Buffer.from('{"lease":1}'), false); equal(ws.closed.length, 1); }
  { const sink = fixture({ eventSink: () => { throw new Error('sink'); } }); sink.adapter.start(); const result = upgrade(sink); equal(result.ws.closed.length, 1); equal(sink.adapter.snapshot().sockets, 0); }
  { const stopped = fixture(); stopped.adapter.start(); const server = FakeWss.instances.at(-1); const { ws } = upgrade(stopped); stopped.adapter.stop(); equal(ws.closed.at(-1), 1001); equal(server.closed, true); equal(stopped.adapter.snapshot().rateEntries, 0); equal(stopped.adapter.stop(), true); equal(stopped.httpServer.handlers.has('upgrade'), false); }
  { const revoked = fixture(); revoked.adapter.start(); const { ws } = upgrade(revoked); equal(revoked.adapter.kill(), true); equal(ws.closed.at(-1), 1008); }
  {
    const authority = crypto.generateKeyPairSync('ed25519');
    const pair = { pairId: 'pair-ab', machineAId: 'device-a', machineBId: 'device-b', capabilityDigest: '1'.repeat(64) };
    const state = {
      admitLease: () => ({ ok: true, outcome: 'accepted' }),
      pairState: () => ({ ok: true, revoked: false }),
      revokePair: () => ({ ok: true, revoked: true })
    };
    const realRelay = createOnlineFraRendezvousRelay({
      enabled: true, authorityPublicKey: authority.publicKey, generation: 1, pairs: [pair],
      clock: () => 1_000_000, randomBytes: size => Buffer.alloc(size, 7), eventSink: () => {}, leaseState: state
    });
    const endpoint = {
      schemaVersion: LEASE_SCHEMA_VERSION, leaseId: 'lease_device_a_0001', pairId: pair.pairId,
      deviceId: 'device-a', peerDeviceId: 'device-b', endpointRole: 'machine-a', mtlsFingerprint: 'a'.repeat(64),
      generation: 1, issuedAtMs: 999_990, expiresAtMs: 1_060_000,
      nonce: crypto.randomBytes(24).toString('base64url'),
      ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      capabilityDigest: pair.capabilityDigest, signature: Buffer.alloc(64).toString('base64url')
    };
    endpoint.signature = crypto.sign(null, leaseSigningBytes(endpoint), authority.privateKey).toString('base64url');
    const direct = realRelay.connect({
      identity: { verified: true, authType: 'mtls', deviceId: 'device-a', mtlsFingerprint: 'a'.repeat(64) },
      lease: endpoint
    });
    realRelay.close(direct.connectionId);
    const integrated = fixture({ relay: realRelay, maxAdmissionBytes: 8192 }); integrated.adapter.start(); const { ws } = upgrade(integrated);
    ws.emit('message', Buffer.from(JSON.stringify({ lease: endpoint })), false);
    equal(ws.closed.length, 0, 'the adapter identity is accepted by the real relay while awaiting the peer');
    equal(realRelay.snapshot().activeConnections, 1); ws.emit('close'); equal(realRelay.snapshot().activeConnections, 0);
  }
  ok(DEFAULTS.maxFrameBytes > 0);
  console.log(`Online FRA websocket adapter tests passed (${assertions} assertions).`);
})();
