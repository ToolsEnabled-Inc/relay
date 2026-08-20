'use strict';

// Pure, opt-in WebSocket edge adapter for the separately authenticated online
// FRA session. It creates no HTTP listener itself; a deployment supplies an
// already-bound HTTPS server whose trusted proxy verifier attests mTLS/SNI.
//
// THE LEG BYTE. Every binary frame on the wire carries ONE leading byte naming
// a leg of the pair -- 0x01 machine-a, 0x02 machine-b, 0x03 web-client:
//
//   endpoint -> edge   [target leg][sealed payload]
//   edge -> endpoint   [source leg][sealed payload]
//
// It exists because the relay routes a pair as THREE legs (two machines and
// one web slot) while each endpoint holds ONE socket. A machine must be able
// to answer its peer and the browser through the same connection, and a
// browser must be able to address either machine; with no per-frame address
// the adapter could only ever route to one peer. The byte is the address and
// nothing else -- the payload after it is sealed above this layer and the
// edge neither reads nor alters it. The relay carries the source-stamped frame
// opaquely, so a frame taken for delivery is already in edge->endpoint form.
// A target that is not a live leg of the sender's own pair, or is the sender's
// own role, is refused and closes the socket.
const crypto = require('node:crypto');
const net = require('node:net');

const SAFE_ID = /^[a-z][a-z0-9_-]{2,95}$/;
const HEX = /^[a-f0-9]{64}$/;
const CONNECTION_ID = /^[A-Za-z0-9._-]{1,128}$/;
const LEG_BYTE = Object.freeze({ 'machine-a': 0x01, 'machine-b': 0x02, 'web-client': 0x03 });
const LEG_ROLE = Object.freeze({ 0x01: 'machine-a', 0x02: 'machine-b', 0x03: 'web-client' });
const DEFAULTS = Object.freeze({
  enabled: false, maxFrameBytes: 262144, maxAdmissionBytes: 8192, maxSockets: 64,
  maxSocketsPerIp: 4, maxAdmissionsPerIp: 12, admissionWindowMs: 60_000,
  admissionTimeoutMs: 10_000, pingIntervalMs: 30_000, idleTimeoutMs: 75_000,
  maxBufferedBytes: 524288, maxDrainPerTick: 16
});

class OnlineFraWebSocketAdapterError extends Error {
  constructor(code) { super(code); this.name = 'OnlineFraWebSocketAdapterError'; this.code = code; }
}
function fail(code) { throw new OnlineFraWebSocketAdapterError(code); }
function plain(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function integer(value, code, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(code); return value; }
function sync(value, code) { if (value && typeof value.then === 'function') fail(code); return value; }
function safeHostname(value) { if (typeof value !== 'string' || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) fail('ONLINE_FRA_WS_OPTIONS_INVALID'); return value; }
function safeIp(value) { return typeof value === 'string' && net.isIP(value) !== 0; }
function metadataFingerprint(attestation) { return crypto.createHash('sha256').update(`${attestation.deviceId}|${attestation.fingerprint}|${attestation.ip}`, 'utf8').digest('hex').slice(0, 16); }

function createOnlineFraWebSocketAdapter(options = {}) {
  const allowed = new Set([
    'WebSocketServer', 'enabled', 'eventSink', 'hostname', 'httpServer', 'relay', 'verifyProxyRequest',
    'keyAdmission', 'clientIpFor',
    'clock', 'setTimer', 'clearTimer', 'maxFrameBytes', 'maxAdmissionBytes', 'maxSockets', 'maxSocketsPerIp',
    'maxAdmissionsPerIp', 'admissionWindowMs', 'admissionTimeoutMs', 'pingIntervalMs', 'idleTimeoutMs',
    'maxBufferedBytes', 'maxDrainPerTick'
  ]);
  if (!plain(options) || Object.keys(options).some(key => !allowed.has(key))) fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  const config = { ...DEFAULTS, ...options };
  if (typeof config.WebSocketServer !== 'function' || !config.httpServer || typeof config.httpServer.on !== 'function'
    || typeof config.httpServer.off !== 'function'
    || typeof config.verifyProxyRequest !== 'function' || typeof config.eventSink !== 'function'
    || !config.relay || typeof config.relay.connect !== 'function' || typeof config.relay.route !== 'function'
    || typeof config.relay.take !== 'function' || typeof config.relay.connectionMetadata !== 'function'
    || typeof config.relay.close !== 'function'
    || typeof config.clock !== 'function' || typeof config.setTimer !== 'function' || typeof config.clearTimer !== 'function'
    || typeof config.enabled !== 'boolean') fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  if (config.eventSink.constructor && config.eventSink.constructor.name === 'AsyncFunction') fail('ONLINE_FRA_WS_EVENT_SINK');
  // KEY-POSSESSION ADMISSION, OPT-IN. When `keyAdmission` is supplied (an
  // online-fra-web-admission instance) a request that carries NO mTLS
  // attestation is admitted by a signed-nonce dance instead of rejected at
  // upgrade: the edge sends a challenge as its first frame, the endpoint's
  // first frame carries the lease, its public key, the nonce and a signature,
  // and keyAdmission.admit() verifies all of it BEFORE relay.connect(). This
  // is how browsers connect (no client-cert UX) and, since 2026-08-20, how
  // machines may connect too, signing with the identity key they generated.
  // Without `keyAdmission` the adapter behaves exactly as before: mTLS only.
  if (config.keyAdmission !== undefined && (!config.keyAdmission || typeof config.keyAdmission.challenge !== 'function'
    || typeof config.keyAdmission.admit !== 'function')) fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  if (config.clientIpFor !== undefined && typeof config.clientIpFor !== 'function') fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  config.hostname = safeHostname(config.hostname);
  for (const [key, min, max] of [
    ['maxFrameBytes', 1024, 1024 * 1024], ['maxAdmissionBytes', 128, 16 * 1024], ['maxSockets', 1, 4096],
    ['maxSocketsPerIp', 1, 256], ['maxAdmissionsPerIp', 1, 10000], ['admissionWindowMs', 1, 3600000],
    ['admissionTimeoutMs', 1, 120000], ['pingIntervalMs', 1, 300000], ['idleTimeoutMs', 2, 600000],
    ['maxBufferedBytes', 1024, 4 * 1024 * 1024], ['maxDrainPerTick', 1, 1024]
  ]) config[key] = integer(config[key], 'ONLINE_FRA_WS_OPTIONS_INVALID', min, max);
  if (config.idleTimeoutMs <= config.pingIntervalMs) fail('ONLINE_FRA_WS_OPTIONS_INVALID');

  let started = false;
  let wss = null;
  const live = new Set();
  const rate = new Map();

  function emit(type, metadata = {}) {
    const event = Object.freeze({ type, atMs: Math.floor(config.clock()), ...metadata });
    let result;
    try { result = config.eventSink(event); }
    catch (error) { if (error instanceof OnlineFraWebSocketAdapterError) throw error; fail('ONLINE_FRA_WS_EVENT_SINK'); }
    if (result && typeof result.then === 'function') {
      try { Promise.resolve(result).catch(() => {}); } catch {}
      fail('ONLINE_FRA_WS_EVENT_SINK');
    }
  }
  function reject(socket) { try { socket.destroy(); } catch {} }
  function attestationFor(req) {
    let value;
    try { value = sync(config.verifyProxyRequest(req), 'ONLINE_FRA_WS_PROXY_ASYNC'); }
    catch { return null; }
    if (!plain(value) || value.ok !== true || value.tlsSni !== config.hostname || value.clientVerify !== 'SUCCESS'
      || !SAFE_ID.test(value.deviceId) || !HEX.test(value.fingerprint) || !safeIp(value.ip)) return keyAttestationFor(req);
    return Object.freeze({ mode: 'mtls', deviceId: value.deviceId, fingerprint: value.fingerprint, ip: value.ip });
  }
  // No certificate was presented. If key admission is configured, the socket
  // is accepted PROVISIONALLY: identity is unknown until the possession proof,
  // and the rate-limit slot is keyed on the client IP alone. The IP comes from
  // the proxy (X-Real-IP) -- trustworthy only because this server binds
  // loopback and nothing but nginx reaches it -- or from the socket itself.
  function keyAttestationFor(req) {
    if (!config.keyAdmission) return null;
    let ip = null;
    try { ip = typeof config.clientIpFor === 'function' ? config.clientIpFor(req) : defaultClientIp(req); } catch { ip = null; }
    if (!safeIp(ip)) return null;
    return Object.freeze({ mode: 'key', deviceId: 'pending', fingerprint: '0'.repeat(64), ip });
  }
  function defaultClientIp(req) {
    const header = req && req.headers ? req.headers['x-real-ip'] : undefined;
    if (typeof header === 'string' && safeIp(header.trim())) return header.trim();
    return req && req.socket ? req.socket.remoteAddress : null;
  }
  function admissionSlot(ip) {
    const now = config.clock();
    let state = rate.get(ip);
    if (!state || now - state.windowStart >= config.admissionWindowMs) state = { windowStart: now, admissions: 0, active: state ? state.active : 0 };
    if (state.admissions >= config.maxAdmissionsPerIp || state.active >= config.maxSocketsPerIp) return null;
    state.admissions += 1;
    state.active += 1;
    rate.set(ip, state);
    return state;
  }
  function releaseSlot(ip) {
    const state = rate.get(ip);
    if (!state) return;
    state.active = Math.max(0, state.active - 1);
    if (state.active === 0 && config.clock() - state.windowStart >= config.admissionWindowMs) rate.delete(ip);
  }
  function isOpen(ws) { return ws && (ws.readyState === undefined || ws.readyState === 1); }
  function relayCall(method, ...args) {
    try { return sync(config.relay[method](...args), 'ONLINE_FRA_WS_RELAY_ASYNC'); }
    catch (error) { if (error instanceof OnlineFraWebSocketAdapterError) throw error; fail('ONLINE_FRA_WS_RELAY_FAILED'); }
  }
  function closeRelay(context) {
    if (!context.connectionId || context.relayClosed) return;
    context.relayClosed = true;
    try { relayCall('close', context.connectionId, 'ONLINE_FRA_WS_CONNECTION_CLOSED'); } catch {}
  }
  function closeContext(context, reason, code = 1008, socketAlreadyClosed = false) {
    if (!context || context.cleaned) return;
    context.cleaned = true;
    if (context.timer !== null) config.clearTimer(context.timer);
    live.delete(context);
    releaseSlot(context.attestation.ip);
    closeRelay(context);
    try { emit('online_fra.ws.closed', { reason, session: context.meta }); } catch {}
    if (!socketAlreadyClosed) {
      try { if (context.ws && typeof context.ws.close === 'function') context.ws.close(code); } catch {}
      try {
        if (context.ws && context.ws.readyState !== 3 && typeof context.ws.terminate === 'function') context.ws.terminate();
      } catch {}
    }
  }
  function schedule(context) {
    if (context.cleaned) return;
    context.timer = config.setTimer(() => {
      context.timer = null;
      if (context.cleaned) return;
      const now = config.clock();
      if (!context.admitted && now >= context.admissionDeadline) return closeContext(context, 'admission_timeout');
      if (context.admitted && now - context.lastActivity >= config.idleTimeoutMs) return closeContext(context, 'idle_timeout', 1001);
      if (context.admitted && now - context.lastPing >= config.pingIntervalMs) {
        try { if (typeof context.ws.ping !== 'function') fail('ONLINE_FRA_WS_PING_UNAVAILABLE'); context.ws.ping(); context.lastPing = now; }
        catch { return closeContext(context, 'ping_failed', 1011); }
      }
      if (context.admitted) drain(context);
      schedule(context);
    }, Math.min(config.admissionTimeoutMs, config.pingIntervalMs));
  }
  function refreshPeer(context) {
    const metadata = relayCall('connectionMetadata', context.connectionId);
    if (!plain(metadata) || !Object.hasOwn(metadata, 'peerConnectionId')
      || (metadata.peerConnectionId !== null && !CONNECTION_ID.test(metadata.peerConnectionId))) {
      fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
    }
    context.peerConnectionId = metadata.peerConnectionId;
    if (typeof metadata.endpointRole === 'string') context.role = metadata.endpointRole;
    return context.peerConnectionId !== null;
  }
  function drain(context) {
    if (context.cleaned || !context.admitted || !isOpen(context.ws) || Number(context.ws.bufferedAmount || 0) > config.maxBufferedBytes) return;
    try {
      // refreshPeer() keeps the machine link current for the metadata it
      // reports; its answer no longer gates delivery, because a web endpoint
      // has no machine-peer link and still has frames queued for it.
      refreshPeer(context);
      for (let count = 0; count < config.maxDrainPerTick && Number(context.ws.bufferedAmount || 0) <= config.maxBufferedBytes; count += 1) {
        const frame = relayCall('take', context.connectionId);
        if (frame === null || frame === undefined) return;
        if (!Buffer.isBuffer(frame) || frame.length < 1 || frame.length > config.maxFrameBytes) fail('ONLINE_FRA_WS_RELAY_FRAME_INVALID');
        if (typeof context.ws.send !== 'function') fail('ONLINE_FRA_WS_SEND_UNAVAILABLE');
        context.ws.send(Buffer.from(frame), { binary: true });
      }
    } catch { closeContext(context, 'relay_drain_failed', 1011); }
  }
  function admit(context, data, binary) {
    if (binary || !Buffer.isBuffer(data) || data.length < 1 || data.length > config.maxAdmissionBytes) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
    let parsed;
    try { parsed = JSON.parse(data.toString('utf8')); } catch { fail('ONLINE_FRA_WS_ADMISSION_INVALID'); }
    let connected;
    if (context.attestation.mode === 'key') {
      // The possession proof. Exactly four keys, and the nonce must be the one
      // THIS socket was challenged with -- a valid proof for some other
      // socket's nonce admits nothing here, whatever keyAdmission would say.
      const keys = ['lease', 'publicKeySpki', 'nonce', 'signature'];
      if (!plain(parsed) || Object.keys(parsed).length !== keys.length || keys.some(key => !Object.hasOwn(parsed, key))
        || parsed.lease === null || typeof parsed.nonce !== 'string' || parsed.nonce !== context.challengeNonce) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
      try {
        connected = sync(config.keyAdmission.admit({ lease: parsed.lease, browserPublicKeySpki: parsed.publicKeySpki, nonce: parsed.nonce, signature: parsed.signature }), 'ONLINE_FRA_WS_RELAY_ASYNC');
      } catch (error) { if (error instanceof OnlineFraWebSocketAdapterError) throw error; fail('ONLINE_FRA_WS_ADMISSION_INVALID'); }
      if (!plain(connected) || !CONNECTION_ID.test(connected.connectionId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      // Identity is known now; the session label follows it.
      context.attestation = Object.freeze({ mode: 'key', deviceId: String(parsed.lease.deviceId), fingerprint: String(parsed.lease.mtlsFingerprint), ip: context.attestation.ip });
      context.meta = metadataFingerprint(context.attestation);
      context.role = parsed.lease.endpointRole;
    } else {
      if (!plain(parsed) || Object.keys(parsed).length !== 1 || !Object.hasOwn(parsed, 'lease') || parsed.lease === null) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
      const identity = Object.freeze({ verified: true, authType: 'mtls', deviceId: context.attestation.deviceId, mtlsFingerprint: context.attestation.fingerprint });
      connected = relayCall('connect', { identity, lease: parsed.lease });
      if (!plain(connected) || !CONNECTION_ID.test(connected.connectionId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      context.role = parsed.lease && parsed.lease.endpointRole;
    }

    context.connectionId = connected.connectionId;
    refreshPeer(context);
    // THE ROLE COMES FROM THE RELAY (refreshPeer reads it off the metadata the
    // relay reports for the connection it just admitted); the lease in hand is
    // the fallback for a relay double that reports none. A role the leg table
    // does not know cannot be addressed, so it cannot be admitted.
    if (!Object.hasOwn(LEG_BYTE, context.role)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
    context.admitted = true;
    context.lastActivity = config.clock();
    context.lastPing = context.lastActivity;
    try { emit('online_fra.ws.admitted', { session: context.meta }); }
    catch { closeContext(context, 'event_sink_failed', 1011); return; }
    drain(context);
  }
  function onMessage(context, data, binary) {
    if (context.cleaned) return;
    try {
      context.lastActivity = config.clock();
      if (!context.admitted) return admit(context, data, binary);
      if (!binary || !Buffer.isBuffer(data) || data.length < 2 || data.length > config.maxFrameBytes
        || Number(context.ws.bufferedAmount || 0) > config.maxBufferedBytes) fail('ONLINE_FRA_WS_FRAME_INVALID');
      // The leg byte is the address. Resolve it against the pair's live legs
      // as the relay reports them NOW, not as they were at admission.
      const targetRole = LEG_ROLE[data[0]];
      if (!targetRole || targetRole === context.role) fail('ONLINE_FRA_WS_FRAME_INVALID');
      const metadata = relayCall('connectionMetadata', context.connectionId);
      if (!plain(metadata) || !plain(metadata.legs)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      const targetId = metadata.legs[targetRole];
      if (targetId === null || targetId === undefined) {
        // AN ABSENT LEG IS A NORMAL STATE, NOT A VIOLATION. The peer has not
        // connected yet, or the browser tab is closed. A hello sent a moment
        // early must not cost the sender its socket and a fresh lease; it is
        // dropped, counted, and the sender retries on its own schedule. The
        // relay never delivered it, so nothing sealed went anywhere.
        context.lastActivity = config.clock();
        try { emit('online_fra.ws.frame_dropped', { reason: 'leg_absent', session: context.meta }); } catch {}
        return;
      }
      if (!CONNECTION_ID.test(targetId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      context.peerConnectionId = metadata.peerConnectionId;
      // Stamp the SOURCE leg in place of the target byte: same length, and the
      // receiver learns who sent it without the edge adding a second frame.
      const frame = Buffer.from(data);
      frame[0] = LEG_BYTE[context.role];
      relayCall('route', { connectionId: context.connectionId, peerConnectionId: targetId, frame });
      drain(context);
    } catch { closeContext(context, context.admitted ? 'frame_invalid' : 'admission_failed'); }
  }
  function attach(ws, attestation) {
    const context = { ws, attestation, meta: metadataFingerprint(attestation), timer: null, cleaned: false, admitted: false,
      relayClosed: false, challengeNonce: null, role: null,
      connectionId: null, peerConnectionId: null, admissionDeadline: config.clock() + config.admissionTimeoutMs,
      lastActivity: config.clock(), lastPing: config.clock() };
    live.add(context);
    if (attestation.mode === 'key') {
      // FIRST FRAME FROM THE EDGE: the challenge. The endpoint has until the
      // admission deadline to answer with the proof; an unanswered challenge
      // costs the nonce store one entry for NONCE_TTL_MS and nothing else.
      let issued;
      try { issued = sync(config.keyAdmission.challenge(), 'ONLINE_FRA_WS_RELAY_ASYNC'); }
      catch { return closeContext(context, 'challenge_failed', 1011); }
      if (!plain(issued) || typeof issued.nonce !== 'string' || issued.nonce.length < 16) return closeContext(context, 'challenge_failed', 1011);
      context.challengeNonce = issued.nonce;
      try {
        if (typeof ws.send !== 'function') fail('ONLINE_FRA_WS_SEND_UNAVAILABLE');
        ws.send(JSON.stringify({ challenge: issued.nonce, expiresAtMs: issued.expiresAtMs }));
      } catch { return closeContext(context, 'challenge_failed', 1011); }
    }
    const once = (event, handler) => { if (typeof ws.once === 'function') ws.once(event, handler); else if (typeof ws.on === 'function') ws.on(event, handler); };
    if (typeof ws.on !== 'function') return closeContext(context, 'socket_invalid');
    ws.on('message', (data, binary) => onMessage(context, data, binary));
    ws.on('pong', () => { if (!context.cleaned) context.lastActivity = config.clock(); });
    once('close', () => closeContext(context, 'socket_close', 1000, true));
    once('error', () => closeContext(context, 'socket_error'));
    try { emit('online_fra.ws.connected', { session: context.meta }); }
    catch { return closeContext(context, 'event_sink_failed', 1011); }
    schedule(context);
  }
  function upgrade(req, socket, head) {
    if (!started || !req || req.method !== 'GET' || req.url !== '/v1/rendezvous' || !Buffer.isBuffer(head) || head.length !== 0 || live.size >= config.maxSockets) return reject(socket);
    const attestation = attestationFor(req);
    if (!attestation || !admissionSlot(attestation.ip)) return reject(socket);
    try {
      wss.handleUpgrade(req, socket, head, ws => attach(ws, attestation));
    } catch {
      releaseSlot(attestation.ip);
      reject(socket);
    }
  }
  const api = {
    start() {
      if (!config.enabled || started) return false;
      wss = new config.WebSocketServer({ noServer: true, maxPayload: config.maxFrameBytes, perMessageDeflate: false });
      config.httpServer.on('upgrade', upgrade);
      started = true;
      return true;
    },
    stop() {
      for (const context of [...live]) closeContext(context, 'adapter_stop', 1001);
      if (started) config.httpServer.off('upgrade', upgrade);
      try { if (wss && typeof wss.close === 'function') wss.close(); } catch {}
      wss = null;
      rate.clear();
      started = false;
      return true;
    },
    revoke() { for (const context of [...live]) closeContext(context, 'revoked', 1008); return true; },
    kill() { return this.revoke(); },
    drain() { for (const context of [...live]) drain(context); },
    snapshot() { return Object.freeze({ enabled: config.enabled, started, sockets: live.size, rateEntries: rate.size }); }
  };
  return Object.freeze(api);
}

module.exports = Object.freeze({ DEFAULTS, OnlineFraWebSocketAdapterError, createOnlineFraWebSocketAdapter });
