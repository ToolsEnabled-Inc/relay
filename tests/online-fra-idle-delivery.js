'use strict';
// DELIVERY TO A LEG THAT IS DOING NOTHING, WHICH IS THE ONLY THING A MACHINE
// EVER DOES WHILE IT WAITS FOR WORK.
//
// The rest of this suite proves the edge CARRIES a frame. None of it proves
// WHEN, and the difference was twenty seconds. Routing drained the sender and
// nobody else, so a frame queued for the receiver sat there until the
// receiver's own periodic tick -- min(admissionTimeoutMs, pingIntervalMs), ten
// seconds at the shipped defaults. A person driving their computer from a
// browser would send a request, wait up to ten seconds for it to arrive, and
// up to ten more for the answer, over a tunnel whose actual transit is
// single-digit milliseconds.
//
// Every existing test missed it, and one of them documents why: the real-socket
// test sends its frame, waits 200ms, then calls `adapter.drain()` by hand with
// the comment "the adapter drains on its ping tick or on the next inbound
// frame; nudge it". That nudge is the defect, written down as a convenience.
// The in-process tests miss it for a different reason -- both legs are driven
// by the same synchronous double, so each is drained by its own next send.
//
// So this test refuses both crutches. It runs at the SHIPPED defaults, never
// touches adapter.drain(), and the receiver never sends anything. If delivery
// regresses to the timer, the frame arrives in ten seconds and this fails in
// two.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { WebSocketServer } = require('ws');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
const { createOnlineFraWebSocketAdapter, DEFAULTS } = require('../src/lib/online-fra-websocket-adapter');

let assertions = 0;
const equal = (a, b, m) => { assertions += 1; assert.equal(a, b, m); };
const ok = (v, m) => { assertions += 1; assert.ok(v, m); };

/* Guilty until it finishes: an async test that dies quietly between awaits
   would otherwise exit 0 having proved nothing. */
process.exitCode = 1;

// The same in-memory relay double the real-socket test uses: two connections
// form a pair, route() queues for the peer, take() drains one.
function relayDouble() {
  const connections = new Map();
  const queues = new Map();
  let seq = 0;
  return {
    connect({ identity, lease }) {
      const id = `conn_${++seq}`;
      connections.set(id, { identity, lease });
      queues.set(id, []);
      return { connectionId: id, deviceId: lease.deviceId };
    },
    connectionMetadata(id) {
      const me = connections.get(id);
      const legs = { 'machine-a': null, 'machine-b': null, 'web-client': null };
      for (const [other, c] of connections) if (c.lease.pairId === me.lease.pairId) legs[c.lease.endpointRole] = other;
      const peerRole = me.lease.endpointRole === 'machine-a' ? 'machine-b' : 'machine-a';
      return { peerConnectionId: me.lease.endpointRole === 'web-client' ? null : legs[peerRole], endpointRole: me.lease.endpointRole, legs };
    },
    route({ peerConnectionId, frame }) { queues.get(peerConnectionId).push(Buffer.from(frame)); },
    take(id) { const q = queues.get(id); return q && q.length ? q.shift() : null; },
    close(id) { connections.delete(id); queues.delete(id); },
    snapshot() { return { connections: connections.size }; },
  };
}

function endpoint(role, pairId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    lease: { endpointRole: role, deviceId: `dev-${role}`, pairId, mtlsFingerprint: crypto.createHash('sha256').update(spki).digest('hex') },
    publicKeySpki: spki.toString('base64url'),
    sign: (nonce) => crypto.sign(null, Buffer.from(nonce, 'base64url'), privateKey).toString('base64url'),
  };
}

/* Resolves when the socket is admitted, and thereafter records the arrival
   TIME of every binary frame -- the measurement this file exists to take. */
function connectAndAdmit(url, ep) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const frames = [];
    const arrivedAt = [];
    ws.addEventListener('error', (e) => reject(new Error('socket error: ' + (e.message || e.type))));
    ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        const challenge = JSON.parse(event.data);
        ws.send(JSON.stringify({ lease: ep.lease, publicKeySpki: ep.publicKeySpki, nonce: challenge.challenge, signature: ep.sign(challenge.challenge) }));
        setTimeout(() => resolve({ ws, frames, arrivedAt }), 50);
        return;
      }
      frames.push(Buffer.from(event.data));
      arrivedAt.push(Date.now());
    });
  });
}

/* Waits for one frame, or gives up well before the periodic tick could have
   delivered it. The budget IS the assertion: at the shipped defaults the timer
   fires at 10s, so anything that needs longer than 2s needed the timer. */
function waitForFrame(peer, budgetMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const poll = setInterval(() => {
      if (peer.frames.length > 0 || Date.now() - started > budgetMs) {
        clearInterval(poll);
        resolve(peer.frames.length > 0 ? peer.arrivedAt[0] - started : null);
      }
    }, 5);
  });
}

(async () => {
  const relay = relayDouble();
  const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => Date.now() });
  const httpServer = http.createServer((req, res) => { res.statusCode = 426; res.end(); });

  /* THE SHIPPED NUMBERS, taken from the module's own DEFAULTS rather than
     retyped, so that a future change to them is reflected here instead of
     silently making this test easier. */
  const drainTickMs = Math.min(DEFAULTS.admissionTimeoutMs, DEFAULTS.pingIntervalMs);
  ok(drainTickMs >= 5000,
    `the periodic drain tick is ${drainTickMs}ms; if it ever drops near the budget below, this test stops being able to tell the fix from the timer and must be rewritten rather than retuned`);

  const adapter = createOnlineFraWebSocketAdapter({
    enabled: true, WebSocketServer, httpServer, relay, hostname: 'relay.example.net',
    verifyProxyRequest: () => ({ ok: false }), keyAdmission,
    eventSink: () => {}, clock: () => Date.now(),
    setTimer: (fn, ms) => setTimeout(fn, ms), clearTimer: (id) => clearTimeout(id),
    // admissionTimeoutMs, pingIntervalMs and idleTimeoutMs are left at their
    // shipped defaults ON PURPOSE. Lowering them is how this defect stayed
    // invisible: the real-socket test sets pingIntervalMs to 1000.
  });
  adapter.start();
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const url = `ws://127.0.0.1:${httpServer.address().port}/v1/rendezvous`;

  const sender = await connectAndAdmit(url, endpoint('machine-a', 'pair-idle'));
  const idle = await connectAndAdmit(url, endpoint('machine-b', 'pair-idle'));
  equal(sender.ws.readyState, 1, 'the sender is admitted and open');
  equal(idle.ws.readyState, 1, 'the receiver is admitted and open');

  /* The receiver now does exactly what a machine waiting for work does:
     nothing. No sends, no nudges, no adapter.drain(). */
  const payload = crypto.randomBytes(512);
  sender.ws.send(Buffer.concat([Buffer.from([0x02]), payload]));

  const latency = await waitForFrame(idle, 2000);
  ok(latency !== null,
    `the idle receiver got NOTHING within 2s. Routing drains the sender; if it no longer drains the RECEIVER, the frame waits for that leg's own ${drainTickMs}ms tick -- so a request takes up to ${drainTickMs / 1000}s to arrive and its answer ${drainTickMs / 1000}s more.`);
  ok(latency < 2000, `delivered in ${latency}ms, well inside the ${drainTickMs}ms tick, so it was not the timer that delivered it`);
  equal(idle.frames.length, 1, 'exactly one frame, not a duplicate from a second drain');
  equal(idle.frames[0][0], 0x01, 'stamped with the source leg');
  ok(idle.frames[0].subarray(1).equals(payload), 'payload byte-identical');

  /* AND BACK, because a round trip is what a person actually waits for: the
     answer travels to a sender that has itself gone idle since. */
  const reply = crypto.randomBytes(512);
  idle.ws.send(Buffer.concat([Buffer.from([0x01]), reply]));
  const backLatency = await waitForFrame(sender, 2000);
  ok(backLatency !== null, 'the answer never reached the original sender, which had gone idle waiting for it');
  ok(backLatency < 2000, `the answer came back in ${backLatency}ms`);
  ok(sender.frames[0].subarray(1).equals(reply), 'and it is the reply, byte for byte');

  sender.ws.close(); idle.ws.close();
  adapter.stop();
  await new Promise((r) => httpServer.close(r));
  console.log(`online-fra-idle-delivery: ${assertions} assertions passed (round trip to an idle leg, shipped timings, no manual drain)`);
  process.exitCode = 0;
})().catch((error) => {
  console.error(error);
  /* HARD EXIT, because a failure here leaves two admitted sockets and a
     listening server behind, and node will not leave on its own. The first
     failing run of this file sat for the full five-minute harness timeout
     before anything noticed -- a test that hangs on failure reads as a hung
     suite rather than a red one. */
  process.exit(1);
});
