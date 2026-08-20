#!/usr/bin/env node
'use strict';

// The production entrypoint: node bin/online-fra-relay-service.js <config.json>
//
// The config file carries PATHS, never secrets inline: the control token and
// the authority public key are read from root-only files it names. The boot
// banner states what is running and what is refused, in the account service's
// own read-the-banner tradition. This file may log; the relay CORE may not
// (its no-logging test greps the core, not this shell).

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { createOnlineFraRelayService } = require('../src/lib/online-fra-relay-service');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
const { createOnlineFraWebSocketAdapter } = require('../src/lib/online-fra-websocket-adapter');

const configPath = process.argv[2];
if (!configPath) {
  console.error('usage: online-fra-relay-service <config.json>');
  process.exit(2);
}

let fileConfig;
try { fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')); }
catch (error) {
  console.error(`Unreadable config at ${configPath}: ${error.message}`);
  process.exit(2);
}

function readNamedFile(key) {
  const named = fileConfig[key];
  if (typeof named !== 'string' || named.length === 0) {
    console.error(`${key} must name a file.`);
    process.exit(2);
  }
  try { return fs.readFileSync(path.resolve(path.dirname(configPath), named), 'utf8').trim(); }
  catch (error) {
    console.error(`Unreadable ${key} (${named}): ${error.message}`);
    process.exit(2);
  }
}

const service = (() => {
  try {
    return createOnlineFraRelayService({
      accountDbPath: fileConfig.accountDbPath,
      leaseStatePath: fileConfig.leaseStatePath,
      authorityPublicKeyPem: readNamedFile('authorityPublicKeyPemPath'),
      generation: fileConfig.generation,
      maxPairs: fileConfig.maxPairs,
      control: {
        host: fileConfig.controlHost,
        port: fileConfig.controlPort,
        token: readNamedFile('controlTokenPath')
      }
    });
  } catch (error) {
    console.error(`REFUSED: ${error.code || 'RELAY_SERVICE_INVALID'} -- ${error.message}`);
    process.exit(2);
  }
})();

// THE EDGE, when the config names one. Behind nginx, which terminates TLS for
// the relay hostname and proxies /v1/rendezvous here over loopback HTTP with
// the client address in X-Real-IP. Admission is by key possession for every
// role (see online-fra-web-admission.js); the mTLS verifier stays available
// for a deployment that chooses to run it, and is inert when `edge.mtls` is
// absent. `ws` is the one dependency, required only on this path, so a
// control-only deployment still loads with nothing installed.
//
//   "edge": { "listenHost": "127.0.0.1", "listenPort": 4821,
//             "hostname": "relay.example.net" }
function startEdge() {
  const edge = fileConfig.edge;
  if (edge === undefined || edge === null) return Promise.resolve(null);
  if (typeof edge !== 'object' || Array.isArray(edge)) { console.error('REFUSED: edge must be an object.'); process.exit(2); }
  const listenHost = edge.listenHost || '127.0.0.1';
  if (listenHost !== '127.0.0.1' && listenHost !== '::1') {
    console.error('REFUSED: edge.listenHost must be loopback. TLS and the public address are nginx\'s; this process never faces the internet directly.');
    process.exit(2);
  }
  const listenPort = Number.isInteger(edge.listenPort) ? edge.listenPort : 4821;
  let WebSocketServer;
  try { ({ WebSocketServer } = require('ws')); }
  catch {
    console.error('REFUSED: the edge needs the `ws` package (MIT). Install it beside this tree: npm install --omit=dev');
    process.exit(2);
  }
  const httpServer = http.createServer((req, res) => {
    // Only upgrades are served. A plain request gets a plain answer that names
    // nothing about the relay's state.
    res.statusCode = 426; res.setHeader('content-type', 'text/plain'); res.end('upgrade required');
  });
  const keyAdmission = createOnlineFraWebAdmission({ relay: service.relay, clock: () => Date.now() });
  const adapter = createOnlineFraWebSocketAdapter({
    enabled: true,
    WebSocketServer,
    httpServer,
    relay: service.relay,
    hostname: edge.hostname,
    // No certificate path in this deployment: every request falls through to
    // key admission. A deployment that terminates mTLS supplies a real
    // verifier here instead.
    verifyProxyRequest: () => ({ ok: false }),
    keyAdmission,
    eventSink: service.metadataSink.sink,
    clock: () => Date.now(),
    setTimer: (fn, ms) => setTimeout(fn, ms),
    clearTimer: id => clearTimeout(id),
    maxSockets: Number.isInteger(edge.maxSockets) ? edge.maxSockets : 64
  });
  adapter.start();
  return new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(listenPort, listenHost, () => resolve({ listenHost, listenPort, hostname: edge.hostname, adapter }));
  });
}

service.start().then(async ({ controlPort }) => {
  const edge = await startEdge();
  const snapshot = service.relay.snapshot();
  console.error('online-fra-relay-service up');
  console.error(`  control        : 127.0.0.1:${controlPort} (Bearer token from file)`);
  console.error(`  generation     : ${snapshot.generation}   pairs ${snapshot.pairCount}/${snapshot.maxPairs}`);
  console.error('  admission      : ASK -- account database read-only, fail closed');
  console.error('  event sink     : metadata-only, O(1), no identifiers retained');
  if (edge) {
    console.error(`  edge           : ${edge.listenHost}:${edge.listenPort} for ${edge.hostname} -- behind nginx TLS`);
    console.error('  edge admission : key possession (signed nonce) for web and machine roles');
  } else {
    console.error('  NOT YET SERVED : no edge configured -- add "edge" to the config to bind');
    console.error('                   the websocket edge behind nginx; admission and control');
    console.error('                   are complete without it.');
  }
}).catch(error => {
  console.error(`REFUSED AT START: ${error.code || error.message}`);
  process.exit(1);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => { service.stop().then(() => process.exit(0)); });
}
