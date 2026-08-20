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
const { createOnlineFraRelayService } = require('../src/lib/online-fra-relay-service');

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

service.start().then(({ controlPort }) => {
  const snapshot = service.relay.snapshot();
  console.error('online-fra-relay-service up');
  console.error(`  control        : 127.0.0.1:${controlPort} (Bearer token from file)`);
  console.error(`  generation     : ${snapshot.generation}   pairs ${snapshot.pairCount}/${snapshot.maxPairs}`);
  console.error('  admission      : ASK -- account database read-only, fail closed');
  console.error('  event sink     : metadata-only, O(1), no identifiers retained');
  console.error('  NOT YET SERVED : the websocket edge binds when the nginx vhost and');
  console.error('                   device CA exist (provisioning); admission and control');
  console.error('                   are complete without it.');
}).catch(error => {
  console.error(`REFUSED AT START: ${error.code || error.message}`);
  process.exit(1);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => { service.stop().then(() => process.exit(0)); });
}
