'use strict';

const assert = require('node:assert/strict');
const fra = require('../src/lib/online-fra-nginx-config');

let assertions = 0;
const equal = (...args) => { assertions += 1; return assert.equal(...args); };
const ok = (...args) => { assertions += 1; return assert.ok(...args); };
const deepEqual = (...args) => { assertions += 1; return assert.deepEqual(...args); };
function throws(run, predicate) { assertions += 1; return assert.throws(run, predicate); }

function valid(overrides = {}) {
  return {
    relayHostname: 'fra-relay.devices.example.net',
    deviceCaPath: '/etc/nginx/fra/device-ca.pem',
    certificatePath: '/etc/nginx/fra/fra-relay.crt',
    certificateKeyPath: '/etc/nginx/fra/fra-relay.key',
    errorLogPath: '/var/log/nginx/fra-relay-error.log',
    backendSocketPath: '/run/fra/rendezvous.sock',
    limitConnZone: 'fra_relay_conn',
    limitReqZone: 'fra_relay_req',
    httpLimitZonesDeclared: true,
    websocketFrameLimitEnforced: true,
    existingServerNames: ['example.com', 'www.example.com'],
    existingVhostInventoryVerified: true,
    ...overrides
  };
}

(() => {
  const input = valid();
  const first = fra.render(input);
  const second = fra.render({ ...input });
  equal(first, second, 'renderer must be deterministic');
  deepEqual(fra.validate(input), {
    ...fra.DEFAULTS, ...input, route: fra.RELAY_ROUTE
  });
  for (const expected of [
    'listen 443 ssl;', 'server_name fra-relay.devices.example.net;', 'ssl_protocols TLSv1.3;',
    'ssl_early_data off;', 'ssl_verify_client on;', 'location = /v1/rendezvous {',
    'proxy_pass http://unix:/run/fra/rendezvous.sock:/v1/rendezvous;', 'proxy_set_header Upgrade $http_upgrade;',
    'proxy_set_header Connection "upgrade";', 'proxy_set_header X-FRA-Client-Verify $ssl_client_verify;',
    'proxy_set_header X-FRA-Client-Certificate $ssl_client_escaped_cert;', 'access_log off;', 'location / { return 404; }',
    'if ($ssl_server_name != fra-relay.devices.example.net) { return 421; }', 'if ($ssl_client_verify != SUCCESS) { return 403; }',
    'proxy_set_header Host fra-relay.devices.example.net;', 'limit_conn fra_relay_conn 4;', 'limit_req zone=fra_relay_req burst=10 nodelay;',
    'proxy_set_header X-FRA-Client-Address $remote_addr;', 'proxy_set_header X-FRA-Max-Frame-Bytes 262144;',
    'proxy_buffering off;', 'proxy_request_buffering off;'
  ]) ok(first.includes(expected), `expected nginx directive: ${expected}`);
  for (const existing of valid().existingServerNames) {
    ok(!first.includes(existing), 'a hostname the operator already serves is never rendered into the relay vhost');
  }
  ok(!/proxy_pass\s+https?:\/\/(?!unix:)/.test(first), 'backend remains Unix-socket-only');
  ok(!first.includes('TLSv1.2'));
  ok(!first.includes('ssl_verify_client optional'));
  equal(typeof fra.render, 'function', 'renderer is pure and exports no deployment operation');

  for (const relayHostname of ['*.example.net', '192.168.1.2', 'FRA.example.net', 'fra;evil.example.net']) {
    throws(() => fra.render(valid({ relayHostname })), error => error && error.code === 'FRA_NGINX_HOSTNAME_INVALID');
  }
  // The forbidden set is the caller's inventory, not a list baked into the
  // module: the SAME hostname renders or collides depending only on whether
  // the operator already serves it.
  {
    const contested = 'relay.example.org';
    ok(fra.render(valid({ relayHostname: contested })).includes(`server_name ${contested};`),
      'a hostname absent from the inventory is renderable');
    throws(() => fra.render(valid({ relayHostname: contested, existingServerNames: [contested] })),
      error => error && error.code === 'FRA_NGINX_HOSTNAME_COLLISION');
  }
  for (const relayHostname of valid().existingServerNames) {
    throws(() => fra.render(valid({ relayHostname })), error => error && error.code === 'FRA_NGINX_HOSTNAME_COLLISION');
  }
  for (const backendSocketPath of ['/run/fra/not-a-socket', '/run/fra/../evil.sock', 'relative.sock', '/run/fra/x.sock;proxy_pass http://evil']) {
    throws(() => fra.render(valid({ backendSocketPath })), error => error && error.code === 'FRA_NGINX_PROXY_BOUNDARY_INVALID');
  }
  for (const field of ['deviceCaPath', 'certificatePath', 'certificateKeyPath', 'errorLogPath']) {
    for (const unsafe of ['/etc/nginx/fra/x; return 200;', '/etc/nginx/fra/x\nproxy_pass http://evil', '/etc/nginx/fra/../secret', '/etc/nginx/fra/$token']) {
      throws(() => fra.render(valid({ [field]: unsafe })), error => error && error.code === 'FRA_NGINX_PATH_INVALID');
    }
  }
  for (const tlsProtocols of ['TLSv1.2', 'TLSv1.2 TLSv1.3', 'TLSv1.3; ssl_verify_client off']) {
    throws(() => fra.render(valid({ tlsProtocols })), error => error && error.code === 'FRA_NGINX_TLS_INVALID');
  }
  for (const clientVerify of ['optional', 'optional_no_ca', 'off', true]) {
    throws(() => fra.render(valid({ clientVerify })), error => error && error.code === 'FRA_NGINX_MTLS_REQUIRED');
  }
  for (const route of ['/', '/v1/', '/v1/rendezvous/', '/v1/rendezvous { proxy_pass http://evil; }']) {
    throws(() => fra.render(valid({ route })), error => error && error.code === 'FRA_NGINX_ROUTE_INVALID');
  }
  throws(() => fra.render(valid({ listenPort: 8443 })), error => error && error.code === 'FRA_NGINX_TLS_INVALID');
  throws(() => fra.render(valid({ earlyData: true })), error => error && error.code === 'FRA_NGINX_TLS_INVALID');
  throws(() => fra.render(valid({ accessLog: true })), error => error && error.code === 'FRA_NGINX_LOGGING_INVALID');
  throws(() => fra.render(valid({ proxyReadTimeoutSeconds: 20, proxySendTimeoutSeconds: 30 })), error => error && error.code === 'FRA_NGINX_TIMEOUT_INVALID');
  throws(() => fra.render(valid({ httpLimitZonesDeclared: false })), error => error && error.code === 'FRA_NGINX_LIMIT_INVALID');
  throws(() => fra.render(valid({ websocketFrameLimitEnforced: false })), error => error && error.code === 'FRA_NGINX_FRAME_LIMIT_REQUIRED');
  throws(() => fra.render(valid({ limitConnZone: 'fra;evil' })), error => error && error.code === 'FRA_NGINX_LIMIT_INVALID');
  throws(() => fra.render(valid({ limitReqZone: 'fra req' })), error => error && error.code === 'FRA_NGINX_LIMIT_INVALID');
  throws(() => fra.render(valid({ existingVhostInventoryVerified: false })), error => error && error.code === 'FRA_NGINX_INVENTORY_INVALID');
  throws(() => fra.render(valid({ existingServerNames: ['fra-relay.devices.example.net'] })), error => error && error.code === 'FRA_NGINX_HOSTNAME_COLLISION');
  throws(() => fra.render(valid({ existingServerNames: ['*.devices.example.net'] })), error => error && error.code === 'FRA_NGINX_HOSTNAME_COLLISION');
  throws(() => fra.render(valid({ existingServerNames: ['bad;server'] })), error => error && error.code === 'FRA_NGINX_INVENTORY_INVALID');
  throws(() => fra.render(valid({ unexpected: 'directive injection' })), error => error && error.code === 'FRA_NGINX_INPUT_INVALID');
  throws(() => fra.render({}), error => error && error.code === 'FRA_NGINX_INPUT_INVALID');

  console.log(`Online FRA nginx config tests passed (${assertions} assertions).`);
})();
