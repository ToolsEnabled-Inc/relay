'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  DEFAULT_MAX_CERTIFICATE_HEADER_BYTES,
  createOnlineFraProxyAttestationVerifier
} = require('../src/lib/online-fra-proxy-attestation');

let assertions = 0;
const equal = (...args) => { assertions += 1; return assert.equal(...args); };
const ok = (...args) => { assertions += 1; return assert.ok(...args); };
const throws = (run, code) => { assertions += 1; return assert.throws(run, error => error && error.code === code); };

// Public example.com leaf certificate captured only as deterministic test data.
// No private key or credential is present.
const DER_BASE64 = 'MIID5jCCA42gAwIBAgIQBiTQqzEVWHgLfVITuWMYMTAKBggqhkjOPQQDAjBRMQswCQYDVQQGEwJVUzEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMSgwJgYDVQQDDB9DbG91ZGZsYXJlIFRMUyBJc3N1aW5nIEVDQyBDQSAzMB4XDTI2MDcyOTIyMTAwOFoXDTI2MTAyNzIyMTcyMVowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR2Tgmj3bLPRaVN0Vud8FEAUiMz3Z2Bd5lti39uhuvBARyn+R6JJkBCv54dlTizzaUBzLnriaPVW9uysYIJXTVio4ICgDCCAnwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSDA/3n9vVKTRVB9O0iFtMyCj7KZjBsBggrBgEFBQcBAQRgMF4wOQYIKwYBBQUHMAKGLWh0dHA6Ly9pLmNmLWkuc3NsLmNvbS9DbG91ZGZsYXJlLVRMUy1JLUUzLmNlcjAhBggrBgEFBQcwAYYVaHR0cDovL28uY2YtaS5zc2wuY29tMCUGA1UdEQQeMByCC2V4YW1wbGUuY29tgg0qLmV4YW1wbGUuY29tMCMGA1UdIAQcMBowCAYGZ4EMAQIBMA4GDCsGAQQBgqkwAQMBATATBgNVHSUEDDAKBggrBgEFBQcDATBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vYy5jZi1pLnNzbC5jb20vYWU4MDFlZDFjNTViYjU3OWQ3OTIwOGIwZDc3MmFjZmI4Y2MzYTIwOC5jcmwwDgYDVR0PAQH/BAQDAgeAMA8GCSsGAQQBgtpLLAQCBQAwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdwCUTkOH+uzB74HzGSQmqBhlAcfTXzgCAT9yZ31VNy4Z2AAAAZ+v9sM2AAAEAwBIMEYCIQD9WFotRGzWRjLUpKu5UgFVEIW2JB7MtvZe+tocSNgcyQIhAJCFdDoCWE99JjFKSmzjeRhbiH0M3Aw+h414y9bGxT+PAHUAyKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5oAAAGfr/bDTAAABAMARjBEAiAKprPtjMQLlLrSks4eCDoJZ6WqekRLH6AWHSHco9LXtQIgMsRhNtbw0Gp9Q0ItZB5D/0qTzrPKMBDbJZor+NZkce4wCgYIKoZIzj0EAwIDRwAwRAIgELh9REqDsIBMBAkADWsc3iuhbkwHyfcv6w+HsjhdPcwCIDzda23fZzKA2+qG5L/k1ti5g4rk3WiJU0UbvpUGLKKv';
const certificate = new crypto.X509Certificate(Buffer.from(DER_BASE64, 'base64'));
const pem = certificate.toString();
const escaped = encodeURIComponent(pem);
const fingerprint = crypto.createHash('sha256').update(certificate.raw).digest('hex');
const notBeforeMs = Date.parse(certificate.validFrom);
const notAfterMs = Date.parse(certificate.validTo);
const now = Math.floor((notBeforeMs + notAfterMs) / 2);
const socketPath = '/run/fra/rendezvous.sock';

function options(overrides = {}) {
  return {
    enabled: true,
    backendSocketPath: socketPath,
    clock: () => now,
    enrollments: [{ deviceId: 'machine-b', certificateSha256: fingerprint, generation: 7, notBeforeMs, notAfterMs, revoked: false }],
    generation: 7,
    hostname: 'fra-relay.devices.example.net',
    maxCertificateHeaderBytes: DEFAULT_MAX_CERTIFICATE_HEADER_BYTES,
    maxFrameBytes: 262144,
    ...overrides
  };
}
function request(overrides = {}) {
  const headers = {
    host: 'fra-relay.devices.example.net', upgrade: 'websocket', connection: 'upgrade',
    'x-fra-client-verify': 'SUCCESS', 'x-fra-client-certificate': escaped,
    'x-fra-client-address': '203.0.113.10', 'x-fra-max-frame-bytes': '262144'
  };
  Object.assign(headers, overrides.headers || {});
  const rawHeaders = Object.entries(headers).flatMap(([name, value]) => [name, value]);
  return {
    method: 'GET', url: '/v1/rendezvous', headers, rawHeaders,
    socket: { server: { address: () => socketPath } },
    ...overrides, headers, rawHeaders: overrides.rawHeaders || rawHeaders
  };
}

const inert = createOnlineFraProxyAttestationVerifier();
equal(inert(request()), null); equal(inert.snapshot().enabled, false);
throws(() => createOnlineFraProxyAttestationVerifier({ enabled: false, hostname: 'unexpected.example' }), 'ONLINE_FRA_PROXY_OPTIONS_INVALID');
throws(() => createOnlineFraProxyAttestationVerifier(options({ backendSocketPath: '/run/fra/../evil.sock' })), 'ONLINE_FRA_PROXY_OPTIONS_INVALID');
const verify = createOnlineFraProxyAttestationVerifier(options());
const accepted = verify(request());
equal(accepted.ok, true); equal(accepted.deviceId, 'machine-b'); equal(accepted.fingerprint, fingerprint);
equal(accepted.ip, '203.0.113.10'); equal(accepted.tlsSni, 'fra-relay.devices.example.net');
equal(Object.isFrozen(accepted), true); equal(verify.snapshot().enrollments, 1);

for (const bad of [
  { method: 'POST' }, { url: '/v1/rendezvous?x=1' },
  { socket: { server: { address: () => '/run/fra/other.sock' } } },
  { headers: { host: 'attacker.example.net' } }, { headers: { upgrade: 'h2c' } },
  { headers: { 'x-fra-client-verify': 'NONE' } }, { headers: { 'x-fra-max-frame-bytes': '999999' } },
  { headers: { 'x-fra-client-address': 'not-an-ip' } }, { headers: { 'x-fra-client-certificate': '%00' } }
]) equal(verify(request(bad)), null);

{
  const duplicate = request();
  duplicate.rawHeaders.push('X-FRA-Client-Verify', 'SUCCESS');
  equal(verify(duplicate), null);
}
equal(createOnlineFraProxyAttestationVerifier(options({ enrollments: [{ deviceId: 'machine-b', certificateSha256: fingerprint, generation: 7, notBeforeMs, notAfterMs, revoked: true }] }))(request()), null);
equal(createOnlineFraProxyAttestationVerifier(options({ clock: () => notAfterMs }))(request()), null);
equal(createOnlineFraProxyAttestationVerifier(options({ enrollments: [{ deviceId: 'machine-b', certificateSha256: '0'.repeat(64), generation: 7, notBeforeMs, notAfterMs, revoked: false }] }))(request()), null);
throws(() => createOnlineFraProxyAttestationVerifier(options({ enrollments: [
  { deviceId: 'machine-b', certificateSha256: fingerprint, generation: 7, notBeforeMs, notAfterMs, revoked: false },
  { deviceId: 'machine-a', certificateSha256: fingerprint, generation: 7, notBeforeMs, notAfterMs, revoked: false }
] })), 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID');
ok(!JSON.stringify(verify.snapshot()).includes(fingerprint));

console.log(`online FRA proxy attestation tests passed (${assertions} assertions).`);
