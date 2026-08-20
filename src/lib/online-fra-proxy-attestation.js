'use strict';

// Synchronous, disabled-by-default verifier for the trusted Nginx -> FRA Unix
// socket boundary. Nginx supplies the verified leaf certificate, not a claimed
// fingerprint; this module parses the leaf and computes SHA-256 itself before
// mapping it to one fixed, generation-bound device enrollment.
const crypto = require('node:crypto');
const net = require('node:net');

const ROUTE = '/v1/rendezvous';
const SAFE_DEVICE_ID = /^[a-z][a-z0-9_-]{2,95}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SOCKET_PATH = /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.sock$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const MAX_TIMESTAMP = 8_640_000_000_000_000;
const DEFAULT_MAX_CERTIFICATE_HEADER_BYTES = 16 * 1024;
const ENROLLMENT_KEYS = Object.freeze([
  'deviceId', 'certificateSha256', 'generation', 'notBeforeMs', 'notAfterMs', 'revoked'
]);

class OnlineFraProxyAttestationError extends Error {
  constructor(code) { super(code); this.name = 'OnlineFraProxyAttestationError'; this.code = code; }
}
function fail(code) { throw new OnlineFraProxyAttestationError(code); }
function plain(value) {
  try {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
      && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
  } catch { return false; }
}
function exact(value, keys, code) {
  if (!plain(value)) fail(code);
  let actual;
  try { actual = Reflect.ownKeys(value); } catch { fail(code); }
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) fail(code);
  for (const key of actual) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { fail(code); }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(code);
  }
  return value;
}
function integer(value, code, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}
function string(value, code, expression, maximum) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || !expression.test(value)) fail(code);
  return value;
}

function normalizedEnrollment(value, expectedGeneration) {
  const source = exact(value, ENROLLMENT_KEYS, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID');
  const generation = integer(source.generation, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID', 1);
  const notBeforeMs = integer(source.notBeforeMs, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID', 1, MAX_TIMESTAMP);
  const notAfterMs = integer(source.notAfterMs, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID', 1, MAX_TIMESTAMP);
  if (generation !== expectedGeneration || notAfterMs <= notBeforeMs || typeof source.revoked !== 'boolean') {
    fail('ONLINE_FRA_PROXY_ENROLLMENT_INVALID');
  }
  return Object.freeze({
    deviceId: string(source.deviceId, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID', SAFE_DEVICE_ID, 96),
    certificateSha256: string(source.certificateSha256, 'ONLINE_FRA_PROXY_ENROLLMENT_INVALID', SHA256, 64),
    generation, notBeforeMs, notAfterMs, revoked: source.revoked
  });
}

function singleHeader(request, name) {
  try {
    const value = request.headers && request.headers[name];
    if (typeof value !== 'string' || !Array.isArray(request.rawHeaders) || request.rawHeaders.length % 2 !== 0) return null;
    let count = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (typeof request.rawHeaders[index] !== 'string' || typeof request.rawHeaders[index + 1] !== 'string') return null;
      if (request.rawHeaders[index].toLowerCase() === name) count += 1;
    }
    return count === 1 ? value : null;
  } catch { return null; }
}

function certificateFromEscapedHeader(value, maximumBytes) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value, 'utf8') > maximumBytes) return null;
  let pem;
  try { pem = decodeURIComponent(value); } catch { return null; }
  if (Buffer.byteLength(pem, 'utf8') > maximumBytes || pem.includes('\0')
      || !pem.startsWith('-----BEGIN CERTIFICATE-----') || !pem.trimEnd().endsWith('-----END CERTIFICATE-----')) return null;
  try { return new crypto.X509Certificate(pem); } catch { return null; }
}

function createOnlineFraProxyAttestationVerifier(options = {}) {
  if (!plain(options)) fail('ONLINE_FRA_PROXY_OPTIONS_INVALID');
  const enabled = Object.hasOwn(options, 'enabled') ? options.enabled : false;
  if (enabled !== true && enabled !== false) fail('ONLINE_FRA_PROXY_OPTIONS_INVALID');
  if (!enabled) {
    if (Object.keys(options).some(key => key !== 'enabled')) fail('ONLINE_FRA_PROXY_OPTIONS_INVALID');
    const inert = () => null;
    Object.defineProperty(inert, 'snapshot', { value: () => Object.freeze({ enabled: false, enrollments: 0 }) });
    return Object.freeze(inert);
  }
  exact(options, [
    'enabled', 'backendSocketPath', 'clock', 'enrollments', 'generation', 'hostname',
    'maxCertificateHeaderBytes', 'maxFrameBytes'
  ], 'ONLINE_FRA_PROXY_OPTIONS_INVALID');
  if (typeof options.clock !== 'function' || !Array.isArray(options.enrollments) || options.enrollments.length < 1 || options.enrollments.length > 128) {
    fail('ONLINE_FRA_PROXY_OPTIONS_INVALID');
  }
  const backendSocketPath = string(options.backendSocketPath, 'ONLINE_FRA_PROXY_OPTIONS_INVALID', SOCKET_PATH, 512);
  if (backendSocketPath.split('/').includes('..') || backendSocketPath.includes('//')) fail('ONLINE_FRA_PROXY_OPTIONS_INVALID');
  const generation = integer(options.generation, 'ONLINE_FRA_PROXY_OPTIONS_INVALID', 1);
  const hostname = string(options.hostname, 'ONLINE_FRA_PROXY_OPTIONS_INVALID', HOSTNAME, 253);
  const maxCertificateHeaderBytes = integer(options.maxCertificateHeaderBytes, 'ONLINE_FRA_PROXY_OPTIONS_INVALID', 2048, 64 * 1024);
  const maxFrameBytes = integer(options.maxFrameBytes, 'ONLINE_FRA_PROXY_OPTIONS_INVALID', 1024, 262144);
  const clock = options.clock;
  const enrollments = options.enrollments.map(value => normalizedEnrollment(value, generation));
  if (new Set(enrollments.map(value => value.deviceId)).size !== enrollments.length
      || new Set(enrollments.map(value => value.certificateSha256)).size !== enrollments.length) {
    fail('ONLINE_FRA_PROXY_ENROLLMENT_INVALID');
  }
  const byFingerprint = new Map(enrollments.map(value => [value.certificateSha256, value]));

  function verify(request) {
    try {
      if (!request || request.method !== 'GET' || request.url !== ROUTE) return null;
      const address = request.socket && request.socket.server && typeof request.socket.server.address === 'function'
        ? request.socket.server.address() : null;
      if (address !== backendSocketPath) return null;
      const host = singleHeader(request, 'host');
      const upgrade = singleHeader(request, 'upgrade');
      const connection = singleHeader(request, 'connection');
      const clientVerify = singleHeader(request, 'x-fra-client-verify');
      const escapedCertificate = singleHeader(request, 'x-fra-client-certificate');
      const clientAddress = singleHeader(request, 'x-fra-client-address');
      const frameLimit = singleHeader(request, 'x-fra-max-frame-bytes');
      if (host !== hostname || !/^websocket$/i.test(upgrade || '') || !/^upgrade$/i.test(connection || '')
          || clientVerify !== 'SUCCESS' || frameLimit !== String(maxFrameBytes) || net.isIP(clientAddress || '') === 0) return null;
      const certificate = certificateFromEscapedHeader(escapedCertificate, maxCertificateHeaderBytes);
      if (!certificate || certificate.ca === true) return null;
      const certificateSha256 = crypto.createHash('sha256').update(certificate.raw).digest('hex');
      const enrollment = byFingerprint.get(certificateSha256);
      if (!enrollment || enrollment.revoked || enrollment.generation !== generation) return null;
      const certificateNotBeforeMs = Date.parse(certificate.validFrom);
      const certificateNotAfterMs = Date.parse(certificate.validTo);
      let now;
      try { now = clock(); } catch { return null; }
      if (!Number.isSafeInteger(now) || now < 1 || now > MAX_TIMESTAMP
          || !Number.isSafeInteger(certificateNotBeforeMs) || !Number.isSafeInteger(certificateNotAfterMs)
          || certificateNotBeforeMs !== enrollment.notBeforeMs || certificateNotAfterMs !== enrollment.notAfterMs
          || now < certificateNotBeforeMs || now >= certificateNotAfterMs) return null;
      return Object.freeze({
        ok: true, tlsSni: hostname, clientVerify: 'SUCCESS', deviceId: enrollment.deviceId,
        fingerprint: certificateSha256, ip: clientAddress
      });
    } catch { return null; }
  }
  Object.defineProperty(verify, 'snapshot', {
    value: () => Object.freeze({ enabled: true, enrollments: enrollments.length, generation, hostname, maxFrameBytes })
  });
  return Object.freeze(verify);
}

module.exports = Object.freeze({
  DEFAULT_MAX_CERTIFICATE_HEADER_BYTES, OnlineFraProxyAttestationError,
  createOnlineFraProxyAttestationVerifier
});
