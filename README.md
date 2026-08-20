# ToolsEnabled relay

The server-side half of ToolsEnabled: a rendezvous relay that verifies signed
short leases, pairs exactly two endpoints, and forwards sealed frames it cannot
read.

**MIT licensed, and self-hosting it is supported.** The client half —
everything that runs on a customer's own machine — is licensed the same way and
is released from the engine repository; if you are reading this before that
repository is up, this half stands on its own and the protocol it speaks is
described below. A customer who connects their own server pays nothing and needs
nothing from us. Paying buys our *operating* this, not access to it.

## The deployment shape: co-located with the account service

The relay runs as a **second unit beside the account service, on the same box**.
That is not a packaging convenience; two things in the code assume it:

- **The control channel is loopback-only by construction.** `control.host` is
  refused unless it is `127.0.0.1` or `::1`, so the calls that register pairs on
  enrolment, cut live connections on removal, and reach the durable pair record
  on account deletion can only come from a process on the same machine.
- **The account database is opened read-only from the local filesystem.**
  Admission — *may these two devices pair?* — is one synchronous `SELECT`
  against the account service's own SQLite file, opened `readOnly: true` so this
  process cannot hold a write lock even by accident. It fails closed: an
  unreadable database refuses admission rather than guessing.

So a self-hoster runs this next to whatever issues its leases and owns its device
records, and gives the relay its own DNS name — the vhost renderer refuses a
hostname the box already serves rather than quietly taking over a live site.

There is no telemetry to switch off. The optional connection-outcome reporter is
inert unless a `report` block is configured, which the entrypoint never sets.

## What is in here

| Module (`src/lib/`) | Lines | What it does |
|---|---:|---|
| `online-fra-rendezvous-relay.js` | 752 | The relay state machine: verifies signed short leases, pairs exact endpoints, forwards opaque frames with per-connection/device/pair backpressure. The hardest engineering in the product. |
| `online-fra-sqlite-lease-state.js` | 564 | The durable authority for pair generation and nonce consumption. The relay deliberately has **no** in-memory replay fallback, so this adapter is the anti-replay boundary. |
| `online-fra-relay-service.js` | 433 | The service shell that composes the rest: lease state → metadata sink → relay → optional websocket edge, plus the loopback control channel and the read-only admission check above. |
| `online-fra-nginx-deployment-verifier.js` | 418 | Gates the relay's nginx deployment against signed backend capability, socket-ownership and certificate-identity attestations. |
| `online-fra-websocket-adapter.js` | 241 | The TLS edge: binds `upgrade` on an already-bound HTTPS server, enforces per-IP admission rate limits, ping/idle timeouts and buffered-byte ceilings. |
| `online-fra-nginx-config.js` | 223 | Renders the relay's mTLS vhost. A pure renderer, but it *is* the deployment shape. |
| `online-fra-proxy-attestation.js` | 163 | Verifies the trusted nginx → relay Unix-socket boundary by parsing the leaf certificate itself. |
| `online-fra-web-admission.js` | 109 | Admission for the browser role, which cannot present a client certificate: nonce challenge, WebCrypto signature, fingerprint checked against the lease. A leaked lease without the browser's key admits nothing. |
| `online-fra-metadata-sink.js` | 108 | The component the privacy claim actually rests on. Every event is read, counted and dropped: no identifier is stored, nothing is durable. |

Total: **3,011 lines**, plus a 79-line entrypoint in `bin/`.

Every one of these imports only Node built-ins (`node:crypto`, `node:net`,
`node:fs`, `node:path`, `node:sqlite`). There is no dependency on the engine and
there must never be one — see `docs/CROSS-REPO.md`.

## Where the sealing lives, and why the relay cannot read your traffic

`online-fra-e2e-session.js` — the end-to-end sealing endpoint — is in the engine
repository rather than here, because it runs on the customer's machines at
**both** ends (roles A and B are both theirs). It performs the X25519 handshake
and the AES-256-GCM sealing whose ciphertext this relay forwards. The relay holds
no key material for those frames and contains no code that could use one; it
routes by pair, never by content.

Both halves being readable is what makes that checkable instead of something you
have to take on trust.

## Running it

```
node bin/online-fra-relay-service.js <config.json>
```

The config carries **paths, never inline secrets**: the control token and the
lease authority's public key are read from the files it names. The boot banner
states what is running and what is refused.

## Tests

```
npm test                 # 9 relay test files, isolated processes
npm run test:crossrepo   # needs the engine checkout beside this one
```

`npm test` is self-contained. `npm run test:crossrepo` proves the engine's hosted
entitlement gate is a real drop-in for this relay; it **refuses** (exit 2) rather
than skipping when the engine checkout is absent.
