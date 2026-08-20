# The one rule about the two repositories

**The dependency points one way only.**

```
    relay repo   ──reads──▶  engine repo
    (this one)               (toolsenabled-current)

    engine repo  ──────✗──▶  relay repo
```

Both halves are MIT. The rule below is about **loadability**, not licensing: it
predates the decision to publish this half and survives it unchanged, because
what it protects was never the licence.

## Why the direction matters more than it looks

The engine repo must build, test and load **completely by itself**:

- A customer, a contributor, or an auditor may clone only the engine. If any file
  there requires something from here, they get a repo that cannot run — and the
  "the client runs on your machine and needs nothing from us" claim is false in
  the most embarrassing possible way.
- The engine's own publish gate (`tools/check-payload-boundary.mjs`) enforces
  this mechanically. Its rule 4 fails any file classified `open` that contains a
  literal `require()` resolving outside that classification. An edge added in the
  wrong direction turns that gate red.

This repo reading the engine is fine and expected: a developer working on the
relay has both checkouts. A relay-only deployment host does not, which is why
`tests/run.js` excludes the cross-repo test from the default suite — run it with
`npm run test:crossrepo` when both are present.

## Constants that straddle the boundary

These values must agree across the two repos. Nothing enforces that
automatically today — a mismatch shows up as frames being accepted by one side
and refused by the other, at runtime, under load.

| Value | Engine (client) | Relay (server) |
|---|---|---|
| Max wire frame | `online-fra-e2e-session.js` `MAX_FRAME_BYTES` = 256 KiB | `online-fra-websocket-adapter.js` `DEFAULTS.maxFrameBytes` = 262144; `online-fra-nginx-config.js` `websocketFrameLimitBytes` max 262144; `online-fra-proxy-attestation.js` `maxFrameBytes` range 1024–262144 |
| Max plaintext | `MAX_PLAINTEXT_BYTES` = 190 KiB | — (relay never sees plaintext) |
| Rendezvous route | — | `/v1/rendezvous`, repeated in the adapter, the attestation verifier and the nginx renderer |

Note the relay core's own `DEFAULT_MAX_FRAME_BYTES` is **64 KiB**, well under the
edge's 256 KiB. That is intentional layering, not a bug: the edge bounds what it
will read off a socket, the core bounds what it will queue. Do not "fix" one to
match the other without reading both.

## The lease word means two different things

Both halves use the word "lease" for different structures. They are not
interchangeable and they do **not** need to agree:

- **Engine, `online-fra-e2e-session.js`**: a 13-key lease in the
  `ToolsEnabled/online-fra/v1/lease` domain, signed by the *device* key, roles
  `A`/`B`. It is part of the end-to-end handshake and the relay never inspects it.
- **Relay, `online-fra-rendezvous-relay.js`**: a 14-key `online-fra-lease.v1`,
  signed by an *authority* key, roles `machine-a`/`machine-b`, carrying an mTLS
  fingerprint. It is the admission ticket and the endpoint never seals with it.

Anyone touching either one should read this paragraph first. The names collide;
the schemas do not.
