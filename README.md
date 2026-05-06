# Veil

> An end-to-end encrypted messenger that takes itself a little less seriously
> than Signal — but its math seriously.

Veil is a small, opinionated experiment in zero-knowledge messaging. There are
no phone numbers, no email addresses, and no usernames. Your identity is a
12-word recovery phrase, just like a Bitcoin wallet. The relay can never read
what you send, and never learns who you are beyond a public address — and with
**sealed sender** envelopes, the relay cannot cryptographically identify the
sender from envelope contents.

### What Veil is for

- Private communication between parties who can compare a safety number
  out-of-band at least once
- Strong cryptographic transport: confidentiality, forward secrecy,
  post-compromise security, sealed sender
- Keeping the relay operator blind to message content and sender identity
- Reducing message-length metadata via fixed-bucket padding

### What Veil is NOT for

- **Whistleblowing or source protection** — no anonymity layer, no cover
  traffic, sender IP is visible to the relay
- **Nation-state adversaries** — classical primitives only, no post-quantum
  security, timing correlation is not addressed
- **Operational security tradecraft** — non-repudiable Ed25519 signatures on
  every message; transcripts are cryptographic evidence
- **Coercion resistance** — vault passphrase opens everything; no duress mode
- **Malware resistance** — any malware with process-memory access on an
  unlocked device has the keys; this is true of Signal Desktop too
- **Anonymous communication** — the relay sees recipient address and
  connection timing; only the sender's address is hidden from the relay

For high-stakes threat models, use [Signal](https://signal.org),
[Briar](https://briarproject.org), or [Cwtch](https://cwtch.im).

This repo contains:

- **`artifacts/veil/`** — a React + Vite web client, dark-themed, Telegram-ish.
- **`artifacts/api-server/`** — an Express + WebSocket relay (`/ws` route),
  with Postgres-backed bundle/queue storage.
- **`lib/crypto-core/`** — all cryptography (pure TypeScript, no DOM deps —
  runs identically in the browser and in Node).
- **`lib/db/`** — Drizzle schema + Postgres client shared by the relay.
- **`scripts/src/veil-cli.ts`** — a Node.js CLI client that speaks the same
  wire protocol as the browser.

> **Disclaimer.** Veil is a research-grade, unaudited project. Do not use it
> for anything where being wrong about cryptography would put you in jail, in
> danger, or in a divorce court. For real threat models, use
> [Signal](https://signal.org).

---

## Quick start

```bash
pnpm install
pnpm --filter @workspace/api-server run dev   # relay on :8080
pnpm --filter @workspace/veil run dev         # web on :PORT
```

Open the web client. The first run will:

1. Generate a fresh 12-word phrase (BIP39, English, 128 bits of entropy).
2. Optionally accept an extra "BIP39 passphrase" — a 25th-word secret that
   must be combined with the phrase to recover your identity.
3. Derive your long-term Ed25519 + X25519 keypairs from it.
4. Mint a signed prekey (SPK) and a pool of 30 one-time prekeys (OPKs).
5. Ask for a local passphrase, which seals an Argon2id-encrypted vault into
   IndexedDB. **IndexedDB is required** — the app refuses to save to
   `localStorage` because it is synchronously readable by any same-origin
   script. If IndexedDB is unavailable (e.g. private-browsing mode), saving
   will fail with an actionable error asking you to open a regular window.

Share the `veil1…` address from your profile with someone else; they can add
you and message you instantly.

### Linked devices

Restoring on a second device with the same phrase **and the same device number**
(0) gives you the same address — but two devices racing to consume OPKs cause
delivery glitches. Instead, pick a new device number (1, 2, …) when restoring
on each additional device. Each device gets its own sub-identity (a different
`veil1…` address) derived from the same phrase via HKDF; senders choose the
device they are addressing. Message history is never synced through the relay.

### CLI

```bash
pnpm --filter @workspace/scripts run veil init           # create identity
pnpm --filter @workspace/scripts run veil restore        # restore from phrase
pnpm --filter @workspace/scripts run veil whoami         # show your address
pnpm --filter @workspace/scripts run veil devices        # list sub-identities
pnpm --filter @workspace/scripts run veil add bob veil1...
pnpm --filter @workspace/scripts run veil send bob "hi"
pnpm --filter @workspace/scripts run veil listen         # stream incoming
```

The CLI uses `~/.veil/vault.json` (override with `VEIL_HOME`) and connects to
`ws://localhost:8080/ws` (override with `VEIL_RELAY`). The browser and CLI
speak the same wire protocol and use the same relay — you can chat between
them.

---

## Cryptography

| Layer | Primitive |
|---|---|
| Identity signatures | Ed25519 |
| Identity key exchange | X25519 |
| Mnemonic | BIP39 — 12 words, English, 128 bits of entropy + optional 25th-word passphrase |
| Sub-identity derivation | HKDF-SHA-256 over `BIP39_seed ‖ "veil/sub/v1" ‖ device_index` |
| Address | `veil1` + base32(SHA-256(edPub ‖ xPub)[0..20]) |
| Signed prekey (SPK) | X25519, Ed25519-signed by identity key; rotated every 7 days |
| One-time prekeys (OPK) | X25519, Ed25519-signed; pool of 30, refilled when < 10 remain |
| Initial key agreement | X3DH-lite — 4 Diffie-Hellman inputs (eph↔I_R, eph↔SPK_R, I_S↔SPK_R, eph↔OPK_R) |
| Ongoing key agreement | Double Ratchet — symmetric-key ratchet + DH ratchet per message |
| Post-compromise security | DH ratchet step on every reply heals a compromised state |
| KDF | HKDF-SHA-256 |
| Bulk encryption | AES-256-GCM, 12-byte random nonce |
| Sealed sender (outer) | Ephemeral X25519 DH → HKDF → AES-256-GCM over the inner envelope |
| Anti-spam | Per-envelope SHA-256 proof-of-work, default 14 leading-zero bits (≈ 100 ms) |
| Anti-replay | 5-minute relay-side replay window keyed on SHA-256(outer fields) |
| Message-length hiding | Plaintext padded to fixed buckets: 128 B, 512 B, 2 KB, 8 KB, 32 KB, 128 KB |
| Safety numbers | SHA-256(sort(edPub_A, edPub_B)) displayed as groups of digits |
| Local vault | Argon2id (m=64 MiB, t=3, p=1) → AES-256-GCM, stored in IndexedDB |

All primitives come from `@noble/curves`, `@noble/ciphers`, `@noble/hashes`,
and `hash-wasm`. Pure JavaScript, zero native modules, identical behaviour in
the browser and in Node.

---

## Wire protocol

### Outer envelope (v2 — relay-visible)

The relay only ever sees:

```jsonc
{
  "v":     2,
  "to":    "veil1…",       // recipient address (32-char base32, veil1 prefix)
  "ek":    "<base64url>",  // outer ephemeral X25519 public key — 32 bytes
  "nonce": "<base64url>",  // outer AES-GCM nonce — 12 bytes
  "ct":    "<base64url>",  // outer ciphertext (encrypts the inner envelope)
  "ts":    1714000000000,  // Unix ms — must be within ±5 min of relay wall clock
  "pow":   "<base64url>"   // SHA-256 PoW nonce — 8 bytes
}
```

`ct` decrypts under a key derived from an ephemeral X25519 ↔ recipient identity
DH. The relay never touches the inner layer.

The relay validates every binary field before accepting an envelope: `ek` must
decode to 32 bytes, `nonce` to 12 bytes, `pow` to 8 bytes, and `ct` must
decode to between 128 bytes and 140 KB. Structurally malformed envelopes are
rejected before the PoW check.

### Inner envelope (v3 — Double Ratchet layer)

```jsonc
{
  "v":      3,
  "to":     "veil1…",
  "from":   "veil1…",      // real sender address — invisible to the relay
  "fromEd": "<base64url>", // sender Ed25519 public key
  "x3dh": {               // present only on the first message in a session
    "fromX":    "<base64url>", // sender X25519 identity key
    "ek":       "<base64url>", // X3DH ephemeral key
    "spkId":    "…",
    "prekeyId": "…"            // omitted when no OPK was available
  },
  "dr": {
    "dh": "<base64url>",   // sender's current Double Ratchet public key
    "pn": 0,               // messages sent in the previous sending chain
    "n":  0                // message number in the current sending chain
  },
  "nonce": "<base64url>",
  "ct":    "<base64url>",  // AES-256-GCM over padded plaintext
  "sig":   "<base64url>",  // Ed25519 over domain‖from‖to‖ts‖dr‖SHA-256(ct)
  "ts":    1714000000000
}
```

`x3dh` is only present on session-opening messages; subsequent messages carry
only the DR header. The recipient verifies the Ed25519 signature *before*
advancing any ratchet state or touching session storage, then clones the
session state before attempting decryption so that a bad message cannot
corrupt a valid session.

### Relay validation pipeline (in order)

1. Address format — `veil1` prefix, 32 base32 chars
2. Envelope version — must be `v: 2`
3. Recipient address — same regex
4. Timestamp skew — must be within ±5 min of relay wall clock
5. Binary field validation — `ek` (32 B), `nonce` (12 B), `pow` (8 B), `ct` (128 B–140 KB), all valid base64url
6. Proof-of-work — must have ≥ N leading-zero bits (default 14)
7. Replay check — outer SHA-256 must not appear in the 5-min window
8. DB enqueue

---

## Local vault

```jsonc
{
  "v":     1,
  "kdf":   { "alg": "argon2id", "salt": "…", "memMiB": 64, "iterations": 3, "parallelism": 1 },
  "nonce": "<base64url>",
  "ct":    "<base64url>"  // AES-256-GCM(JSON.stringify(VaultData))
}
```

`VaultData` (v3) contains: serialized identity (device index, BIP39 passphrase
flag), current + previous signed prekeys, OPK pool, contacts, message history,
per-contact Double Ratchet session state, and per-contact last-read timestamps.
Nothing readable is ever written to disk.

The vault lives in IndexedDB (`veil-secure-v1`). A lightweight `localStorage`
marker enables a synchronous `hasVault()` check at startup without touching
IndexedDB.

**Storage hardening:** `saveVaultBlob` writes exclusively to IndexedDB.
Falling back to `localStorage` is intentionally refused — `localStorage` is
synchronously readable by any same-origin script, which is an unacceptable
exposure for an encrypted vault blob. If IndexedDB is unavailable, the save
throws with a clear error message. The legacy `localStorage` read path is
retained only to migrate vaults created by older versions of the app; once
migrated, all subsequent saves go to IndexedDB.

**Persist-before-ACK:** after decrypting and advancing the Double Ratchet, the
client writes the updated session state to the vault and awaits confirmation
before sending an `ack` to the relay. If the write fails, the relay re-delivers
on the next connection. This guarantees the ratchet state and the relay queue
are never permanently out of sync.

---

## Relay storage

Bundles, OPKs, and pending envelopes live in Postgres (`relay_bundles`,
`relay_prekeys`, `relay_envelopes`). OPK consumption uses
`SELECT … FOR UPDATE SKIP LOCKED` then `DELETE`, so two concurrent senders can
never claim the same key. Envelopes older than 7 days are GC'd hourly.

The 5-minute replay shield is in-memory only — it need not survive restarts
because the timestamp-skew check already prevents cross-reboot re-injection.

---

## Security hardening

### Authenticated `hello` — challenge-response

Every WebSocket connection begins with a cryptographic challenge before the
relay routes any messages or honours any `ack`:

1. **Server → client**: `{ kind: "challenge", nonce: "<16-byte base64url>" }` sent immediately on connection open.
2. **Client signs**: `Ed25519.sign(SHA-256("veil/hello/v1" ‖ nonce ‖ address), IK_Ed.priv)` — proving it holds the identity key for the claimed address.
3. **Client → server**: `{ kind: "hello", address: "veil1…", sig: "<sig>" }`.
4. **Server verifies**: looks up `edPub` from `relay_bundles`, verifies the signature; rejects with `auth_failed` if invalid.

The nonce binds the signature to exactly this connection and this address; a
valid signature cannot be replayed on a different connection or for a different
address.

**Bootstrapping exception**: new addresses that have never published a bundle
are allowed through without a signature (the relay has no `edPub` to verify
against). Immediately after receiving `welcome`, the client publishes its
bundle. All subsequent connections from that address must be authenticated.

**Defence-in-depth**: even on an authenticated socket, `ack` is only honoured
for delivery IDs that were **delivered to the current connection** (per-socket
`deliveredIds` tracking). `ack` is additionally subject to the same per-IP
token bucket as all mutating verbs, and is capped at 256 IDs per message.

### IP attribution and rate limiting

All mutating verbs (`publish`, `fetchBundle`, `send`, `ack`) draw from a
per-IP token bucket: 30-token burst, 6 tokens/second sustained.

IP attribution reads `X-Forwarded-For` **only** when `TRUST_PROXY=1` is set,
and takes the **rightmost** entry (appended by the outermost trusted proxy,
not forgeable by the client). Without `TRUST_PROXY=1`, the raw TCP socket
address is used — which is Replit's shared proxy in a cloud deployment, making
per-IP bucketing coarser but at least unforgeable.

### Stats endpoint

`GET /api/admin/stats` is gated by the `STATS_SECRET` environment variable.
When set, requests must include an `X-Stats-Token: <secret>` header; without
the header, the endpoint returns `401 Unauthorized`. If `STATS_SECRET` is
unset the endpoint is open — acceptable for local/dev environments where the
relay is not internet-reachable.

### Content-Security-Policy

The relay API sends `default-src 'none'; frame-ancestors 'none'` on every HTTP
response. The web client sets a CSP in two places for defence-in-depth:

- **HTTP header** — via the Vite dev server `headers` config (required for
  `frame-ancestors` to take effect).
- **`<meta http-equiv>`** — in `index.html`, for hosting environments that
  forward content unmodified.

Two separate policies are in effect:

**Development** (Vite dev server HTTP header — `vite.config.ts`):
```
script-src 'self' 'unsafe-inline'   ← required for HMR
```

**Production** (`<meta http-equiv>` in `index.html` — applies to built output):
```
default-src 'none';
script-src 'self';                  ← no 'unsafe-inline'
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src https://fonts.gstatic.com;
connect-src 'self' wss: ws:;
img-src 'self' data: blob:;
frame-ancestors 'none';
base-uri 'self';
form-action 'none';
```

Vite production builds emit no inline scripts (all JS is in external `.js`
files), so `'unsafe-inline'` is not needed and is not present in the meta tag.
`style-src 'unsafe-inline'` remains because Tailwind injects inline styles at
runtime; the upgrade path is CSS modules or a hash-based allowlist.

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | Yes | — | HTTP + WebSocket listen port |
| `DATABASE_URL` | Yes | — | Postgres connection string |
| `SESSION_SECRET` | Yes | — | HMAC secret for Express sessions |
| `VEIL_POW_BITS` | No | `14` | PoW difficulty (leading-zero bits) |
| `TRUST_PROXY` | No | unset | Set `"1"` when behind exactly one trusted reverse proxy |
| `STATS_SECRET` | No | unset | Bearer token for `/api/admin/stats`; omit to leave open |
| `LOG_LEVEL` | No | `info` | Pino log level |

---

## Threat model

**Veil resists:**

- **Malicious relay.** With sealed sender, the relay sees only
  `{recipient, padded-ct-size, timestamp, PoW}`. It cannot read messages,
  forge envelopes (the inner Ed25519 signature covers fields the relay never
  sees in plaintext), cryptographically identify the sender from envelope
  contents, or distinguish two messages from the same sender.
- **Network attackers.** TLS handles transport confidentiality. Inner
  signatures and AEAD additional data prevent tampering even if TLS is
  stripped. Padding hides exact plaintext length.
- **Stolen device (locked vault).** Without the passphrase the on-disk blob is
  AES-256-GCM ciphertext under an Argon2id-derived key. A 10-character mixed
  passphrase provides adequate protection against GPU-assisted offline attacks.
- **Replay attacks.** The relay rejects any envelope whose outer SHA-256 it has
  seen in the last 5 minutes. The AEAD additional data on the inner envelope
  additionally binds it to one recipient and one timestamp.
- **Spam.** Every envelope requires a 14-bit SHA-256 PoW (~100 ms CPU). Per-IP
  token buckets cap all mutating verbs at 6 req/s sustained.
- **Forward secrecy.** The Double Ratchet advances sending-chain keys on every
  message. Compromising one message key reveals nothing about past or future
  messages.
- **Post-compromise security.** After a DH ratchet step (triggered by any
  reply), the session heals — future messages are protected even if a prior
  session key was extracted.
- **Mnemonic theft (with 25th-word passphrase).** The BIP39 phrase alone is
  insufficient; an attacker needs the separate passphrase to derive identity
  keys.
- **Malformed envelope injection.** All binary fields are validated for length
  and base64url encoding at relay ingestion. Structurally invalid envelopes
  never reach the database or any recipient client.
- **XSS escalation.** A Content-Security-Policy is active on both the relay API
  and the web client, blocking inline-script injection and restricting
  connection targets. The production meta tag drops `'unsafe-inline'` from
  `script-src`; dev keeps it only for Vite HMR.
- **Stats endpoint enumeration.** The `/api/admin/stats` endpoint requires a
  pre-shared token when `STATS_SECRET` is configured.
- **ACK delivery-race DoS.** The relay requires a valid Ed25519 signature on
  every `hello` for addresses with a published bundle. An attacker who knows
  Alice's address cannot claim it without her private key; unauthenticated
  sockets receive no messages and cannot ack.
- **Vault exposure via `localStorage`.** Saving the vault to `localStorage` is
  refused entirely — the app throws if IndexedDB is unavailable. The legacy
  read path migrates old vaults but will not write back to `localStorage`.
- **DR memory exhaustion.** A malicious peer who repeatedly rotates their DH
  ratchet key while skipping many messages per epoch cannot grow the
  skipped-key cache (`MKSKIPPED`) without bound. A global cap of
  `DR_MAX_SKIP_TOTAL = 2 000` total entries is enforced across all epochs, in
  addition to the per-chain cap of `DR_MAX_SKIP = 1 000`.

**Veil does not (yet) resist:**

- **Active malware on an unlocked device.** If an attacker can read process
  memory while the vault is open, they have the keys. This is true of Signal
  Desktop too.
- **Traffic analysis.** Message *timing* is visible to a passive observer on
  both legs (sender → relay, relay → recipient). Padding defeats size
  correlation but not timing correlation. There is no dummy traffic, no
  mixnet.
- **MITM on first contact.** There is no public-key infrastructure. A malicious
  relay can substitute any bundle on first contact. Compare safety numbers with
  your contact over a separate channel; Veil shows them prominently and marks
  verified contacts.
- **Compelled disclosure.** Coercing the passphrase opens the vault. No duress
  mode is provided — a fake passphrase is detectable, and a plausible-deniable
  vault leaves side-channels a determined adversary will find.
- **Targeted delivery DoS (partial residual).** The ACK race is closed by
  authenticated `hello`. The residual exposure is the bootstrapping window: on
  a new user's very first connection (before their bundle is published), any
  party who connects as that address first can receive the queued messages.
  This window is one-time and extremely narrow (milliseconds between connection
  and publish). After first publish, all connections must be authenticated.
- **Deniability.** Every message carries an Ed25519 signature from the sender's
  long-term identity key. Messages are cryptographically non-repudiable. The
  app discloses this in the UI.
- **Group messaging.** Not implemented.

---

## Breaking my own app

Things I tried to break, and whether they work:

- **"Just send the message twice — the AES nonce will repeat."** No. Each
  envelope uses a fresh 96-bit random nonce, and the GCM key comes from a
  fresh X25519 ephemeral keypair. The relay drops exact duplicates by envelope
  hash within a 5-minute window.

- **"Strip the signature and inject a malicious inner envelope."** No. The
  recipient verifies the Ed25519 signature over
  `domain ‖ from ‖ to ‖ ts ‖ dr ‖ SHA-256(ct)` before advancing the ratchet.
  Tamper with any of those fields and decryption never starts.

- **"Replay an old Double Ratchet message after the session key advances."** No.
  The DR message number `n` is checked against the ratchet's expected receive
  index. Out-of-order or replayed indices are rejected. Combined with the relay's
  5-minute replay window, re-injection is blocked at two independent layers.

- **"Re-publish a sender's prekey bundle to MITM future sessions."** No. The
  relay refuses to overwrite `edPub` or `xPub` for an address that already has
  a bundle. Identity keys are sticky from first publish, enforced at the DB
  level.

- **"Make the relay return an attacker's bundle for Bob's address."** A
  malicious relay *can* substitute a bundle on first contact — there is no PKI.
  Compare safety numbers out-of-band; once verified, the client shows a
  verified badge.

- **"Spam the queue."** Every envelope requires a 14-bit PoW (~100 ms CPU).
  Token buckets cap the sustained rate. The per-user queue caps at 1 024
  envelopes; oldest are **silently evicted** when the cap is hit. If a
  recipient stays offline while their queue fills, the sender may advance the
  Double Ratchet chain key past the evicted messages. When the recipient
  reconnects, those gaps accumulate as skipped-key entries. If the skip window
  (`DR_MAX_SKIP = 1 000` per chain, `DR_MAX_SKIP_TOTAL = 2 000` total across
  all epochs) is exhausted, the session is **permanently wedged** and cannot
  recover without an explicit session reset. This is the highest-risk queue
  interaction: a targeted attacker who can hold a recipient offline long enough
  can force a permanent session break. The sender-visible queue-depth warning
  (orange toast at > 900 / 1 024 envelopes) exists to surface this risk before
  it becomes irreversible. If it does become irreversible, use "Reset session"
  in the contact detail panel to erase local DR state and re-establish a fresh
  X3DH session on the next send.

- **"Race two devices on the same identity."** Use device number 1+ on any
  second device. Each device gets its own sub-identity and OPK pool derived from
  the same phrase.

- **"Brute-force the local vault."** Argon2id at 64 MiB is the same default as
  Signal Desktop. A GPU can test hundreds of guesses per second at this memory
  cost — use a long passphrase (≥10 characters enforced; longer is much better).

- **"Back-date an envelope to bypass the replay window."** The relay rejects any
  envelope whose `ts` is more than 5 minutes from its wall clock.

- **"Solve PoW once and replay forever."** The PoW nonce is bound to
  `(to, ek, nonce, ct, ts)`. Changing any field invalidates the proof. Exact
  replays are caught by the 5-minute dedup window regardless.

- **"Send a malformed `ek` / `nonce` / `ct` to crash the recipient."** The relay
  validates all binary fields for expected byte lengths and valid base64url
  before accepting the envelope. A zero-length `ct`, wrong-size `ek`, or garbage
  `nonce` is rejected at ingestion with a descriptive error; the envelope never
  reaches the database or any recipient.

- **"Exhaust the receiver's memory by rotating your DR ratchet key repeatedly
  while skipping ~1 000 messages per epoch."** Closed. Each DH epoch is capped
  at `DR_MAX_SKIP = 1 000` skipped keys, and a global `DR_MAX_SKIP_TOTAL = 2 000`
  cap bounds the total `MKSKIPPED` cache across all epochs. Exceeding it raises
  an error before any new entry is inserted; the clone-before-mutate invariant
  keeps the original session intact for retry.

- **"Say `hello` as Alice, read her delivery IDs, then `ack` them to delete her
  messages."** Closed. The relay issues a 128-bit random challenge nonce on
  every connection and requires an Ed25519 signature over
  `SHA-256("veil/hello/v1" ‖ nonce ‖ address)` from any address that has
  published a bundle. An attacker without Alice's private key will receive
  `auth_failed` and the socket stays unauthenticated — no messages delivered,
  no acks honoured. The per-socket `deliveredIds` guard remains as a
  defence-in-depth second layer.

- **"Spoof `X-Forwarded-For` to bypass per-IP rate limiting."** Only when
  `TRUST_PROXY=1` is set does the relay read XFF, and it takes the *rightmost*
  entry (added by the outermost trusted proxy, not the client). Without
  `TRUST_PROXY=1`, the raw socket address is used.

- **"Hit `/api/admin/stats` to fingerprint the deployment."** Requires the
  correct `X-Stats-Token` header when `STATS_SECRET` is configured.

- **"Save the vault to `localStorage` where XSS can read it."** Refused at the
  storage layer. `saveVaultBlob` throws if IndexedDB is unavailable, rather
  than silently downgrading. The only `localStorage` write is a one-byte
  presence marker (`"1"`) used for a synchronous `hasVault()` check — never
  the vault blob itself.

If you find something that is **not** in this list, open an issue. That is the
whole point of publishing it.

---

## Test suite

`lib/crypto-core` ships a vitest suite (`src/__tests__/`) that mechanically
verifies the cryptographic invariants. Run it with:

```bash
pnpm --filter @workspace/crypto-core run test
# or, from the repo root:
pnpm run test
```

67 tests across three files:

| File | What it covers |
|---|---|
| `ratchet.test.ts` | In-order and out-of-order delivery, bidirectional DH ratchet advances, AAD/AEAD binding (wrong AAD / nonce / tampered ciphertext all throw), per-chain skip cap (`DR_MAX_SKIP`), global skip cap (`DR_MAX_SKIP_TOTAL`), clone-before-mutate isolation, serialization round-trips |
| `identity.test.ts` | Mnemonic validation, derivation determinism, address format, `isValidAddress`, safety-number symmetry and format, hello-challenge sign/verify, OPK and SPK signature round-trips, `spkExpired` timing |
| `session.test.ts` | Full X3DH establishment, OPK consumption, wrong-recipient rejection, sequential delivery, bidirectional exchange, bundle validation, empty/emoji/500-byte plaintext encoding |

Tests exercise pure TypeScript logic only — no browser globals, no relay, no
IndexedDB. PoW is disabled (`powBits: 0`) to keep the suite fast. The full
test-invariant matrix is documented in PROTOCOL.md §11.

---

## Roadmap

**Implemented:**

- ✅ Postgres-backed relay — messages survive server restarts.
- ✅ Per-IP token-bucket rate limiting + SHA-256 PoW anti-spam.
- ✅ Sealed sender — relay cannot cryptographically identify sender from envelope contents.
- ✅ X3DH key agreement with SPK + OPK pool.
- ✅ **Double Ratchet** — forward secrecy + post-compromise security per message.
- ✅ BIP39 mnemonic identity + optional 25th-word passphrase.
- ✅ Multi-device: HKDF sub-identities from the same phrase.
- ✅ Length-bucket padding (6 sizes, up to 128 KiB).
- ✅ Safety numbers + contact verification flow.
- ✅ **IndexedDB-only vault** — saves refused if IndexedDB is unavailable; legacy `localStorage` read path for migration only.
- ✅ Double Ratchet session state persisted across page reloads.
- ✅ **Persist-before-ACK** — crash-safe decrypt → persist → ack ordering.
- ✅ In-app message search with result highlighting.
- ✅ Contact rename, unread badges, last-read tracking.
- ✅ CSP + security headers on relay (`X-Frame-Options`, HSTS, `Referrer-Policy`, `Permissions-Policy`) and web client (`Content-Security-Policy` via HTTP header + meta tag).
- ✅ Envelope field validation at relay ingestion (byte lengths, base64url format).
- ✅ Per-connection ACK authentication via delivered-ID tracking.
- ✅ Rate-limited, size-capped `ack` batches (token bucket + 256 ID cap).
- ✅ Configurable trusted-proxy IP attribution (`TRUST_PROXY`).
- ✅ Protected stats endpoint (`STATS_SECRET`).
- ✅ Internal error sanitisation — DB errors logged server-side, not forwarded to clients.
- ✅ Node.js CLI client — same protocol, interoperable with the browser.
- ✅ **Authenticated `hello`** — Ed25519 challenge-response on every WebSocket connection; closes the ACK delivery-race DoS window.
- ✅ **Production CSP hardened** — `'unsafe-inline'` removed from `script-src` in the production meta tag; dev-only HMR policy separated.
- ✅ **Global skipped-key cap** — `DR_MAX_SKIP_TOTAL = 2 000` bounds the `MKSKIPPED` cache across all DH ratchet epochs; closes the memory-exhaustion path.
- ✅ **Protocol specification** — PROTOCOL.md covers cryptographic agility, randomness sources, key erasure semantics, resource exhaustion limits, session recovery, multi-tab race conditions, and IndexedDB transaction semantics.
- ✅ **Sender-visible queue depth** — relay returns `queueDepth` in every `sent` ACK; client shows an orange warning toast at > 900 / 1 024 envelopes.
- ✅ **Post-compromise session reset** — "Reset session" in the contact detail panel erases local DR state; the next outbound message re-establishes a fresh X3DH session.
- ✅ **Deniability disclosure** — empty-chat placeholder states that messages are Ed25519-signed and non-repudiable, surfacing the trade-off in the UI.
- ✅ **Formal invariant test suite** — 67 vitest tests covering every critical DR and identity invariant; `pnpm run test` from the root.

**Later, if anyone shows up:**

- Group chats with sender keys (Signal-style group protocol).
- Voice / video over WebRTC, key-agreed in-band.
- Disappearing messages and per-thread auto-erase.
- Tor / mixnet transport and dummy-traffic generation.
- `style-src` nonce-based allowlist (removes `'unsafe-inline'` from style directives).
- A third-party cryptographic audit.

**Probably never, but in the spirit of honesty:**

- Federation. Pick one relay; run your own if you want sovereignty.
- Bridging to SMS, email, or Matrix. Not the use case.
- A duress / panic / fake-vault mode. False security is worse than none.

---

## License

MIT. No warranty, express or implied. The cryptography here is intentionally
simple and conservative, but it has not been audited. If you ship anything
serious on top of it, you do so at your own risk.
