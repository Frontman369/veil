# Veil Protocol Specification v3

**Status**: Stable — frozen at v3. See §15 for version stability policy.  
**Date**: 2026-05.  
**Audit status**: No independent cryptographic audit has been performed.  
**Warning**: This document is a best-effort description of the current
implementation. Where this document and the code disagree, the code is the
ground truth until reconciled — discrepancies are bugs in one or the other.

---

## 1. Goals and Non-Goals

### Goals
| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM authenticated encryption |
| Sender authenticity | Ed25519 signatures on every message |
| Forward secrecy (message level) | Double Ratchet symmetric KDF chain |
| Post-compromise security | Double Ratchet DH ratchet steps |
| Sealed sender (relay metadata) | Outer ephemeral ECDH hides sender address |
| Anti-spam | Per-IP token bucket + per-message SHA-256 PoW |
| Replay protection | 5-min server-side dedup window + DR message counters |
| Key binding | BIP39 mnemonic → deterministic Ed25519 + X25519 |

### Non-Goals (explicitly out of scope)

- **Deniability** — Every message carries an Ed25519 signature attributable to
  the sender's long-term identity key. This is a deliberate design choice
  (authenticity over deniability). A sophisticated attacker with access to the
  ciphertext and the Ed25519 signature can produce a cryptographic transcript
  that proves a specific key signed a specific message. Screenshots are not
  required — the signature itself is the evidence. If deniability is required,
  Veil is the wrong tool.
- **Link-layer anonymity** — a passive observer of both legs can do timing
  analysis; no mixnet or cover traffic is provided.
- **Post-quantum security** — all primitives are classical.
- **Duress mode** — deliberately not implemented (see §8).
- **Forward anonymity** — the relay sees _recipient_ address and can track when
  a user receives messages. Only the _sender's_ address is hidden.
- **Key transparency** — there is no append-only log of bundle publications.
  A malicious relay can silently substitute a bundle on first contact. Safety
  number verification (§3.3) is the only mitigation.

---

## 2. Cryptographic Primitives

| Primitive | Library | Purpose |
|---|---|---|
| Ed25519 | `@noble/curves/ed25519` | Identity signing, SPK signing, OPK signing, message auth |
| X25519 | `@noble/curves/ed25519` | ECDH (X3DH, sealed sender, DR DH ratchet) |
| AES-256-GCM | `@noble/ciphers/aes` | Authenticated encryption (inner, outer, DR messages) |
| HKDF-SHA256 | `@noble/hashes/hkdf` | Key derivation (X3DH KDF, DR KDF_RK) |
| HMAC-SHA256 | `@noble/hashes/hmac` | DR chain key advancement (KDF_CK) |
| SHA-256 | `@noble/hashes/sha2` | Address derivation, fingerprints, PoW, replay IDs |
| Argon2id | `hash-wasm` | Vault key derivation from passphrase |
| BIP39 | `@scure/bip39` | Mnemonic generation and seed derivation |

### 2.1 Cryptographic Agility Statement

Veil has **no runtime algorithm negotiation**. Algorithms are pinned to the
protocol version declared in the inner envelope's `v` field:

| Inner `v` | Key exchange | Symmetric | Hash | Status |
|---|---|---|---|---|
| 2 | X3DH-lite (no DR) | AES-256-GCM | HKDF-SHA256 | Legacy; received only |
| 3 | X3DH + Double Ratchet | AES-256-GCM | HKDF-SHA256 / HMAC-SHA256 | Current |

Rules:
- A future algorithm change MUST increment the inner version.
- Peers that receive an unknown version MUST reject the message, not downgrade.
- There is no negotiation phase; the sender picks based on what the recipient's
  bundle version advertises (future) or defaults to the current version (now).

### 2.2 Randomness Sources

| Environment | Source | Library |
|---|---|---|
| Browser | `crypto.getRandomValues(Uint8Array)` | `@noble/hashes/utils` `randomBytes` |
| Node.js relay | `node:crypto.randomBytes` | Node.js built-in |

`@noble/hashes/utils.randomBytes` delegates to the platform CSPRNG and re-throws
if unavailable — there is no silent fallback to a weak source. Both paths use
OS-kernel entropy (Web Crypto API in browsers; `/dev/urandom` via libuv in Node).

---

## 3. Identity

### 3.1 Key derivation from mnemonic

```
seed ← BIP39.mnemonicToSeed(mnemonic, bip39Passphrase)   // 64 bytes

# Primary device (deviceIndex = 0)
ed_seed ← SHA-256("veil/identity/ed25519/v1" ‖ seed)
x_seed  ← SHA-256("veil/identity/x25519/v1"  ‖ seed)

# Sub-device (deviceIndex ≥ 1)
sub_seed ← HKDF-SHA256(ikm=seed, info="veil/identity/v2/device/{index}", L=64)
ed_seed  ← SHA-256("veil/identity/ed25519/v1" ‖ sub_seed)
x_seed   ← SHA-256("veil/identity/x25519/v1"  ‖ sub_seed)

IK_Ed ← Ed25519.generateKeyPair(ed_seed)   # long-term identity key (signing)
IK_X  ← X25519.generateKeyPair(x_seed)     # long-term identity key (DH)
```

### 3.2 Address

```
address ← "veil1" ‖ Base32( SHA-256(IK_Ed.pub ‖ IK_X.pub)[0:20] )
```

32-character base32 string prefixed `veil1`.

### 3.3 Safety number

The safety number between two parties `A` and `B` is:

```
[first, second] ← sort_lexicographic( A.pub_concat, B.pub_concat )
safety_num ← SHA-256(first ‖ second)[0:16]
           → 30-decimal-digit string in six 5-digit groups
```

where `pub_concat = IK_Ed.pub ‖ IK_X.pub`. Users MUST compare this
out-of-band (voice call, in-person) before trusting a contact.

Safety numbers are symmetric: `safetyNum(A, B) = safetyNum(B, A)`. They are
deterministic given the two public key pairs. They do NOT change unless a
party's identity key changes (which only happens via mnemonic recovery on a
different device index). A change in safety number after first contact
indicates either a key rotation by the peer or a relay-substituted bundle.

---

## 4. Prekeys

### 4.1 Signed Prekey (SPK)

A medium-term X25519 key pair signed by the identity Ed25519 key.

```
SPK.priv ← random(32)
SPK.pub  ← X25519.getPublicKey(SPK.priv)
SPK.sig  ← Ed25519.sign("veil/spk/v1" ‖ SPK.pub, IK_Ed.priv)
SPK.id   ← Base64url(random(8))
```

Rotated weekly; up to 2 generations kept so in-flight messages decrypt.

### 4.2 One-Time Prekey (OPK)

Single-use X25519 key pair signed by the identity key.

```
OPK.priv ← random(32)
OPK.pub  ← X25519.getPublicKey(OPK.priv)
OPK.sig  ← Ed25519.sign("veil/prekey/v1" ‖ OPK.pub, IK_Ed.priv)
OPK.id   ← Base64url(random(8))
```

Pool of ≤200 keys per user on the relay. The relay atomically pops one OPK
per bundle fetch (`FOR UPDATE SKIP LOCKED`), preventing double-use.

---

## 5. Session Establishment: X3DH + Double Ratchet Initialisation

First message from Alice to Bob:

### 5.1 X3DH key agreement (sender side)

```
EPH     ← X25519.generateKeyPair()   # inner ephemeral, per-message
DH1     ← X25519(EPH.priv,  Bob.IK_X.pub)
DH2     ← X25519(EPH.priv,  Bob.SPK.pub)
DH3     ← X25519(EPH.priv,  Bob.OPK.pub)   # omitted if no OPK
DH4     ← X25519(Alice.IK_X.priv, Bob.IK_X.pub)

ikm     ← DH1 ‖ DH2 ‖ DH3 ‖ DH4   # (DH3 empty if no OPK)
SK      ← HKDF-SHA256(ikm, salt=∅, info="veil/msg/aes-256-gcm/v2", L=32)
```

After computing SK, all DH output buffers (DH1–DH4) and the IKM buffer are
immediately zeroed. The inner ephemeral private key (`EPH.priv`) is zeroed
after the DH outputs are computed.

### 5.2 DR sender initialisation

```
Alice.DHs  ← X25519.generateKeyPair()  # Alice's initial DR ratchet key pair
Alice.DHr  ← Bob.SPK.pub
(Alice.RK, Alice.CKs) ← KDF_RK(SK, DH(Alice.DHs.priv, Alice.DHr))
Alice.CKr  ← ⊥
Alice.Ns   ← Alice.Nr ← Alice.PN ← 0
MKSKIPPED  ← {}
```

### 5.3 X3DH key agreement (receiver side, Bob)

```
DH1 ← X25519(Bob.IK_X.priv,  Alice.EPH.pub)
DH2 ← X25519(Bob.SPK.priv,   Alice.EPH.pub)
DH3 ← X25519(Bob.OPK.priv,   Alice.EPH.pub)   # omitted if no OPK
DH4 ← X25519(Bob.IK_X.priv,  Alice.IK_X.pub)
SK  ← HKDF-SHA256(DH1 ‖ DH2 ‖ DH3 ‖ DH4, …)  # same as Alice's
```

Bob verifies `Alice.EPH.pub` is a valid X25519 point, verifies the SPK
signature against Alice's claimed `edPub`, and verifies the OPK signature
if an OPK was claimed. Any verification failure aborts the session.

### 5.4 DR receiver initialisation

```
Bob.DHs ← (Bob.SPK.priv, Bob.SPK.pub)  # SPK is initial ratchet key pair
Bob.DHr ← ⊥
Bob.RK  ← SK
Bob.CKs ← Bob.CKr ← ⊥
Bob.Ns  ← Bob.Nr ← Bob.PN ← 0
```

Bob's first DH ratchet step is triggered by Alice's DR header on first decrypt.

---

## 6. Double Ratchet (ongoing messages)

### 6.1 KDF functions

```
KDF_RK(rk, dh_out):
  out ← HKDF-SHA256(ikm=dh_out, salt=rk, info="VeilDR/RK/v1", L=64)
  return (out[0:32], out[32:64])   # (new_root_key, new_chain_key)

KDF_CK(ck):
  mk     ← HMAC-SHA256(key=ck, data=0x01)   # message key (32 B)
  new_ck ← HMAC-SHA256(key=ck, data=0x02)   # next chain key (32 B)
  return (new_ck, mk)
```

### 6.2 Encrypt

```
(MK, CKs) ← KDF_CK(CKs)
header    ← { dh: DHs.pub, pn: PN, n: Ns }
Ns++
nonce     ← random(12)
headerTag ← "|DR|" ‖ header.dh ‖ "|" ‖ header.pn ‖ "|" ‖ header.n
aad       ← "VeilDR/AAD/v1|" ‖ from ‖ "|" ‖ to ‖ "|" ‖ ts ‖ headerTag
ct        ← AES-256-GCM(MK, nonce, pad(plaintext), aad)
MK.fill(0)   # zero message key immediately
```

The AAD binds the ciphertext to the `(from, to, ts, dr_header)` tuple.
Tampering with any of those fields causes AEAD authentication to fail.

### 6.3 Decrypt

```
1. Check MKSKIPPED[header.dh, header.n] → use cached key if present
2. If header.dh ≠ DHr (DH ratchet step):
   skipMessageKeys(header.pn)
   PN  ← Ns; Ns ← Nr ← 0
   DHr ← header.dh
   (RK, CKr) ← KDF_RK(RK, DH(DHs.priv, DHr))
   DHs ← X25519.generateKeyPair()
   (RK, CKs) ← KDF_RK(RK, DH(DHs.priv, DHr))
3. skipMessageKeys(header.n)
4. (CKr, MK) ← KDF_CK(CKr); Nr++
5. plaintext ← AES-256-GCM.decrypt(MK, …); MK.fill(0)
```

`MAX_SKIP = 1000` — per-chain limit. The receiver raises an error if more than
1 000 messages are skipped in one ratchet chain.

`MAX_SKIP_TOTAL = 2000` — global limit. The total number of cached skipped keys
across ALL ratchet epochs is capped at 2 000. A peer that repeatedly rotates
their DH ratchet key while skipping many messages per epoch cannot grow the
cache beyond this bound. Exceeding it raises an error; the clone-before-mutate
pattern (§10.2, I2) keeps the original session intact for retry.

### 6.4 Key Erasure Semantics

Veil makes best-effort key erasure. JavaScript does not guarantee memory layout
or GC timing, so `fill(0)` zeroes the typed-array buffer but cannot prevent the
runtime from having already copied the value to a different heap location.

| Key material | Erased when | Mechanism |
|---|---|---|
| Message key (MK) | Immediately after AEAD use | `mk.fill(0)` in `finally` blocks |
| Old DHs private key | Immediately before overwrite on DH ratchet step | `session.DHsPriv.fill(0)` |
| X3DH ephemeral private | After DH outputs computed | `innerEphPriv.fill(0)` |
| X3DH DH outputs | After SK derived | `.fill(0)` per output |
| Skipped MK (MKSKIPPED) | On first use (one-time) | `skippedMk.fill(0)` in `finally` |
| Chain keys (CKs, CKr) | On replacement (no explicit zero) | Overwritten by new reference |
| Root key (RK) | On replacement (no explicit zero) | Overwritten by new reference |
| Outer sealed-sender key | After sealing | `outerEphPriv.fill(0)`, `outerKey.fill(0)` |

**Limitation**: Chain keys and root key are reassigned (JS pointer swap), not
zeroed. The old buffer becomes GC-eligible but is not explicitly filled. This
is a known limitation of in-process JS crypto — hardware-backed key storage
(WebAuthn/TPM) would be required for stronger erasure guarantees.

### 6.5 Forward Secrecy and PCS

- **Per-message forward secrecy**: each message key is derived from a
  one-way KDF; compromise of the current chain key cannot recover past keys.
- **Post-compromise security**: after a key compromise, the next DH ratchet
  step (triggered on the first reply) produces keys unrelated to the
  compromised material. Recovery latency = one round trip.

### 6.6 Formal DR State Definition

A DR session is a typed record `S`:

| Field | Type | Description |
|---|---|---|
| `RK` | `bytes[32]` | Root key — shared secret updated on every DH ratchet step |
| `DHs` | `{ priv: bytes[32], pub: bytes[32] }` | Current sending ratchet key pair |
| `DHr` | `bytes[32] \| null` | Current receiving ratchet public key; `null` until first receive |
| `CKs` | `bytes[32] \| null` | Sending chain key; `null` until first send or after DH ratchet step |
| `CKr` | `bytes[32] \| null` | Receiving chain key; `null` until first receive |
| `Ns` | `uint32` | Messages sent in current sending chain |
| `Nr` | `uint32` | Messages received in current receiving chain |
| `PN` | `uint32` | Message count in the previous sending chain |
| `MKSKIPPED` | `Map<string → bytes[32]>` | Cached message keys for out-of-order messages |

Key encoding in `MKSKIPPED`: `"<base64url(DHr_pub)>:<Nr>"` → `MK`.

**Initial state — Alice (first sender after X3DH):**

```
DHs  ← fresh X25519 keypair
DHr  ← Bob.SPK.pub
(RK, CKs) ← KDF_RK(SK, X25519(DHs.priv, DHr))
CKr  ← null;  Ns ← Nr ← PN ← 0;  MKSKIPPED ← {}
```

**Initial state — Bob (first receiver):**

```
DHs  ← (Bob.SPK.priv, Bob.SPK.pub)
DHr  ← null;  RK ← SK
CKs  ← CKr ← null;  Ns ← Nr ← PN ← 0;  MKSKIPPED ← {}
```

**Structural invariants** (must hold at all times; checked by test suite §14):

| # | Invariant | Violation means |
|---|---|---|
| S1 | `MKSKIPPED.size ≤ DR_MAX_SKIP_TOTAL` | Memory exhaustion attack succeeded |
| S2 | `DHs.pub = X25519.getPublicKey(DHs.priv)` | DHs is a valid key pair |
| S3 | `CKs ≠ null` when any send is attempted | Session not properly initialised |
| S4 | `CKr ≠ null` when a receive is attempted on an established chain | DH ratchet step was skipped |
| S5 | `DHr = null ⟺ Nr = 0 ∧ PN = 0` | Ratchet state is inconsistent |
| S6 | Every `MK` in `MKSKIPPED` is 32 bytes | Truncated key material |
| S7 | `Ns` and `Nr` only ever increase within a given chain | Ratchet counter wrapped or reversed |

**Serialisation**: `MKSKIPPED` is serialised as a JSON object mapping
`"<b64url(DHr)>:<N>"` → `base64url(MK)`. Numeric fields (`Ns`, `Nr`, `PN`)
are JSON numbers. Key buffers (`RK`, `DHs.priv`, `DHs.pub`, `DHr`, `CKs`,
`CKr`) are base64url strings. See `lib/crypto-core/src/ratchet.ts`
`serializeDrSession` / `deserializeDrSession`.

### 6.7 DR State Transition Diagram

The diagram traces a bidirectional 3-turn exchange (Turn 1: A→B, Turn 2: B→A,
Turn 3: A→B). Subscripts on key names identify the epoch.

```
Alice                                             Bob
─────                                             ───

After X3DH:
 RK=RK₀  DHs=EK_A  DHr=SPK_B  CKs=CK_A0          RK=SK   DHs=SPK_B  DHr=⊥
 CKr=⊥   Ns=Nr=PN=0                                CKr=⊥   Ns=Nr=PN=0

──────────────────── Turn 1: Alice sends msg 0 ────────────────────────────────

 SEND:
  (MK_A0, CKs') ← KDF_CK(CKs)
  header = {dh: EK_A.pub, pn: 0, n: 0}
  ct ← AES-GCM(MK_A0, nonce, pad(pt), aad)
  MK_A0.fill(0)
  Ns ← 1;  CKs ← CKs'

                ─── envelope {dh:EK_A.pub, pn:0, n:0} ──────────────────►

                                                   RECV:
                                                    header.dh=EK_A.pub ≠ DHr(⊥)
                                                    → DH ratchet step:
                                                      skipMessageKeys(pn=0) [noop]
                                                      PN' ← Ns(0);  Ns ← Nr ← 0
                                                      DHr ← EK_A.pub
                                                      (RK₁,CKr_B0) ← KDF_RK(SK,
                                                        DH(SPK_B.priv, EK_A.pub))
                                                      DHs ← fresh EK_B
                                                      (RK₂,CKs_B0) ← KDF_RK(RK₁,
                                                        DH(EK_B.priv, EK_A.pub))
                                                    skipMessageKeys(n=0) [noop]
                                                    (CKr_B0',MK) ← KDF_CK(CKr_B0)
                                                    pt ← AES-GCM.decrypt(MK, ...)
                                                    Nr ← 1;  CKr ← CKr_B0'

State after T1:
 Alice: RK=RK₀  DHs=EK_A  DHr=SPK_B             Bob: RK=RK₂  DHs=EK_B
        CKs=CKs'  CKr=⊥  Ns=1                         DHr=EK_A  CKs=CKs_B0
                                                         CKr=CKr_B0'  Nr=1

──────────────────── Turn 2: Bob sends msg 0 ──────────────────────────────────

                                                   SEND:
                                                    (MK_B0, CKs_B0') ← KDF_CK(CKs_B0)
                                                    header={dh:EK_B.pub, pn:0, n:0}
                                                    Ns ← 1;  CKs ← CKs_B0'

                ◄── envelope {dh:EK_B.pub, pn:0, n:0} ──────────────────

 RECV:
  header.dh=EK_B.pub ≠ DHr(SPK_B)
  → DH ratchet step:
    skipMessageKeys(pn=1) [skip EK_A chain to n=1]
    PN ← Ns(1);  Ns ← Nr ← 0
    DHr ← EK_B.pub
    (RK₃,CKr_A) ← KDF_RK(RK₀, DH(EK_A.priv,  EK_B.pub))
    DHs ← fresh EK_A'
    (RK₄,CKs_A1) ← KDF_RK(RK₃, DH(EK_A'.priv, EK_B.pub))
  skipMessageKeys(n=0) [noop]
  (CKr_A',MK) ← KDF_CK(CKr_A)
  pt ← AES-GCM.decrypt(MK, ...)
  Nr ← 1

State after T2:
 Alice: RK=RK₄  DHs=EK_A'  DHr=EK_B            Bob: RK=RK₂  DHs=EK_B
        CKs=CKs_A1  CKr=CKr_A'                        DHr=EK_A  CKs=CKs_B0'
        Ns=0  Nr=1  PN=1                               Ns=1

──────────────────── Turn 3: Alice sends msg 0 (new chain) ────────────────────

 SEND:
  (MK_A1_0, CKs_A1') ← KDF_CK(CKs_A1)
  header = {dh: EK_A'.pub, pn: 1, n: 0}
  Ns ← 1

                ─── envelope {dh:EK_A'.pub, pn:1, n:0} ──────────────────►

                                                   RECV:
                                                    header.dh=EK_A'.pub ≠ DHr(EK_A)
                                                    → DH ratchet step:
                                                      (RK₅,CKr_B2) ← KDF_RK(RK₂,
                                                        DH(EK_B.priv,  EK_A'.pub))
                                                      DHs ← fresh EK_B'
                                                      (RK₆,CKs_B2) ← KDF_RK(RK₅,
                                                        DH(EK_B'.priv, EK_A'.pub))
```

Key observations:
1. Every reply from the other party triggers a DH ratchet step (`header.dh` changes).
2. Each DH ratchet step requires two DH operations and two `KDF_RK` calls.
3. `PN` (previous chain length) enables `skipMessageKeys` to cache keys for
   messages sent before the DH rotation that arrive after the ratchet step.
4. The DHs private key is zeroed immediately after the `KDF_RK` call that consumes it.
5. After a DH ratchet step, the receiver has both a new `CKr` (for the sender's
   new chain) and a new `CKs` (for their own next reply), derived independently.

### 6.8 Key Schedule Diagram

```
BIP39 mnemonic (12 words) [+ optional 25th-word passphrase]
        │
        ▼  BIP39.mnemonicToSeed(mnemonic, passphrase)
BIP39 Seed (64 bytes)
        │
        ├─[device 0]─ SHA-256("veil/identity/ed25519/v1" ‖ seed) ──► ed_seed
        │             SHA-256("veil/identity/x25519/v1"  ‖ seed) ──► x_seed
        │
        └─[device k≥1]─ HKDF-SHA256(ikm=seed,
                             info="veil/identity/v2/device/k", L=64) ──► sub_seed
                         SHA-256("veil/identity/ed25519/v1" ‖ sub_seed) ──► ed_seed
                         SHA-256("veil/identity/x25519/v1"  ‖ sub_seed) ──► x_seed

ed_seed ──► Ed25519.fromSeed ──► (IK_Ed.priv, IK_Ed.pub)
x_seed  ──► X25519.fromSeed  ──► (IK_X.priv,  IK_X.pub)

IK_Ed.pub ‖ IK_X.pub ──► SHA-256 ──► [0:20] ──► Base32 ──► "veil1" + 32 chars
                                                              = address

Medium-term key (SPK):
  SPK.priv ← random(32);  SPK.pub ← X25519.getPublicKey(SPK.priv)
  SPK.sig  ← Ed25519.sign("veil/spk/v1" ‖ SPK.pub, IK_Ed.priv)

One-time key (OPK):
  OPK.priv ← random(32);  OPK.pub ← X25519.getPublicKey(OPK.priv)
  OPK.sig  ← Ed25519.sign("veil/prekey/v1" ‖ OPK.pub, IK_Ed.priv)

X3DH Session Key (sender, Alice → Bob):
  DH1 ← X25519(EPH.priv,        Bob.IK_X.pub)  ╮
  DH2 ← X25519(EPH.priv,        Bob.SPK.pub)   │ IKM = DH1‖DH2[‖DH3]‖DH4
  DH3 ← X25519(EPH.priv,        Bob.OPK.pub)   │  (DH3 omitted when no OPK)
  DH4 ← X25519(Alice.IK_X.priv, Bob.IK_X.pub)  ╯
         │
         ▼  HKDF-SHA256(ikm=IKM, salt=∅, info="veil/msg/aes-256-gcm/v2", L=32)
         SK (32 bytes — shared secret)
         │
         ▼  KDF_RK(SK, X25519(DHs.priv, Bob.SPK.pub))
        (RK₀, CKs₀)  ← initial root key + sending chain key

Per-message key derivation (sending chain):
  CKsₙ ──► HMAC-SHA256(key=CKsₙ, data=0x02) ──► CKsₙ₊₁  (chain advances)
  CKsₙ ──► HMAC-SHA256(key=CKsₙ, data=0x01) ──► MKₙ      (message key, 32B)
                                                      │
                                                      ▼  AES-256-GCM(MKₙ, nonce,
                                                         pad(plaintext), aad)
                                                    ciphertext
                                                      │
                                                     MKₙ.fill(0) ◄── immediate erase

Per-DH-ratchet-step:
  Old DHs.priv ──► X25519(DHs.priv, DHr) ──► dh_out
  dh_out ──► KDF_RK(RK_prev, dh_out) ──► (RK_new, CK_new)
  dh_out.fill(0);  DHs.priv.fill(0)  ◄── both zeroed
  DHs ← fresh X25519 keypair

Vault key derivation:
  passphrase ──► Argon2id(m=65536 KiB, t=3, p=1, salt=random(32), L=32) ──► K_vault
  K_vault ──► AES-256-GCM(K_vault, nonce, JSON.stringify(VaultData)) ──► vault_ct
```

---

## 7. Wire Format

### 7.1 Outer envelope (relay-visible)

```json
{
  "v":     2,           // outer format version (always 2; relay checks this)
  "to":    "veil1…",   // recipient address (relay routes on this)
  "ek":    "<b64url>", // outer ephemeral X25519 pub (32 B)
  "nonce": "<b64url>", // AES-GCM nonce (12 B)
  "ct":    "<b64url>", // AES-GCM ciphertext of JSON(InnerEnvelope*)
  "ts":    1234567890, // Unix ms; relay rejects if |ts - now| > 5 min
  "pow":   "<b64url>"  // SHA-256 PoW nonce
}
```

The relay sees only: recipient address, ciphertext bucket size, timestamp, PoW.
It cannot learn the sender's address from envelope contents alone.

### 7.2 Inner envelope v2 (legacy, preserved for backward-compat)

Decrypted by recipient via:

```
K_outer ← HKDF-SHA256(X25519(IK_X.priv, ek), info="veil/sealed/v2/aes-256-gcm/key", L=32)
inner   ← AES-256-GCM.decrypt(K_outer, nonce, ct, AAD="veil/sealed/v2|to|ts")
```

### 7.3 Inner envelope v3 (Double Ratchet — current)

```json
{
  "v":     3,
  "to":    "veil1…",
  "from":  "veil1…",
  "fromEd": "<b64url>",  // sender Ed25519 pub (for sig verification)

  // X3DH block — ONLY on first message:
  "x3dh": {
    "fromX":    "<b64url>",  // sender X25519 pub (IK_X)
    "ek":       "<b64url>",  // inner ephemeral X25519 pub for X3DH
    "spkId":    "…",
    "prekeyId": "…"          // omitted if no OPK used
  },

  "dr": { "dh": "<b64url>", "pn": 0, "n": 0 },  // DR header

  "nonce": "<b64url>",  // AES-GCM nonce for DR-encrypted ct
  "ct":    "<b64url>",  // DR message-key-encrypted padded plaintext
  "sig":   "<b64url>",  // Ed25519 sig over sigPayloadV3(…)
  "ts":    1234567890
}
```

### 7.4 Signature payload v3

```
sigPayloadV3 =
  "veil/msg/sig/v3" ‖
  from ‖ "|" ‖ to ‖ "|" ‖ ts ‖ "|" ‖ dr.pn ‖ "|" ‖ dr.n ‖ "|" ‖
  dr.dh_bytes ‖ "|" ‖
  nonce ‖ "|" ‖
  SHA-256(ct)
  # for first message, additionally:
  ‖ "|x3dh|" ‖ spkId ‖ "|" ‖ prekeyId ‖ "|" ‖ ek_bytes
```

### 7.5 Length-bucket padding

Plaintext is padded to the nearest bucket before encryption:

| Bucket | Max plaintext |
|---|---|
| 128 B | ≤ 91 B |
| 512 B | ≤ 475 B |
| 2 048 B | ≤ 2 011 B |
| 8 192 B | ≤ 8 155 B |
| 32 768 B | ≤ 32 731 B |
| 131 072 B | ≤ 131 035 B |

### 7.6 Proof-of-Work

```
for nonce = 0, 1, 2, …:
  h ← SHA-256("veil/pow/v1|" ‖ to ‖ "|" ‖ ek ‖ "|" ‖ ct ‖ "|" ‖ ts ‖ "|" ‖ nonce)
  if leading_zero_bits(h) ≥ BITS: accept
```

Default: 14 bits (~16 384 hashes, ~125 ms on a mid-range device).
Configurable server-side via `VEIL_POW_BITS`.

**Limitation**: 14-bit SHA-256 PoW stops casual spam from commodity hardware.
It does not stop GPU-backed spam campaigns or botnets. PoW binds the nonce to
`(to, ek, ct, ts)` — changing any field invalidates the proof.

---

## 8. Relay Security Model

### 8.1 Security checks

| Check | Implementation |
|---|---|
| **Hello authentication** | Ed25519 challenge-response on every connection (see §8.2) |
| PoW verification | SHA-256 leading zeros on outer fields |
| Clock skew | `\|env.ts − server_now\| ≤ 5 min` |
| Replay detection | In-memory SHA-256 dedup map, 5-min window, 100 K cap |
| Rate limiting | Per-IP token bucket: 30 burst / 6 rps sustained |
| V1 envelope rejection | `env.v !== 2` → hard reject |
| SPK required | Bundle publish without SPK → reject |
| OPK atomicity | `FOR UPDATE SKIP LOCKED` prevents double-pop |
| Ack scope | Ack only honoured for IDs delivered on same connection |

The relay is **zero-knowledge** with respect to message content. It stores
sealed opaque blobs and routes them by recipient address only.

### 8.2 Authenticated `hello` — challenge-response

**Problem** addressed: before this mechanism, any party that knew Alice's address
could open a WebSocket, say `hello` as Alice, receive her queued messages (opaque
sealed blobs they cannot decrypt), and `ack` those IDs — permanently deleting her
messages from the queue before she reads them.

**Protocol** (executes on every new WebSocket connection):

```
1. TCP/TLS accept
2. Server  →  { kind: "challenge", nonce: "<16-byte base64url random>" }
3. Client computes:
     msg ← SHA-256("veil/hello/v1" ‖ nonce ‖ address)
     sig ← Ed25519.sign(msg, IK_Ed.priv)
4. Client  →  { kind: "hello", address: "veil1…", sig: "<base64url sig>" }
5. Server fetches edPub from relay_bundles for the claimed address.
   - If no bundle exists → bootstrapping path (see §8.3); proceed without sig.
   - If bundle exists and sig absent → reject with error "authentication required".
   - If bundle exists and sig invalid → reject with error "authentication failed".
   - If sig valid → mark socket as authenticated.
6. Authenticated sockets receive:
   - Queued `deliver` messages
   - Permission to send `ack`
```

**Security properties**:
- The nonce is 128 bits of fresh randomness — replay across connections is
  computationally infeasible.
- The signed message binds `nonce` AND `address`: a valid sig for Alice cannot
  be replayed for Bob, nor can it be replayed on a different connection.
- The relay computes no long-term session state from the challenge — it is
  stateless after the initial `hello` is verified.

### 8.3 Bootstrapping path

New users must publish a bundle before they can authenticate (the relay needs
`edPub` to verify signatures). The bootstrap sequence is:

```
1. Connect → receive challenge
2. Send hello WITHOUT sig (no bundle on file yet → relay accepts)
3. Receive welcome
4. Publish bundle (relay stores edPub)
5. All subsequent connections must include a valid sig in hello
```

This is a one-time window. Once the bundle is published the address is
permanently in authenticated mode.

**Residual risk**: during the bootstrapping window (between connection open and
bundle publish), any client that connects with the same address can receive
queued messages. This window is extremely narrow (milliseconds) and one-time.
After the first successful publish, all connections require authentication.

---

## 9. Vault Storage

```
argon2id_key ← Argon2id(passphrase, salt, m=65536, t=3, p=1, L=32)
vault_ct     ← AES-256-GCM(argon2id_key, nonce, JSON(VaultData))
```

Storage location: **IndexedDB exclusively** (`veil-secure-v1` database,
`vault` object store). A lightweight sync marker (`veil.vault.marker = "1"`)
remains in `localStorage` for the synchronous `hasVault()` check at startup —
this marker never contains key material.

**No `localStorage` fallback for writes.** `saveVaultBlob` throws rather than
downgrading to `localStorage`, because:
- `localStorage` is synchronously readable by any same-origin JavaScript.
- An XSS vulnerability or malicious extension can exfiltrate the blob without
  async I/O and without leaving timing signals.
- Even though the blob is AES-256-GCM ciphertext, the wider access surface is
  unacceptable for a cryptographic vault.

**Legacy read path**: `loadVaultBlob` will read from the legacy `localStorage`
key (`veil.vault`) if present and IndexedDB is empty, to migrate vaults created
by older versions of Veil. The migration flag `_localStorageFallbackActive` is
set at vault-load time. Subsequent save attempts will still use IndexedDB; if
IndexedDB is unavailable, the save throws with an actionable error message
("Secure storage (IndexedDB) is unavailable. Open Veil in a regular
(non-private) browser window.") rather than writing the vault back to
`localStorage`. Once migrated, the legacy key is deleted.

---

## 10. Session State Machine

### 10.1 Per-contact session lifecycle

```
                          ┌───────────────────────────────────────────┐
                          │                                           │
         (first message   │                                 (DH ratchet
          sent or rcvd)   ▼                                 step on reply)
  NONE ──────────────► ESTABLISHED ──────────────────────► RATCHETING
                          │         ◄──────────────────────     │
                          │                (DH step complete)   │
                          │                                      │
                          └─────────────── persisted ───────────┘

  Any state ──── "Reset session" action ────► NONE
```

States:

- **NONE** — no session exists. First message must carry an `x3dh` block; all
  fields (`fromX`, `ek`, `spkId`) are mandatory.
- **ESTABLISHED** — a DR session exists. Messages carry only the `dr` header.
  The `x3dh` block is absent.
- **RATCHETING** — a DH ratchet step is in progress (sender has rotated their
  DR public key; receiver performs two DH operations before decrypting). This
  is an internal sub-state of ESTABLISHED; from the outside it is invisible.

### 10.2 Decrypt state-machine invariants

The following invariants MUST hold at every decrypt call-site. Violation is a
protocol error; the message MUST be discarded and the session MUST NOT advance.

| # | Invariant | Checked by |
|---|---|---|
| I1 | Ed25519 signature is verified BEFORE any session state mutation | `decryptInnerV3` pre-clone check |
| I2 | Session is cloned before `drDecrypt`; clone is committed only on AEAD success | `cloneDrSession` + copy-on-success return |
| I3 | `inner.to` matches `identity.address` | `decryptInnerV3` guard |
| I4 | `inner.ts` matches the outer envelope `ts` | `decryptInnerV3` guard |
| I5 | Session is persisted to vault BEFORE the relay ACK is sent | `handleDeliver` await ordering |
| I6 | Skipped keys are bounded: `header.n - Nr ≤ MAX_SKIP (1000)` | `skipMessageKeys` guard |
| I7 | DH ratchet key material is zeroed after use | `DHsPriv.fill(0)` in `drDecrypt` |
| I8 | Message keys are zeroed after AEAD decrypt | `mk.fill(0)` in finally blocks |
| I9 | SPK must be present in the local key store for X3DH receive | `spkLookup` non-null check |

**I2 in detail** — The clone-before-mutate pattern guarantees that if
`drDecrypt` throws at any point (too many skipped messages, AEAD
authentication failure, state error), the original session object is
unchanged and will be retried correctly on the next delivery attempt:

```typescript
const sessionCopy = cloneDrSession(session);           // snapshot
const padded = drDecrypt(sessionCopy, header, …);      // mutates copy
return { …, session: sessionCopy };                    // commit copy to caller
// Original session is unchanged if drDecrypt throws
```

**I5 in detail** — Persist-before-ACK is the critical ordering constraint for
DR session durability. The failure modes are asymmetric:

- If persist succeeds but ACK fails → relay re-delivers → `drDecrypt` fails
  on the clone (AEAD failure, duplicate message index), error is shown. No
  data loss.
- If ACK succeeds but persist fails → message removed from relay, session
  state not saved → on reload the session is stale → permanent message loss.

### 10.3 Skipped-message handling

The skipped-key cache (`MKSKIPPED`) maps `(DHratchetPub, messageN)` → `MK`.
A key is inserted when messages arrive out of order; it is deleted immediately
after use (one-time consumption).

```
MKSKIPPED["<b64url(DHr)>:<N>"] → Uint8Array(32)
```

The cache is bounded by `MAX_SKIP = 1000` per ratchet chain. If a sender
skips more than 1 000 messages, the receiver raises an error rather than
allocate unbounded memory. This is the same limit as the Signal reference
implementation.

The cache is part of the persisted `DrSession` (serialized as
`MKSKIPPED: Record<string, string>` in the vault). On reload, in-flight
skipped messages can still be decrypted.

### 10.4 Replay Semantics

#### Replay domain definitions

A **replay** is any attempt to have a message accepted more than once. Veil
defines three distinct replay domains, each defended independently:

**Domain R1 — Outer envelope replay** (relay-level)

A replay in this domain is an outer envelope (`v`, `to`, `ek`, `nonce`, `ct`,
`ts`, `pow`) identical to one the relay has already accepted.

*Replay ID*: `SHA-256(to ‖ ek ‖ nonce ‖ ct ‖ ts)` — computed over the raw
base64url bytes of those fields concatenated.

*Defence*: in-memory dedup map with 5-minute TTL (100 K entry cap).

*Residual*: the dedup map is not persisted. A relay restart clears it. The
5-minute timestamp window limits the exposure to the ±5-minute clock skew
already enforced. An envelope replayed after a relay restart is blocked by
the timestamp check as long as `now − ts > 5 min`.

**Domain R2 — Sealed-sender replay** (intermediate)

Changing `to` or any outer field changes the outer replay ID. An attacker who
replays an outer envelope to a *different* recipient succeeds only in delivering
an unreadable blob to that recipient — the inner AEAD is keyed to the original
recipient's identity key. The relay routes on `to`; it cannot detect
cross-recipient replays by envelope content alone.

**Domain R3 — Inner envelope replay** (DR-level)

A replay in this domain is an outer envelope with a modified outer envelope
(bypassing R1) that contains the original inner ciphertext.

*Replay ID*: `(header.dh, header.n)` — the DR ratchet public key and message
counter tuple.

*Defence*: the DR message counter `Nr` advances monotonically within a chain.
An already-consumed `(dh, n)` has no key in `MKSKIPPED` (it was deleted on
first use) and the symmetric chain has already advanced past that counter. The
AEAD tag fails.

*Corner case*: a replayed first message (X3DH block present, `header.n = 0`)
with a *fresh* outer PoW (new `ts`, new `pow`) would bypass R1. Bob's response:
he attempts X3DH receive, which always produces a fresh session. If he already
has an established session with Alice, the replayed first message initiates a
*parallel* session from his side — effectively a simultaneous-initiation edge
case (see §10.13).

**Replay defence summary:**

| Layer | Scope | Survives relay restart? | Survives clock skew? |
|---|---|---|---|
| Outer dedup (R1) | All outer fields | No | N/A — TTL governs |
| Timestamp skew | `ts` field only | Yes | Bounded to ±5 min |
| DR counter (R3) | `(dh, n)` pair | Yes (persisted in vault) | Yes |

### 10.5 Multi-device identity model

Each device `k` derives an independent sub-identity:

```
sub_seed(k) ← HKDF-SHA256(ikm=BIP39_seed, info="veil/identity/v2/device/k", L=64)
IK_Ed(k)    ← Ed25519.from(SHA-256("veil/identity/ed25519/v1" ‖ sub_seed(k)))
IK_X(k)     ← X25519.from(SHA-256("veil/identity/x25519/v1"  ‖ sub_seed(k)))
address(k)  ← "veil1" ‖ Base32(SHA-256(IK_Ed(k) ‖ IK_X(k))[0:20])
```

Consequences and documented trade-offs:

| Property | Value |
|---|---|
| Trust boundary | Each device is a fully independent identity |
| Sender choice | Sender must choose which device address to message |
| OPK isolation | Each device has its own OPK pool; no race conditions |
| Contact UX | Contacts may appear fragmented (multiple addresses per person) |
| Sync | No message history sync between devices (out of scope) |
| DR sessions | Per-device sessions; no cross-device session sharing |

This model trades UX complexity for a simpler trust boundary. The alternative
(Signal-style linked devices sharing a single identity key) requires a trusted
device-linking ceremony and concurrent session management — complexity that
Veil has not implemented and does not plan to implement.

### 10.6 Resource Exhaustion Limits

| Resource | Limit | Behaviour when exceeded |
|---|---|---|
| Per-chain skipped keys (MKSKIPPED) | 1 000 per ratchet epoch (`DR_MAX_SKIP`) | Error; session not advanced; clone intact |
| Total skipped keys (MKSKIPPED) | 2 000 across all epochs (`DR_MAX_SKIP_TOTAL`) | Error; session not advanced; clone intact |
| OPK pool per address | 200 keys (`MAX_PREKEYS_PER_USER`) | Incoming OPKs discarded silently; session still possible using SPK only |
| Relay message queue per address | 1 024 envelopes (`MAX_QUEUE_PER_USER`) | Oldest envelopes evicted; **silent message loss possible** (see §12) |
| ACK batch size | 256 IDs per `ack` message | Excess IDs silently truncated |
| Per-connection delivered-ID tracking | 4 096 entries per WebSocket connection | Oldest entries stop being tracked; those IDs can no longer be acked on this connection |
| Per-IP rate limit | 30 burst / 6 rps token bucket | `rate_limited` error returned; connection stays open |
| WebSocket payload | 1 MiB per frame | Frame rejected by `ws` library; connection closed |
| Relay replay cache | 100 000 entries (in-memory) | Oldest entries evicted; a restarted relay loses the entire cache (5-min clock-skew window provides residual protection) |
| SPK generations kept | 2 per address | Third generation discarded; messages using the oldest SPK will fail to decrypt |

### 10.7 Session Recovery Semantics

**Formal recovery invariants** — the following must hold after any recovery path:

| # | Invariant | Rationale |
|---|---|---|
| R1 | A recovered session either resumes from a persisted state or starts fresh via X3DH | No intermediate states are valid |
| R2 | A session resumed from vault must not re-use any `(dh, n)` pair already used | DR counter monotonicity |
| R3 | A peer that resets their session must send a new X3DH message; the receiver's response must not use the old session's DR keys | Old and new sessions must not interleave |
| R4 | A failed vault write must not advance the relay ACK | Invariant I5; the relay re-delivers |
| R5 | A vault restored from a backup that is older than the last sent message will see AEAD failures on received replies | The restored party's chain key diverges; failure is detectable, not silent |
| R6 | After a session reset, the next outbound message MUST include an X3DH block | The peer has no DR context from the reset party |

**Ratchet state corruption** (vault write-truncation, storage fault):

The vault is an AES-256-GCM blob; truncation or bit-flip causes AEAD
authentication failure on next unlock — the vault does not open. The user
must restore from their recovery phrase. DR sessions are re-established
from the first message received after restoration.

**Session desync** (e.g. one side reverted to a stale vault backup):

The stale party will hold old chain key material. AEAD authentication fails
on all messages sent by the advanced party. The stale party can still SEND
messages; the advanced party's receive will fail at the DR AEAD step (not at
signature verification, since Ed25519 keys are long-term). There is no
automated resynchronisation path. Symptoms: persistent decrypt errors on
one side. Recovery: the stale party uses "Reset session" in the contact
detail panel, which erases local DR state. The next outbound message carries
a fresh X3DH block and restarts the session.

**Skipped-key window exceeded** (>1 000 messages skipped in one chain):

Error raised inside `skipMessageKeys`. The message is discarded. The session
is NOT advanced (clone-before-mutate, invariant I2). The relay will
re-deliver on reconnect (until ACKed or queue expires). No data loss on
the session object.

**Global skipped-key cache full** (>2 000 total entries):

Same error path as above. Additional skip attempts are rejected. The cache
remains intact. The peer must either deliver previously-skipped messages or
the user must execute a manual session reset.

**OPK depletion**:

If the relay has no OPKs on file for a recipient, `claimBundle` returns the
SPK-only bundle (no `prekey` field). The sender proceeds with a 3-DH X3DH
instead of 4-DH. The session is slightly weaker (no OPK forward secrecy) but
functional. The client is notified via `pendingPrekeys: 0` in the `welcome`
message and should immediately publish a fresh batch.

### 10.8 Multi-Tab Race Conditions

The browser client holds DR session state exclusively in memory (`sessionsRef`)
and persists to the IndexedDB vault on each message event. When the same vault
is open in two or more tabs simultaneously:

1. **Send race** — Tab A and Tab B each hold a copy of the session at time *t*.
   If both send to the same peer, each advances its own ratchet copy. The
   recipient receives two messages claiming the same ratchet position; the
   second AEAD decryption fails.

2. **Receive race** — Tab A receives and decrypts a `deliver` event, advancing
   its chain key. Tab B (stale copy) receives the next delivery and tries to
   decrypt with the old chain key — AEAD fails.

3. **Persist race** — Both tabs call `persistVault` concurrently. The IndexedDB
   `put` operations are not coordinated; the last write wins, silently
   discarding the other tab's ratchet advancement.

**Mitigation**: Veil does not implement multi-tab coordination (BroadcastChannel,
SharedWorker, or Web Locks API). **Open Veil in one tab at a time.** If you
observe persistent decrypt errors after using multiple tabs, use the "Reset
session" action in the contact detail panel to force fresh X3DH re-establishment.

**Blast radius**: Limited to DR session failure for the affected peer. The vault
blob remains cryptographically intact (AEAD authentication is unaffected).

### 10.9 IndexedDB Transaction Semantics and Vault Consistency

The vault is a single AES-256-GCM blob stored under one IndexedDB key. All
writes are whole-blob replacements. This has several implications:

1. **Atomicity** — A partial write produces a blob that fails AEAD
   authentication on the next read, effectively reverting to the previous
   committed state. This is the desired behaviour (prefer corruption detection
   over silent data loss).

2. **Crash consistency** — If the browser crashes between `persistVault`
   returning and the relay `ack` being sent, the relay re-delivers. The next
   decrypt attempt encounters the already-advanced ratchet and succeeds via the
   skipped-key cache (or fails if the entry was evicted by the 1 000-key cap).
   The persist-before-ack ordering is intentional: vault durability is
   prioritised over relay-side deletion.

3. **QuotaExceededError** — If the origin's storage quota is exhausted,
   `IDBObjectStore.put()` throws. The message is displayed locally
   (optimistic state) but the ratchet advancement is not persisted. On next
   unlock the stale ratchet may cause decrypt errors. Users should clear
   old messages and retry.

4. **No `localStorage` fallback** — `saveVaultBlob` throws if IndexedDB is
   unavailable. The error message instructs the user to reopen in a regular
   (non-private) window. The `localStorage` write path is disabled entirely
   for new saves; only the read path remains for migrating legacy vaults.

### 10.10 WebSocket Connection State Machine

Each server-side WebSocket connection tracks a state machine with the following
states and transitions:

```
                   ┌──── TCP/TLS accept ────┐
                   │                        │
                   ▼                        │
          CHALLENGE_SENT ──────────────────►│
          (challenge nonce                  │
           sent to client)                  │
                   │                        │
        ┌──────────┴──────────┐             │
        │                     │             │
   hello received        hello received     │
   (no bundle on         (bundle exists)    │
    file)                     │             │
        │               ┌─────┴──────┐      │
        ▼               │            │      │
  BOOTSTRAPPING    sig valid    sig absent  │
  (allow without                or invalid  │
   auth; await               ─────────────►┤
   bundle publish)                   │
        │               ▼            │
        │          AUTHENTICATED     │
        │          (deliver queued   │
        │           msgs; allow ack) │
        └──────────────►│            │
         (after bundle  │            │
          publish)      │            │
                        ▼            │
                  connection close   │
                  on any error ─────►┤
                                     ▼
                               connection closed
```

**State transition table:**

| Current state | Event | Guard | Next state | Action |
|---|---|---|---|---|
| — | TCP accept | — | `CHALLENGE_SENT` | Send 128-bit random nonce |
| `CHALLENGE_SENT` | `hello` received | no bundle on file | `BOOTSTRAPPING` | Send `welcome`; flush queued messages |
| `CHALLENGE_SENT` | `hello` received | bundle exists, sig valid | `AUTHENTICATED` | Mark socket authenticated; send `welcome`; flush queue |
| `CHALLENGE_SENT` | `hello` received | bundle exists, sig absent | — | Send `auth_required`; close |
| `CHALLENGE_SENT` | `hello` received | bundle exists, sig invalid | — | Send `auth_failed`; close |
| `BOOTSTRAPPING` | `publish` received | — | `BOOTSTRAPPING` | Store bundle; subsequent connections must authenticate |
| `BOOTSTRAPPING` | `send` received | rate limit OK | `BOOTSTRAPPING` | Enqueue envelope; send `sent` with `queueDepth` |
| `AUTHENTICATED` | `ack` received | IDs ∈ `deliveredIds` | `AUTHENTICATED` | Delete from DB; remove from `deliveredIds` |
| `AUTHENTICATED` | `ack` received | IDs ∉ `deliveredIds` | `AUTHENTICATED` | Silently ignore unknown IDs |
| Any | rate limit exceeded | — | same | Send `rate_limited`; connection stays open |
| Any | malformed frame | — | — | Close connection |

**Key properties:**
- `deliveredIds` is a per-socket `Set<string>` initialised empty on connection.
  A delivery ID is added when the relay pushes it to this socket. It is removed
  when acked. This prevents an authenticated client from acking IDs delivered
  to a *different* connection of the same address.
- The nonce is single-use and fresh per connection. It is not stored after the
  `hello` is verified.

### 10.11 ACK Semantics

An `ack` message deletes one or more envelopes from the relay queue, preventing
re-delivery. The following conditions ALL must hold for an ACK to be accepted:

```
PRECONDITIONS for ACK acceptance:
  1. socket.state ∈ {AUTHENTICATED, BOOTSTRAPPING}
  2. ∀ id ∈ ack.ids: id ∈ socket.deliveredIds
  3. rate_limit_bucket.tryConsume(1) = true
  4. |ack.ids| ≤ 256

EFFECT on acceptance:
  DELETE FROM relay_envelopes WHERE id = ANY(accepted_ids)
  socket.deliveredIds ∖= accepted_ids

EFFECT on rejection of individual IDs (condition 2 fails):
  Unknown IDs are silently dropped from the batch.
  Known IDs in the same batch are still processed.

EFFECT on rate limit failure (condition 3 fails):
  Entire ack is rejected; error returned; connection stays open.
```

**ACK ordering invariant** (I5 restated formally):

Let `persist(session)` be the IndexedDB write and `ack(ids)` be the relay
deletion. The implementation guarantees:

```
persist(session) completes successfully
        BEFORE
ack(ids) is sent to the relay
```

Violation would result in the relay deleting the envelope before the client
has durably stored the advanced ratchet state. The relay would not re-deliver,
and the ratchet state would be stale on next load, causing permanent decrypt
failures.

**Deliver-before-ACK ordering** (relay side):

The relay sends `deliver` events before the client sends `ack`. The relay does
not mark an envelope as delivered until the `ack` arrives — the envelope
remains in the queue and will be re-delivered on reconnect until acked. This
ensures at-least-once delivery from the relay's perspective.

### 10.12 Failure Mode Classification

Protocol failures are classified into four severity levels:

**Level 1 — Fatal to the connection (close socket)**

| Failure | Cause | Recovery |
|---|---|---|
| `auth_failed` | Invalid Ed25519 hello signature | Reconnect with correct key |
| `auth_required` | Hello sent without signature when bundle exists | Reconnect and include sig |
| Malformed frame | WebSocket frame exceeds 1 MiB or is not valid JSON | Reconnect |

**Level 2 — Fatal to the message (discard; session preserved)**

| Failure | Cause | Recovery |
|---|---|---|
| AEAD authentication failure | Tampered ciphertext, wrong nonce, wrong AAD | Relay re-delivers (if not yet acked); no session mutation |
| Ed25519 signature failure | `inner.sig` does not verify against `inner.fromEd` | Message discarded; no session mutation; clone intact |
| Wrong recipient (`inner.to ≠ address`) | Mis-routed message | Discard silently |
| Timestamp mismatch (`inner.ts ≠ outer.ts`) | Envelope tampering | Discard |
| Unknown `inner.v` | Future protocol version | Discard; log |

**Level 3 — Fatal to the session (session reset required)**

| Failure | Cause | Recovery |
|---|---|---|
| Skip cap exceeded (`DR_MAX_SKIP`) | >1 000 messages skipped in one chain | Manual session reset; re-establish X3DH |
| Global skip cap exceeded (`DR_MAX_SKIP_TOTAL`) | >2 000 total cached keys | Manual session reset |
| Missing SPK for X3DH receive | SPK rotated, old messages arrive | Cannot decrypt; user must reset and peer must re-send |
| Permanent ratchet desync | Stale vault restored; chain keys diverge | Manual session reset on stale side |

**Level 4 — Transient (retryable)**

| Failure | Cause | Recovery |
|---|---|---|
| `QuotaExceededError` | IndexedDB storage full | Clear old messages; retry |
| Rate limit (`rate_limited`) | Token bucket exhausted | Back off and retry |
| IndexedDB unavailable for save | Private browsing mode | Reopen in regular window |
| Network disconnect | Connection lost | Reconnect; relay re-delivers unacked messages |

**Error containment principle**: a Level 2 or Level 3 failure must NEVER cause
a Level 1 event (connection close). The connection remains open so the client
can display an error and the user can attempt recovery without losing other
concurrent functionality.

### 10.13 Simultaneous Session Initiation

When Alice and Bob both send a first message to each other before either
receives the other's message, they each create a session initialised from
the other's bundle. This creates two parallel DR sessions, one on each side.

```
Alice                           Bob
─────                           ───
fetchBundle(Bob)                fetchBundle(Alice)
X3DH(Bob)  → session_AB         X3DH(Alice) → session_BA
send msg_A                      send msg_B
      │                               │
      └──────────── relay ────────────┘
      ▼                               ▼
 recv msg_B                       recv msg_A
 (x3dh block present,             (x3dh block present,
  new session)                     new session)
```

**What happens on receive:**

When Alice receives Bob's message (which has an `x3dh` block), the client checks
whether she already has an established session with Bob:

- If no session exists locally: normal X3DH receive; session established.
- If a session already exists: the incoming `x3dh` block initiates a *new*
  session on Alice's side. The previous session's DR state is discarded and
  replaced by the session initialised from Bob's `x3dh` message.

This is intentional: if both sides simultaneously initiate, the *received*
X3DH message wins, because both parties eventually receive each other's initial
message and converge on a common shared state. The session established from
the received X3DH block is the one that will be used for subsequent messages.

**Convergence**: after processing each other's initial messages, Alice and Bob
each have:
- A local send chain initialised from their own X3DH output.
- A local receive chain initialised from the peer's X3DH output.

These are different chains (different ephemeral keys were used), so they are not
symmetric until the first DH ratchet step, which occurs on the first reply from
either party.

**Current implementation note**: the client does not explicitly detect or
handle the simultaneous-initiation case. It accepts any incoming `x3dh` block
as a new session, overwriting any existing session for that peer. This is
correct for convergence but may cause a briefly confusing UX if messages cross.

---

## 11. Security Properties Summary

### What Veil proves cryptographically

1. **Ciphertext authenticity** — every inner ciphertext is bound to a specific
   `(sender, recipient, timestamp, DR header)` tuple via the Ed25519 signature
   and AES-256-GCM AAD. Neither field alone provides this; both are required.

2. **Forward secrecy** — compromise of a DR chain key at time `t` reveals
   nothing about message keys derived before `t` (HMAC one-way chain).

3. **Post-compromise security** — after a chain key compromise, the next DH
   ratchet step produces a new root key derivation that the compromised party
   cannot predict (requires knowledge of the new ephemeral DH private key).

4. **Sealed sender** — from the relay's view, the outer envelope carries no
   plaintext sender identity. The relay cannot _cryptographically_ identify
   the sender from envelope contents alone. Traffic analysis (IP, timing,
   fetch patterns) is out of scope and not addressed.

5. **OPK non-reuse** — the relay's `FOR UPDATE SKIP LOCKED` + `DELETE`
   guarantees exactly-once OPK consumption under concurrent senders.

6. **Bundle immutability** — the relay refuses to overwrite `edPub` or `xPub`
   for an address that has already published a bundle. Identity keys are sticky
   from first publish, enforced at the database level.

### What Veil does NOT prove

1. **Deniability** — Ed25519 signatures are non-repudiable. A message archive
   with valid signatures is a cryptographic proof of authorship.

2. **Key transparency** — there is no append-only log of identity key
   publications. A malicious relay can swap bundles on first contact.

3. **Traffic analysis resistance** — timing and pattern metadata is visible
   to a network observer of both legs.

4. **Post-quantum security** — all primitives are classical; harvest-now-
   decrypt-later is a real risk for long-term secrets.

5. **Supply-chain integrity** — a compromised npm package or build toolchain
   can subvert any of the above. No SBOM or reproducible build is provided.

---

## 12. Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| No link-layer anonymity | Timing correlation on both legs | Use Tor (planned) |
| TOFU trust model | MITM on first contact possible | Safety number verification (implemented) |
| In-memory replay cache | Clears on relay restart; ±5-min window is residual protection | 5-min clock-skew window limits impact; acceptable for threat model |
| No post-quantum primitives | Harvest-now-decrypt-later risk | Roadmap item |
| No formal audit | Subtle protocol flaws may exist | Document clearly; planned |
| Active device malware | RAM access defeats all crypto | Same as Signal; hardware-bound key storage needed |
| Compelled disclosure | Vault passphrase reveals plaintext | No duress mode (deliberate — false deniability is itself a tell) |
| No multi-device sync for DR sessions | Ratchet state per device | Roadmap |
| IndexedDB unavailable (private-mode) | Saves throw; app unusable without regular window | Actionable error message; cannot silently degrade |
| DR persist-before-ACK | If persist fails, ACK is not sent; relay re-delivers; duplicate fails at AEAD | Acceptable: duplicate AEAD failure is better than message loss |
| PoW vs. botnets | 14-bit PoW slows casual spam; GPU botnets not significantly deterred | Adaptive PoW (roadmap); server-side account reputation (roadmap) |
| Queue overflow — silent message loss | Oldest envelope evicted at 1 024 cap; sender unaware; can advance DR chain key past evicted messages; if skipped-key window exhausted, session permanently wedged | Sender-visible queue-depth toast at >900; "Reset session" UI for recovery |
| Chain key / root key not zeroed | CKs, CKr, RK overwritten by reference; GC copy may linger | JS limitation; hardware-bound key storage eliminates this |
| No automated session recovery | Persistent desync requires manual reset | "Reset session" action in contact panel; fresh X3DH on next send |
| Multi-tab race | Concurrent tabs sharing a vault can corrupt DR state | Open Veil in one tab at a time; "Reset session" recovers |
| Simultaneous session initiation | Both sides may briefly hold divergent sessions | Incoming X3DH overwrites existing session; converges after first reply |
| Ed25519 message signatures | Non-repudiable transcripts; no deniability | Disclosed in goals (§1) and in product UI |
| Bootstrapping window | First connection before bundle publish is unauthenticated | One-time, extremely narrow (milliseconds); after publish, permanent auth |

---

## 13. Threat Model Summary

**Veil protects against:**
- Passive eavesdropper on the relay-recipient link
- Honest-but-curious relay operator (sealed sender + E2EE)
- Spam bots (PoW + rate limits)
- Replay of old messages (5-min dedup window + DR message counters)
- Message tampering (AEAD authentication + Ed25519 sig)
- Key-compromise impersonation (X3DH forward secrecy + DR PCS)
- Message-size correlation (length-bucket padding)
- ACK theft (authenticated hello + per-socket delivered-ID tracking)
- Memory exhaustion via skipped-key flooding (DR_MAX_SKIP + DR_MAX_SKIP_TOTAL)
- Vault exfiltration via `localStorage` downgrade (hard refusal; IndexedDB only)

**Veil does NOT protect against:**
- Active malware with RAM access on a logged-in device
- Passive observation of _both_ network legs simultaneously (timing/traffic analysis)
- Compelled disclosure (passphrase coercion)
- Nation-state–level key-transparency attacks on first contact
- Deniability (Ed25519 signatures are non-repudiable)
- Supply-chain compromise (npm, build tooling, CDN)

---

## 14. Invariant Test Suite

`lib/crypto-core` ships a vitest test suite (`src/__tests__/`) that mechanically
verifies the invariants documented in this specification.

### 14.1 Ratchet tests (`ratchet.test.ts`)

| Test group | Invariants verified |
|---|---|
| In-order delivery | 20-message sequential round-trip; `Ns` counter advances correctly |
| Out-of-order delivery | Reverse and arbitrary permutations; `MKSKIPPED` populated and fully drained |
| Bidirectional / DH ratchet | 6-round Alice↔Bob exchange; `DHsPub` rotates on every reply |
| AAD / AEAD binding | Wrong AAD, wrong nonce, single-bit ciphertext flip all throw; modified `header.n` throws |
| Per-chain skip cap | Skipping exactly `DR_MAX_SKIP` succeeds; `DR_MAX_SKIP + 1` throws "Too many skipped" |
| Global skip cap | `MKSKIPPED` at `DR_MAX_SKIP_TOTAL` causes next skip to throw "cache full" |
| Clone-before-mutate | Failed decrypt on clone leaves original intact; successful clone keeps original at prior state |
| Serialization | Numeric fields, key material, and `MKSKIPPED` entries all survive `serialize → deserialize`; restored session continues the send chain identically |

### 14.2 Identity tests (`identity.test.ts`)

| Test group | Invariants verified |
|---|---|
| Mnemonic validation | Known good phrases pass; garbage rejects; whitespace trimmed |
| Derivation determinism | Same mnemonic → same address + keys; BIP39 passphrase and `deviceIndex` produce distinct identities; `deviceIndex=0` is stable (v1 compatibility) |
| Address format | `veil1` prefix; 37 chars; base32 alphabet `[a-z2-7]{32}`; `isValidAddress` accepts / rejects correctly |
| Safety numbers | Symmetric `A+B == B+A`; 30-digit decimal in 6 groups of 5; deterministic; distinct pairs produce distinct numbers |
| Hello challenge | Sign→verify passes; wrong key, wrong nonce, wrong address, truncated signature all fail |
| OPK signatures | `generatePrekey → verifyPrekey` passes; wrong `edPub` and tampered pub fail; unique IDs |
| SPK signatures | `generateSignedPrekey → verifySignedPrekey` passes; `spkExpired` correct |

### 14.3 Session tests (`session.test.ts`)

| Test group | Invariants verified |
|---|---|
| First message (X3DH) | Round-trip plaintext; correct sender address; OPK consumed; x3dh block present |
| Wrong recipient | Envelope addressed to Bob cannot be decrypted by Alice |
| Subsequent messages | Second message (no X3DH) round-trips; 10 sequential messages all decrypt in order |
| Bidirectional exchange | Alice→Bob→Alice 3-turn exchange using a single shared DR session |
| Bundle validation | Invalid SPK signature throws; address/key mismatch throws |
| Plaintext encoding | Empty string; emoji and multi-byte UTF-8; 500-byte message all round-trip correctly |

### 14.4 Running the tests

```sh
pnpm --filter @workspace/crypto-core run test
# or, from the repo root:
pnpm run test
```

Tests exercise the pure-TypeScript crypto logic only — no browser globals, no
relay, no IndexedDB. PoW is disabled (`powBits: 0`) to keep the suite fast.

---

## 15. Version Stability Policy

### Protocol freeze — v3

Inner envelope version `"v": 3` is **frozen**. The following are guaranteed
not to change without a version bump:

| Component | Frozen |
|---|---|
| Outer envelope field names and types | ✅ |
| Inner envelope v3 field names and types | ✅ |
| Signature payload format (`sigPayloadV3`) | ✅ |
| X3DH DH input order and HKDF parameters | ✅ |
| DR KDF functions (`KDF_RK`, `KDF_CK`) | ✅ |
| DR header fields (`dh`, `pn`, `n`) | ✅ |
| AAD construction string | ✅ |
| DR skip limits (`DR_MAX_SKIP`, `DR_MAX_SKIP_TOTAL`) | ✅ |
| Vault format v3 field names | ✅ |
| Address derivation (`"veil1" ‖ Base32(SHA-256(…)[0:20])`) | ✅ |
| `hello` challenge protocol | ✅ |
| PoW hash construction | ✅ |

### What triggers a version bump

Any of the following changes requires incrementing the inner `v` field to `4`
and providing a documented migration path:

- Change to KDF input material, salt, or info strings
- Change to DR header fields or encrypt/decrypt logic
- Change to the signature payload construction
- Change to AAD construction
- Addition of mandatory new fields to the inner envelope
- Change to address derivation
- Change to X3DH DH input order or count

### What does NOT trigger a version bump

- New optional fields on the inner envelope that receivers can safely ignore
- Relay-side policy changes (PoW difficulty, rate limits, queue size)
- Client UX changes
- Changes to the outer envelope that do not affect the cryptographic layer

### Migration policy

When a new inner version is introduced:

1. A transition period is announced during which both `v: 3` and `v: N` are
   accepted.
2. The transition period is at minimum 30 days from the first release that
   supports `v: N`.
3. Clients that only understand `v: 3` will reject `v: N` messages with an
   "unknown protocol version" error — no silent fallback.
4. Vault format changes are handled by a version field (`VaultData.v`);
   migration is performed lazily on first open.

### Implementation reference

The canonical implementation is `lib/crypto-core/` at the commit tagged
`protocol-v3-freeze`. Any discrepancy between this document and that
implementation is a bug; file an issue or security report as appropriate
(see `SECURITY.md`).

---

_This specification describes protocol version 3. Protocol version 2 (legacy
X3DH without Double Ratchet) remains implemented for backward compatibility
and is auto-detected on incoming messages._
