# Security Policy

## Project status

Veil is a **research-grade, unaudited** encrypted messenger. It has not
undergone an independent cryptographic audit. Do not rely on it for
operational security in high-risk situations.

## Scope

The following components are in scope for security reports:

| Component | Location |
|---|---|
| Cryptographic library | `lib/crypto-core/` |
| Wire protocol (outer + inner envelope) | `PROTOCOL.md` §7 |
| Relay server | `artifacts/api-server/` |
| Web client | `artifacts/veil/` |
| Vault storage and key derivation | `artifacts/veil/src/lib/store.ts` |

## What is in scope

- Cryptographic protocol bugs (X3DH key agreement, Double Ratchet state
  machine, key derivation, AEAD use)
- Authentication or authorization bypasses on the relay
- Session state corruption or replay attack bypasses
- Information leakage from the relay about sender or message content
- Vault key derivation or storage weaknesses
- Logic errors in the decrypt invariants documented in `PROTOCOL.md` §10.2

## What is NOT in scope

These are **acknowledged limitations**, not reportable vulnerabilities:

- Denial-of-service via resource exhaustion — documented in `PROTOCOL.md`
  §10.6 with explicit limits
- Physical access to an unlocked device (endpoint malware)
- Compelled disclosure / legal orders
- Traffic timing analysis (no mixnet or cover traffic is provided — this is a
  stated non-goal)
- Browser extension compromise or supply-chain attacks on npm packages
- Social engineering attacks
- Vulnerabilities in third-party dependencies that do not affect Veil
  specifically

## Reporting a vulnerability

Open a **private** GitHub Security Advisory on this repository, or email the
maintainer directly (address in the git commit history).

Please include:

- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The affected component and protocol version (`v: 3` for the current inner
  envelope)
- Your assessment of impact and exploitability

We will acknowledge receipt within **72 hours** and aim to triage within
**7 days**. Critical issues (remote code execution, full session compromise,
relay information disclosure) will be prioritised.

## Disclosure policy

- We investigate all in-scope reports.
- We will coordinate a disclosure timeline with the reporter.
- We aim to ship a patch within **14 days** of a confirmed critical finding,
  **30 days** for high-severity findings.
- We will credit reporters in the changelog unless they request anonymity.
- We do not offer a bug bounty at this time — Veil is a research project
  with no commercial backing.
- We follow a **90-day default disclosure deadline**: if we have not shipped
  a fix within 90 days, we encourage reporters to publish their findings.

## Protocol version stability

Protocol v3 (inner envelope `"v": 3`) is declared **stable**. See
`PROTOCOL.md` §15 for the version stability policy.

Breaking changes to the wire format, vault format, or ratchet semantics will
require a new version number and a documented migration path.

## What "production ready" does and does not mean for Veil

Veil currently meets:

- ✅ Stable, documented protocol (v3)
- ✅ No known critical vulnerabilities
- ✅ Mechanically-verified cryptographic invariants (67-test vitest suite)
- ✅ Documented threat model with explicit non-goals
- ✅ Hardened relay: authenticated hello, rate limiting, PoW, sealed sender

Veil does **not** yet meet:

- ❌ Independent third-party cryptographic audit
- ❌ Reproducible builds
- ❌ Key transparency / append-only bundle log
- ❌ Native clients (browser is the primary target)
- ❌ Security disclosure infrastructure (email alias, CVE process)
- ❌ CI security pipeline (dependency scanning, SAST)

Users should factor this gap into their threat model.

## Threat model scope

Veil is designed for:

- Private communication between parties who share an out-of-band channel
  for safety-number verification
- Strong cryptographic transport: confidentiality, authenticity, forward
  secrecy, post-compromise security
- Relay confidentiality: the relay operator cannot read message content or
  cryptographically identify senders
- Metadata reduction: message length hiding, sealed sender

Veil is **NOT** designed for:

- Whistleblower operations or source protection
- Operational clandestine tradecraft
- Protection against nation-state-level network surveillance
- Anonymous communication (no mixnet, no cover traffic)
- Resistance to malware on the endpoint
- Anti-forensics or secure deletion guarantees
- Coercion resistance (no duress mode)
