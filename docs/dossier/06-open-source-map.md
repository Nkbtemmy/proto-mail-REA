# 06 — Open-Source Map (our primary sources)

*This project is Option A: reconstruct from Proton's **own** open-source code and
published papers. This chapter is the index of those sources — what each repo
teaches and where it feeds our build. These are reference material to **learn
from**, not code to copy; most are GPL-3.0 and this reconstruction is an
independent, clean-room learning system.*

## 1. Proton's own repositories

| Repo | Lang | What it authoritatively shows | Feeds our |
|------|------|-------------------------------|-----------|
| **ProtonMail/WebClients** | TypeScript | The web client monorepo: how the client orchestrates key unlock, message encryption, API calls, KT checks | overall flow, API shapes |
| **ProtonMail/go-srp** | Go | The exact SRP wire format: signed modulus, versioned password hashing, proof construction | `srp` (wire-exactness notes), `auth-server` |
| **ProtonMail/gopenpgp** | Go | High-level OpenPGP usage patterns (encrypt/sign/verify, key handling) as Proton uses them | `crypto` cross-check |
| **ProtonMail/go-crypto** | Go | Proton's fork of `x/crypto` with OpenPGP incl. RFC 9580 (crypto-refresh), Curve25519 | `crypto` (ECC profile) |
| **openpgpjs/openpgpjs** | JS | The OpenPGP implementation the web client runs in-browser | client crypto model |
| **ProtonMail/proton-bridge** | Go | The desktop bridge: local IMAP/SMTP, how decrypted mail is exposed to Thunderbird/Outlook | `client`, bridge concept |
| **ProtonMail/go-proton-api** | Go | The server API surface as a Go client sees it (endpoints, payloads) | `api`, `auth-server` contracts |
| **ProtonMail/proton-python-client** | Python | The most *readable* SRP + auth reference (good for porting) | `srp`, `auth-server` |
| **ProtonMail/protoncore_android** | Kotlin | Cross-platform core incl. the **key-transparency** module and signed key lists | `keyserver` (SKL/KT) |
| **ProtonMail/android-mail**, **ios-mail** | Kotlin / Swift | Full mobile clients; key handling, auth, KT on device | design cross-check |

## 2. Specifications and papers

| Source | What it pins down |
|--------|-------------------|
| **Key Transparency whitepaper (2024)** | Merkle-tree epochs, chain hash, CT anchoring, auditor invariants |
| **Transparency Summit 2024 deck** | The 4-hour epoch cadence and `keytransparency.ch` certificate scheme |
| **RFC 9580 / 4880 (OpenPGP)** | Packet formats, hybrid encryption, signatures |
| **RFC 5054 (SRP for TLS)** | SRP-6a group parameters + derivation we based `srp` on |
| **RFC 6962 (Certificate Transparency)** | The append-only log KT anchors into |
| **Proton patent US 8,689,003** | Proton's own description of its SRP-based auth |

## 3. Independent clean-room references (useful cross-checks)

| Project | Why it helps |
|---------|--------------|
| **emersion/hydroxide** (Go) | A third-party open-source Proton bridge that documents the API + SRP flow from the outside — excellent clean-room corroboration |
| Community write-ups (dev.to, etc.) | Plain-language confirmations of the user-key/address-key/token model |

## 4. How to use these ethically

- **Read to understand**, re-implement in our own words/structure (that's what a
  dossier-driven reconstruction is).
- Respect licenses: GPL-3.0 code read for learning ≠ pasted into a differently
  licensed product. Our `reference-system/` is original code written from the
  dossier.
- Never use any of this to deploy something that impersonates Proton or handles
  real users' Proton credentials. This is a study system.

## Sources

- Proton GitHub org: https://github.com/ProtonMail
- go-srp: https://github.com/ProtonMail/go-srp · gopenpgp: https://github.com/ProtonMail/gopenpgp · go-crypto: https://github.com/ProtonMail/go-crypto
- WebClients: https://github.com/ProtonMail/WebClients · proton-bridge: https://github.com/ProtonMail/proton-bridge
- proton-python-client: https://github.com/ProtonMail/proton-python-client · protoncore_android: https://github.com/ProtonMail/protoncore_android
- OpenPGP.js: https://github.com/openpgpjs/openpgpjs · hydroxide: https://github.com/emersion/hydroxide
- KT whitepaper: https://proton.me/files/proton_keytransparency_whitepaper.pdf
