# 00 — Overview, Threat Model, and System Map

*Reconstructed from Proton's open-source clients and published security design. Sources listed at the end of each chapter.*

## 1. What Proton Mail actually is

Proton Mail is an email service whose central design claim is **zero-access
encryption**: the server stores your mail in a form it cannot read. It achieves
this with **OpenPGP** (the same standard as PGP/GPG), applied automatically and
invisibly, plus an authentication scheme (**SRP**) in which the server never
learns your password.

The whole system is organized around one idea:

> The server is treated as **honest-but-curious and potentially compromised**.
> Everything sensitive is encrypted on the client, under keys the server only
> ever sees in encrypted form.

Everything else — the mail transfer agent, the storage, the web/mobile clients,
the API — is plumbing arranged so that this property holds end to end.

## 2. Threat model (what Proton defends against, and what it does not)

**Defended:**
- A server operator (or anyone who seizes/breaches the servers) reading stored
  mail bodies, attachments, contacts, calendar events, and private keys. All are
  stored as ciphertext the server cannot decrypt.
- Password theft from the server: the server never receives the password (SRP),
  and never holds a key that can decrypt user data.
- The server lying about a recipient's public key to mount a man-in-the-middle
  (defended by **Key Transparency**).

**Explicitly *not* fully defended (honest limitations Proton documents):**
- **Metadata.** Sender, recipient, timestamps, and message **subject lines** are
  *not* end-to-end encrypted — the server needs them to route, thread, and search.
  This is the single most important caveat in the whole design.
- **Inbound mail from non-Proton senders** (e.g. Gmail) arrives in plaintext over
  SMTP. Proton encrypts it to your public key *on arrival* (zero-access), but the
  server does see it for that brief window. This is weaker than true E2E.
- **A malicious client build** pushed to the user. Web delivery means Proton (or
  an attacker who compromises delivery) could in principle ship code that leaks
  the password/keys. Key Transparency and open-source clients mitigate but do not
  eliminate this.
- **Endpoint compromise** (malware on the user's own device).

Keeping this table honest is a goal of this dossier: a reconstruction that claims
more than Proton does would be wrong.

## 3. The two encryption regimes

Proton mail travels under one of two regimes depending on the other party:

1. **Proton → Proton (true end-to-end).** The sender looks up the recipient's
   public key via the API, verifies it against Key Transparency, and encrypts the
   message to it. Only the recipient's private key can open it. The server never
   sees plaintext.

2. **Proton ↔ external world (zero-access, not E2E).**
   - *Incoming* external mail: delivered in cleartext (or opportunistic TLS) to
     Proton's MTA, then **immediately encrypted to the recipient's public key**
     and stored. The server sees it only in transit.
   - *Outgoing* to external: sent over SMTP+TLS. Optionally PGP-encrypted if the
     recipient's key is known, or sent as a **password-protected message**
     ("Encrypt to Outside": a symmetric-encrypted message the recipient opens via
     a link + a shared secret).

## 4. System map

```
                         ┌──────────────────────────────────────────┐
                         │                CLIENTS                     │
                         │  web (TS) · iOS (Swift) · Android (Kotlin) │
                         │  Bridge (Go, exposes IMAP/SMTP to desktop) │
                         │  --- all crypto happens HERE ---           │
                         └───────────────┬────────────────────────────┘
                                         │  HTTPS REST API (SRP auth)
                         ┌───────────────▼────────────────────────────┐
                         │                 API / APP SERVER            │
                         │  auth (SRP) · sessions · mail metadata ·    │
                         │  message store (ciphertext) · settings      │
                         └───┬───────────────┬───────────────┬─────────┘
                             │               │               │
                   ┌─────────▼──────┐ ┌──────▼───────┐ ┌─────▼──────────┐
                   │  KEY SERVER     │ │  MAIL STORE   │ │  MTA (SMTP)     │
                   │  public-key dir │ │  PGP blobs +  │ │  send/receive · │
                   │  encrypted priv │ │  metadata     │ │  encrypt-on-    │
                   │  keys · SKLs    │ │               │ │  arrival hook   │
                   └─────────┬───────┘ └───────────────┘ └────────────────┘
                             │
                   ┌─────────▼───────────────┐
                   │  KEY TRANSPARENCY         │
                   │  Merkle tree of SKLs,     │
                   │  anchored every 4h into   │
                   │  Certificate Transparency │
                   └───────────────────────────┘
```

The chapters that follow open each of these boxes:

- **01 Cryptography** — the key hierarchy that makes "the server can't read it" true.
- **02 Authentication (SRP)** — login without sending a password.
- **03 Key management + Transparency** — how public keys are distributed and kept honest.
- **04 Mail data flow** — the life of a message under each regime.
- **05 System architecture** — the concrete components and their contracts.
- **06 Open-source map** — the real Proton repos these facts come from.
- **07 Reconstruction plan** — how our Java system mirrors all of it.

## Sources

- Proton Mail — Wikipedia (design summary, zero-access): https://en.wikipedia.org/wiki/Proton_Mail
- Proton — "Encryption keys" support: https://proton.me/support/account/security-privacy/encryption-keys
- Proton — Key Transparency support: https://proton.me/support/key-transparency
- Proton — Key Transparency whitepaper (2024): https://proton.me/files/proton_keytransparency_whitepaper.pdf
- Proton — Key Transparency, Transparency Summit 2024 deck: https://transparency.dev/pdfs/summit2024/Key%20Transparency%20Proton.pdf
- "End-to-end encryption with Proton Mail" (dev.to walkthrough): https://dev.to/dhaven/end-to-end-encryption-with-proton-mail-3b63
