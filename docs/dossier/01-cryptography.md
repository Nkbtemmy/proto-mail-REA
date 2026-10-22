# 01 — Cryptography and the Key Hierarchy

*This is the heart of Proton Mail. Everything else exists to preserve the property this chapter establishes: the server holds private keys only as ciphertext it cannot decrypt.*

## 1. Building block: OpenPGP hybrid encryption

Proton uses standard **OpenPGP** (RFC 4880, and the newer "crypto-refresh"
RFC 9580). A message is never encrypted with a public key directly. Instead:

1. A fresh random **session key** is generated per message (symmetric, AES-256
   or similar).
2. The message body (and each attachment) is encrypted **symmetrically** with the
   session key → a *Symmetrically Encrypted Integrity Protected Data* packet.
3. The session key is then encrypted **once per recipient** to that recipient's
   public key → a *Public-Key Encrypted Session Key* (PKESK) packet.
4. The whole thing is (optionally) **signed** with the sender's private key.

So a Proton message to N recipients = one encrypted body + N wrapped session keys.
This is ordinary OpenPGP; Proton's contribution is *where the keys come from and
how they are protected*, which is the rest of this chapter.

- **Modern default algorithms:** Curve25519 — **X25519** for encryption (ECDH) and
  **Ed25519** for signatures (EdDSA). Legacy/compatibility keys may be **RSA
  2048/4096**. Users may choose; weak or non-standardized keys are rejected.

## 2. The key hierarchy

Proton keys form a tree. From the top:

```
         password  ───────────────────────────────────────────┐
             │ (derivation #1: key passphrase via bcrypt+salt)  │ (derivation #2:
             ▼                                                   │  SRP verifier —
     ┌───────────────┐                                           │  see chapter 02)
     │  USER KEY      │  OpenPGP keypair.                         │
     │  (account key) │  Private key stored ENCRYPTED under      │
     └──────┬─────────┘  the key passphrase.                     ▼
            │ decrypts                                     (authentication,
            ▼                                               never touches keys)
     ┌───────────────────────────┐
     │  ADDRESS KEY TOKEN(s)       │  A random passphrase ("token") per address key,
     │  (encrypted to USER KEY,    │  stored encrypted to the user key and signed.
     │   signed)                   │
     └──────┬──────────────────────┘
            │ unlocks
            ▼
     ┌───────────────────────────┐
     │  ADDRESS KEY(s)             │  OpenPGP keypair per email address.
     │  one+ per email address     │  Private key stored ENCRYPTED under its token.
     └───────────────────────────┘  THIS is what encrypts/decrypts mail content.
```

### Unlock sequence (what happens at login, client-side)
1. Client has the user's password and fetches the **key salt** from the server.
2. `keyPassphrase = bcrypt(password, keySalt)` → unlocks the **user private key**.
3. For each address key: decrypt its **token** using the user private key (and
   verify the token's signature), then use the token to unlock the **address
   private key**.
4. The address private keys now live in client memory and are used to
   decrypt/sign mail. They are *never* sent to the server unencrypted.

### Why two levels (user key + address keys)?
- The **user key** protects account-wide data (notably the encrypted **contacts**)
  and acts as the trust root that signs/wraps address-key tokens.
- **Address keys** isolate each identity. You can add/rotate an address key, or
  add a whole address, without re-encrypting everything else — only a new token
  (encrypted to the user key) is created.

### Older / alternate shape
Earlier Proton accounts encrypted each address key's private key **directly** with
the mailbox password passphrase (no per-address token). The token-wrapped model is
the current one and is what Key Transparency's signed key lists assume. A faithful
reconstruction should implement the token model and may ignore the legacy shape.

## 3. Single-password vs two-password mode

The password does **two independent jobs**. How many passwords cover those jobs is
a mode:

| Mode | Login/auth (SRP) | Key passphrase (unlock keys) |
|------|------------------|------------------------------|
| **Single-password (default today)** | derived from the one password | derived from the *same* password, via a different salt/derivation |
| **Two-password (legacy/opt-in)** | "login password" | separate "mailbox password" |

Crucially, even in single-password mode the two derivations are **separate**: the
value sent for authentication can never be used to decrypt keys, and vice versa.
The server stores the SRP *verifier* and the *key salt*; from neither can it
recover the password or the keys.

## 4. What the server stores (and what it can do with it)

| Item | Stored form | Can the server use it? |
|------|-------------|------------------------|
| User public key | plaintext (it's public) | yes — hand it out |
| User **private** key | OpenPGP, encrypted under key passphrase | **no** — passphrase never reaches server |
| Address public keys | plaintext | yes — publish via key directory |
| Address **private** keys | OpenPGP, encrypted under token | **no** |
| Address-key tokens | encrypted to user key, signed | **no** |
| Key salt | plaintext (random) | only to let the client derive the passphrase |
| SRP verifier | plaintext | only to run SRP (can't invert to password) |
| Mail body / attachments | OpenPGP ciphertext | **no** |
| Contacts (sensitive fields) | OpenPGP ciphertext (+ signed) | **no** |
| Metadata (from/to/subject/time) | **plaintext / server-readable** | yes — this is the documented gap |

## 5. Contacts: zero-access + signed

Contacts deserve a note because they show Proton's "encrypted *and* signed" pattern.
A vCard is split into fields that are:
- **cleartext + signed** (e.g. the email address itself — needed to send to it, but
  signed so the server can't tamper), and
- **encrypted + signed** (e.g. notes, phone numbers — zero-access).

The signature is made by the **user key**, so a client can detect server tampering
of even the cleartext fields.

## 6. Implications for our reconstruction

Our Java `crypto` core (drafted with manzi, see `ai-collab/`) must provide:
- OpenPGP keypair generation (Curve25519 default, RSA option) with **encrypted**
  private-key export.
- Hybrid encrypt-and-sign / decrypt-and-verify to/from armored keys.
- A **key-derivation** module: `bcrypt(password, salt) → passphrase`.
- A **token** module: generate random token, encrypt-to-user-key + sign, and the
  inverse unlock path.
- Separation of the auth derivation (chapter 02) from the key derivation.

## Sources

- Proton — "Encryption keys" / key management support pages: https://proton.me/support/account/security-privacy/encryption-keys
- Proton — GopenPGP (high-level OpenPGP in Go): https://github.com/ProtonMail/gopenpgp
- Proton — go-crypto (fork of x/crypto, OpenPGP, RFC 9580): https://github.com/ProtonMail/go-crypto
- OpenPGP.js (Proton-maintained JS OpenPGP): https://github.com/openpgpjs/openpgpjs
- "End-to-end encryption with Proton Mail" (walkthrough of user key / address key / token): https://dev.to/dhaven/end-to-end-encryption-with-proton-mail-3b63
- RFC 9580 (OpenPGP): https://www.rfc-editor.org/rfc/rfc9580.html
