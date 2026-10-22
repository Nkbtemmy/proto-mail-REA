# 04 — Mail Data Flow

*The life of a message under each regime. This chapter ties chapters 01–03
together: keys (01) are unlocked at login, looked up and verified (03), and used
here to keep the server blind to content.*

## 1. Proton → Proton (true end-to-end)

```
Alice (client)                      server                      Bob (client)
   │ 1. GET /keys?email=bob  ───────────▶ directory + KT inclusion proof
   │ 2. verify Bob's key against KT epoch root
   │ 3. session key SK = random; body ← AES-256(SK)
   │    SK ← wrap to Bob's public key; sign with Alice's addr key
   │ 4. POST /messages {ciphertext, metadata} ─▶ store PGP blob + metadata
   │                                             (server sees only ciphertext)
   │                                                   5. GET /messages ──────▶│
   │                                                   6. unwrap SK with Bob's │
   │                                                      addr key; decrypt;   │
   │                                                      verify Alice's sig   │
```

Server stores: the OpenPGP blob (opaque) + metadata (From/To/Subject/time/labels)
in the clear. It never holds a key that opens the blob.

## 2. Incoming from the outside world (zero-access, **not** E2E)

External senders (Gmail, etc.) don't have Bob's PGP key, so mail arrives in
cleartext over SMTP. Proton makes it zero-access **on arrival**:

```
external MTA ──SMTP(+TLS)──▶ Proton MTA (Apache James)
                                  │ 1. accept; run SPF/DKIM/DMARC → store result as metadata
                                  │ 2. ENCRYPT-ON-ARRIVAL: wrap body to Bob's public key
                                  │    (session key + PKESK, exactly like §1 but server-side)
                                  │ 3. store PGP blob + metadata; discard plaintext
                                  ▼
                            Bob decrypts client-side with his address key
```

The honest caveat (chapter 00): for the brief window between step 1 and step 3 the
server holds plaintext. After step 3 it cannot read it. This is weaker than E2E and
Proton says so.

## 3. Outgoing to the outside world

Three sub-cases, chosen per-recipient:

| Recipient | How it's sent |
|-----------|---------------|
| Has a known PGP key (e.g. another PGP user, or pinned key) | Encrypt+sign to their key, send as PGP/MIME over SMTP |
| No PGP key, normal email | Send over SMTP with opportunistic **TLS**; not E2E |
| No PGP key, but Alice wants confidentiality | **"Encrypt to Outside"** — see §4 |

## 4. "Encrypt to Outside" (password-protected messages)

For a recipient with no key, Alice sets a **message password**. The body is
encrypted **symmetrically** under a key derived from that password; the recipient
gets a link to a Proton-hosted page and types the password (shared out-of-band) to
decrypt in their browser. Replies from that page are encrypted back to Alice. The
server stores only the symmetric ciphertext; the password never reaches it.

## 5. What is stored, and what stays readable

| Field | Stored form |
|-------|-------------|
| Body, attachments | OpenPGP ciphertext (per-attachment session keys) |
| From / To / Cc | server-readable (routing) |
| **Subject** | server-readable (**not** encrypted) — the key metadata caveat |
| Timestamp, size, flags, labels/folders | server-readable |
| Authentication results (SPF/DKIM/DMARC) | server-computed metadata |

**Search:** because bodies are ciphertext, the server cannot search them. Proton
builds an **encrypted search index on the client** (downloaded, searched locally)
for full-text search — an optional feature, not server-side.

## 6. Address-key selection and signing

- A user may have multiple address keys; one is **primary** (used to sign and as
  the default encryption target). Older keys remain to decrypt old mail.
- Outgoing Proton mail is **signed** with the sending address's primary key, so
  recipients (and KT) can verify authorship.

## 7. Implications for our reconstruction

- `mail-pipeline` (Apache James mailet) implements **encrypt-on-arrival**: a
  server-side hook that wraps inbound plaintext to the recipient's public key
  using the chapter-01 crypto core, then hands James a ciphertext message to store.
- `api` exposes `POST /messages` (store), `GET /messages` (fetch ciphertext +
  metadata), and the send paths.
- Proton→Proton send is done **client-side** (our minimal client / test harness):
  look up key via `keyserver`, verify, `encryptAndSign`, post.
- "Encrypt to Outside" is implemented as a symmetric-password message type
  (documented; built if time allows).
- Metadata (incl. subject) is stored in the clear **by design**, matching Proton,
  and documented as such so we don't overclaim.

## Sources

- Proton — "What is zero-access encryption": https://proton.me/blog/zero-access-encryption
- Proton — "Why subject lines aren't encrypted" / security details: https://proton.me/support/proton-mail-encryption-explained
- Proton — encrypted search: https://proton.me/blog/search-mail-encryption
- Apache James (the MTA Proton-style systems build on): https://james.apache.org/
- "End-to-end encryption with Proton Mail" (data flow walkthrough): https://dev.to/dhaven/end-to-end-encryption-with-proton-mail-3b63
