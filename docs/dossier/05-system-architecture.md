# 05 — System Architecture

*The concrete components, their contracts, and the trust boundaries. This is the
blueprint the reference system (`reference-system/`) implements.*

## 1. Components and trust boundaries

```
                        ══════════ TRUSTED (client) ══════════
                        │  client: holds password + unlocked  │
                        │  private keys; does ALL crypto       │
                        ═══════════════════╤══════════════════
                                           │ HTTPS REST (SRP-authenticated)
┌──────────────────────────────────────────┴───────────────────────────────────┐
│                          UNTRUSTED (server side)                               │
│                                                                                │
│  ┌────────────┐   ┌───────────────┐   ┌───────────────┐   ┌────────────────┐  │
│  │ API/app    │   │ auth server    │   │ key server     │   │ MTA (James)    │  │
│  │ messages,  │◀─▶│ SRP, 2FA,      │   │ vault + public │   │ SMTP in/out +  │  │
│  │ labels,    │   │ sessions,      │   │ key directory  │   │ encrypt-on-    │  │
│  │ settings   │   │ tokens         │   │ + SKL + KT     │   │ arrival        │  │
│  └─────┬──────┘   └───────┬────────┘   └───────┬────────┘   └───────┬────────┘  │
│        │                  │                    │                    │           │
│  ┌─────▼──────────────────▼────────────────────▼────────────────────▼───────┐  │
│  │                        data stores (all server-readable EXCEPT blobs)      │  │
│  │  users(salt,verifier,version,encUserKey) · addresses(encAddrKey,token,SKL) │  │
│  │  messages(metadata + blobRef) · blobstore(PGP ciphertext) · kt_epochs      │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
        ▲ reverse proxy / TLS termination (Caddy) sits in front of all HTTP
```

The single most important line is the trust boundary: **everything below it is
assumed hostile**, and the design still holds because what's below only ever sees
ciphertext and SRP verifiers.

## 2. Component contracts

### auth server (SRP)
- `POST /auth/info {username}` → `{modulus(signed), serverEphemeral B, salt, srpSession, version}`
- `POST /auth {srpSession, clientEphemeral A, clientProof M1}` → `{serverProof M2, accessToken, refreshToken, uid, scope, twoFA?}`
- `POST /auth/2fa {uid, totp|fido2}` → elevates scope
- `POST /auth/refresh {refreshToken}` → new access token

### key server
- `POST /keys` (authed) → store encrypted key rings + salt
- `GET /keys?email=` → `{keys:[{publicKey, flags, primary}], sklProof}`
- `GET /kt/epoch/{id}` → `{rootHash, chainHash, ctAnchor}`; `GET /kt/proof?email=` → inclusion proof

### API / app server
- `POST /messages` (authed) → store `{ciphertextBlob, metadata}`
- `GET /messages`, `GET /messages/{id}` → metadata + blob
- `POST /messages/send` → route per recipient (Proton vs external, §04)

### MTA (Apache James)
- SMTP :25 inbound → **encrypt-on-arrival mailet** → store ciphertext via API
- SMTP submission :587 outbound → send per the §04 rules

## 3. Data model (minimum viable)

```
users       (id, username, email, key_salt, srp_salt, srp_verifier, srp_version,
             enc_user_privkey, user_pubkey, created_at)
addresses   (id, user_id, email, enc_addr_privkey, addr_token, addr_pubkey,
             skl_json, skl_signature, primary, flags)
messages    (id, user_id, from_addr, to_addrs, subject, ts, flags, labels,
             blob_ref, has_signature)
blobs       (ref, bytes)                         -- opaque PGP ciphertext
kt_epochs   (epoch_id, root_hash, chain_hash, ct_anchor, created_at)
sessions    (uid, user_id, access_token, refresh_token, scope, expires_at)
```

Note which columns are plaintext (everything except `enc_*`, `blob`, and the PGP
`*_privkey` fields) — that is the metadata surface from chapter 00, on purpose.

## 4. Mapping to the reference system

| Architecture box | Reference module | State |
|------------------|------------------|-------|
| crypto primitives | `crypto` (Bouncy Castle) | ✅ built + tested |
| SRP engine | `srp` | ✅ built + tested |
| auth server | `auth-server` (Spring Boot) | ⏳ next |
| key server + SKL + KT | `keyserver` (Spring Boot) | ⏳ next |
| API/app server | `api` (Spring Boot) | ⏳ |
| MTA + encrypt-on-arrival | `mail-pipeline` (Apache James mailet) | ⏳ |
| client / test harness | `client` (CLI) | ⏳ |
| reverse proxy | Caddy (config only) | ⏳ |

## 5. Deployment shape

A `docker-compose` stack: Caddy (TLS) → {auth, key, api} Spring services + James
MTA + a database (Postgres) + blob volume. Mirrors how a Proton-like system runs,
scaled down to one host for study.

## Sources

- Proton — architecture overview / security features: https://proton.me/blog/security-features
- Proton Bridge (shows the client/server split in Go): https://github.com/ProtonMail/proton-bridge
- Apache James: https://james.apache.org/
- Caddy: https://caddyserver.com/docs/
