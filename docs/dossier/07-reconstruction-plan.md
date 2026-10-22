# 07 — Reconstruction Plan

*How the dossier becomes working software. This is the bridge from "how Proton
works" (chapters 00–06) to `reference-system/`.*

## 1. Scope

**In scope (the heart + its plumbing):** crypto core, SRP auth, key server with
SKL + Key Transparency, mail pipeline with encrypt-on-arrival, an API, and a
minimal client that proves end-to-end flow.

**Parked (documented, not built now):** calendar, drive, VPN, contacts manager,
mobile clients, full webmail UI. These reuse the same crypto/auth foundation, so
they are extensions, not new concepts.

## 2. Concept → code mapping

| Proton concept (dossier ch.) | Reference class/module |
|------------------------------|------------------------|
| OpenPGP hybrid encrypt/sign (01) | `crypto` · `PgpCrypto` ✅ |
| User/address keys, key passphrase (01) | `crypto` · `KeyDerivation` ✅ (token model: next) |
| SRP-6a handshake (02) | `srp` · `SrpClient`/`SrpServer` ✅ |
| Versioned password hash, signed modulus (02) | `srp` + `auth-server` ⏳ |
| Encrypted key vault + directory (03) | `keyserver` ⏳ |
| Signed Key List (03) | `keyserver` · `SignedKeyList` ⏳ |
| Key Transparency epochs + proofs (03) | `keyserver` · `KtMerkleTree`, `KtEpoch` ⏳ |
| Encrypt-on-arrival (04) | `mail-pipeline` · James mailet ⏳ |
| Message store + metadata (04/05) | `api` + Postgres ⏳ |
| Proton→Proton send (04) | `client` ⏳ |

## 3. Build order & milestones

1. ✅ **M1 — crypto core** (`crypto`): keygen, encrypt+sign, decrypt+verify,
   detached sign/verify, key derivation. *8 tests.*
2. ✅ **M2 — SRP engine** (`srp`): full handshake, wrong-password rejection. *2 tests.*
3. ✅ **M3 — address-key token model** (`crypto`): random token per address key,
   token encrypted-to-user-key + signed, unlock path. *(completes ch. 01)*
4. ✅ **M4 — key server** (`keyserver`): vault + directory + SKL generate/verify +
   KT Merkle tree with inclusion proofs (CT anchor simulated). *13 tests.*
5. ✅ **M5 — auth server** (`auth-server`): SRP login, signed modulus, sessions. *3 tests.*
6. ✅ **M6 — mail store + metadata** (`mail`): in-memory store + envelopes. *(HTTP API
   + Postgres = deployment form, parked — the `api` DTOs describe the wire contract)*
7. ✅ **M7 — mail pipeline** (`mail`): encrypt-on-arrival. *2 tests.* *(Apache James
   integration = deployment form, parked)*
8. ✅ **M8 — client / end-to-end** (`app`): register → SRP login → KT-verified key
   lookup → send Proton→Proton → encrypt-on-arrival → read. *1 scenario test; also a
   runnable demo (`mvn -pl app exec:java`).*
9. ✅ **M9 — networked form** (`api`): a JDK-HttpServer + Jackson HTTP API over all
   services, proven by an integration test over real HTTP; an executable jar
   (`reconmail-api.jar`) verified to serve HTTP; `Dockerfile` + `docker-compose` +
   Caddy. *(A full multi-container split + Postgres is the only packaging left.)*
10. ✅ **Curve25519 profile** (`crypto`): Ed25519 + X25519, matching Proton's default.
11. ✅ **Apache James mailet** (`mta`): a real `GenericMailet` (encrypt-on-arrival)
    compiled against the James 3.8.0 API.

12. ✅ **Split into microservices + persistence**: the HTTP layer is split into
    separate `auth` / `keys` / `mail` services behind a `gateway` (the mail service
    calls the key service over HTTP), each backed by a durable embedded **H2**
    database (`persistence` module). Verified by `DistributedIntegrationTest` (full
    flow through the gateway) and `PersistenceRestartTest` (state survives a
    restart). Multi-container `docker-compose` + Caddy + a `Makefile` package it.

**Status: 10 modules, 45 tests, `mvn test` green.** The system is implemented and
verified end to end — in-process, over HTTP, as separate networked services behind a
gateway, and durably across restarts. Postgres instead of H2 is a JDBC driver swap.

## 4. Deliberate simplifications vs Proton (stated honestly)

| We do | Proton does | Why the gap is OK |
|-------|-------------|-------------------|
| RSA-3072 default keys | Curve25519 default | RSA path is easiest to pin+verify first; ECC is a drop-in second profile (go-crypto shows it) |
| Simulated CT anchoring | Real certs on `keytransparency.ch` logged to CT | The Merkle tree, chain hash, and inclusion proofs are real; only the external CT mint is stubbed |
| RFC 5054 x-derivation in `srp` tests | Versioned bcrypt + expandHash | Wire-exact hashing is isolated behind the version field; swap in to interop |
| Postgres single host | Sharded production infra | Study system, one host |
| Subject/metadata in clear | Same (in clear) | Faithful — not a simplification, a documented property |

## 5. How manzi (Qwen 14B) is used per module

Lesson from M1/M2 (see `ai-collab/`): manzi hallucinates intricate library APIs
and protocol math, but is useful for **self-contained, well-trodden Java**.

- **Good to delegate:** DTO/record classes, JSON (de)serialization POJOs, plain
  CRUD repository interfaces, straightforward JUnit test skeletons, utility
  methods with a precise spec.
- **Claude writes:** anything touching Bouncy Castle, the SRP/Merkle math, the KT
  proof logic, security-sensitive validation, and all integration.
- **Always:** prompt → `ai-collab/prompts/`, output → `ai-collab/outputs/`, a
  `*.REVIEW.md` verdict, and nothing merged unverified.

## 6. Definition of done for the whole project

A reviewer can: read the dossier and understand Proton's design; run
`docker-compose up`; use the `client` to register two users, log in over SRP,
send an end-to-end-encrypted message between them, and confirm via the database
that the server stored **only ciphertext** for the body — while the dossier's
honest caveats (metadata, incoming-mail window) are reproduced faithfully.
