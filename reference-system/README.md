# ReconMail reference system

A working, test-verified reconstruction of Proton Mail's core, built from the
dossier in `../docs/dossier/`. Multi-module Maven, **Java 25**, **Bouncy Castle**.

## Quick start

```bash
# build + run all tests (29 tests)
mvn -f reference-system/pom.xml test

# run the end-to-end demo (register → SRP login → E2E send → encrypt-on-arrival → read)
mvn -f reference-system/pom.xml -q -DskipTests install
mvn -f reference-system/app/pom.xml -q -Dexec.mainClass=com.reconmail.app.EndToEndScenario exec:java
```

## Modules

| Module | What it is | Dossier | Tests |
|--------|------------|---------|-------|
| `crypto` | OpenPGP core (`PgpCrypto`): keygen, encrypt+sign, decrypt+verify, detached sign/verify; `KeyDerivation` (bcrypt); `AddressKeyFactory` (token model) | ch. 01 | 8 |
| `srp` | SRP-6a engine (`SrpClient`/`SrpServer`, `SrpCredentials`), RFC 5054 2048-bit group | ch. 02 | 2 |
| `keyserver` | `KeyServer` facade: encrypted vault + public-key directory; `SignedKeyLists`; `MerkleTree` + `KeyTransparency` (epochs, chain hash, inclusion proofs); `api.*` wire DTOs | ch. 03, 05 | 13 |
| `auth-server` | `AuthService`: SRP login, signed modulus, session tokens | ch. 02 | 3 |
| `mail` | `MailStore` + `MailPipeline` (encrypt-on-arrival); `StoredMessage`/`Envelope` | ch. 04 | 2 |
| `app` | `EndToEndScenario`: the whole flow wired together, as a test and a runnable demo | ch. 07 | 1 |

## What this reconstruction proves

Running `EndToEndScenario` demonstrates, with assertions:

- login over **SRP** with the **signed modulus verified** (no password on the wire),
- the full **key hierarchy** (password → user key → token → address key),
- **Key Transparency**-verified recipient key lookup before sending,
- **end-to-end** Proton→Proton encryption with a verified signature,
- **encrypt-on-arrival** for external inbound mail,
- and that the server stored **only ciphertext** for message bodies — while the
  **subject stayed readable**, faithfully reproducing Proton's documented metadata
  caveat.

## Deliberate simplifications (see dossier ch. 07 §4)

- **RSA-3072** keys (Proton defaults to **Curve25519**; a drop-in second profile).
- **Simulated** CT-log anchoring (the Merkle tree, chaining, and proofs are real).
- **In-process library modules** instead of networked services. The dossier (ch. 05)
  specifies the HTTP/Postgres/Apache-James/Caddy/`docker-compose` deployment form;
  that packaging (M9) is the documented remaining work.

## Human + AI collaboration

Parts were drafted by the local Qwen model (`manzi-14b`); every delegation and its
review verdict are in `../ai-collab/`. Correctness-critical code (all crypto, SRP,
and Merkle/KT logic) was written and verified by Claude; `manzi` contributed the
data-transfer records. Nothing from `manzi` was merged without compiling + testing.
