# ReconMail — Getting Started

*Structure drafted by manzi (A3); technical claims corrected by Claude (manzi had
invented "HKDF/AES-GCM"). Sample CLI outputs below are illustrative.*

## Prerequisites
- Java 25
- Maven 3.9+

## Build & test
```bash
mvn -f reference-system/pom.xml test     # ~38 tests
```

## Interactive CLI
```bash
mvn -f reference-system/cli/pom.xml -q -Dexec.mainClass=com.reconmail.cli.Cli exec:java
```
Example session:
```
reconmail> register alice@recon.test alice-pw
registered alice@recon.test (KT epoch #1)
reconmail> register bob@recon.test bob-pw
registered bob@recon.test (KT epoch #2)
reconmail> login alice@recon.test alice-pw
login alice@recon.test: OK (signed modulus verified, SRP proof exchanged)
reconmail> send alice@recon.test bob@recon.test Lunch? see-you-at-noon
sent (id=1a2b3c4d); server stored 1416 chars of ciphertext
reconmail> read bob@recon.test 1a2b3c4d alice@recon.test
subject="Lunch?" body="see-you-at-noon" signatureValid=true
reconmail> inbox bob@recon.test
inbox of bob@recon.test:
  [1a2b3c4d] from=alice@recon.test subject="Lunch?"
reconmail> accounts
accounts: alice@recon.test, bob@recon.test
reconmail> external friend@gmail.com bob@recon.test Hi hello-from-outside
delivered external mail to bob@recon.test (id=...)
```

## End-to-end demo
```bash
mvn -f reference-system/app/pom.xml -q -Dexec.mainClass=com.reconmail.app.EndToEndScenario exec:java
```

## HTTP API
```bash
mvn -f reference-system/api/pom.xml -q -Dexec.mainClass=com.reconmail.api.ApiMain exec:java
# or the executable jar (see deployment/README.md):
java -jar reference-system/api/target/reconmail-api.jar 8080
```
Every service lives under `/api/v1/<service>`, with the same paths in every
deployment form (all-in-one, `make cluster`, Docker). Each service has its own
**Swagger UI** at `/api/v1/<service>/docs` and its OpenAPI document at
`/api/v1/<service>/openapi.json` (both generated from the route table, so they always
match the code):

- http://localhost:8080/api/v1/auth-server/docs
- http://localhost:8080/api/v1/key-server/docs
- http://localhost:8080/api/v1/mail-server/docs

Routes:
- `POST /api/v1/auth-server/register` — store client-computed SRP salt + verifier (password never sent)
- `POST /api/v1/auth-server/info` — signed modulus, server ephemeral B, salt, session
- `POST /api/v1/auth-server/login` — verify client proof, return server proof + session
- `GET  /api/v1/auth-server/modulus-key` — the key that signs the modulus
- `POST /api/v1/key-server/keys` — store encrypted key material + signed key list, commit a KT epoch
- `GET  /api/v1/key-server/keys/{email}` — public-key directory lookup
- `GET  /api/v1/key-server/keys/{email}/proof` — Key Transparency inclusion proof
- `POST /api/v1/mail-server/messages` — store an (already E2E-encrypted) message
- `POST /api/v1/mail-server/messages/external` — deliver external mail with encrypt-on-arrival
- `GET  /api/v1/mail-server/messages/{id}` — fetch a stored message (ciphertext + metadata)
- `GET  /api/v1/mail-server/messages/inbox/{email}` — list envelopes (metadata only)

## Modules
- **crypto** — OpenPGP (Bouncy Castle): key generation (RSA-3072 or Curve25519 =
  Ed25519 + X25519), hybrid encrypt-and-sign / decrypt-and-verify, detached
  signatures, and **bcrypt**-based key-passphrase derivation; plus the address-key
  token model.
- **srp** — SRP-6a (2048-bit group) client + server, and verifier derivation.
- **keyserver** — encrypted key vault, public-key directory, Signed Key Lists, and
  Key Transparency (Merkle tree + epoch chaining + inclusion proofs).
- **auth-server** — SRP login with a signed modulus and session issuance.
- **mail** — message store (ciphertext + metadata) and the encrypt-on-arrival pipeline.
- **app** — the end-to-end demo scenario across all components.
- **cli** — interactive command-line client over the library.
- **api** — the HTTP (networked) deployment form over all services.
