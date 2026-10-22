# MANZI_TASKS — the backlog, as ready-to-paste prompts

Work top to bottom. For each task: save the prompt to `ai-collab/prompts/<id>.md`
(some are pre-made), run `./ask-manzi.sh prompts/<id>.md`, paste the code into the
named file(s), then **`mvn -f ../reference-system/pom.xml test`**. Green = keep.
Red = manzi hallucinated; fix or revert. Log a one-line verdict in
`outputs/<id>.REVIEW.md`.

The prompts deliberately include the EXACT method signatures manzi may call, because
it invents APIs when left to guess.

---

## Reference: public APIs manzi is allowed to call (do not invent others)

```
// crypto
record PgpCrypto.KeyPairResult(String publicKeyArmored, String privateKeyArmored)
record PgpCrypto.DecryptResult(String plaintext, boolean signatureValid)
PgpCrypto(): KeyPairResult generateKeyPair(String userId, char[] pass)
             String encryptAndSign(String text, String recipientPub, String senderPriv, char[] senderPass)
             DecryptResult decryptAndVerify(String armored, String recipientPriv, char[] recipientPass, String senderPub)
             String signDetached(String text, String signerPriv, char[] pass)
             boolean verifyDetached(String text, String sigArmored, String signerPub)
KeyDerivation: static byte[] newSalt(); static char[] deriveKeyPassphrase(char[] pw, byte[] salt16)
record AddressKeyFactory.AddressKey(String addressPublicKeyArmored, String addressPrivateKeyArmored, String encryptedToken)
AddressKeyFactory(PgpCrypto): AddressKey createAddressKey(String userId, String userPub, String userPriv, char[] userPass)
                              char[] unlockToken(String encToken, String userPriv, char[] userPass, String userPub)

// srp
record SrpParams(BigInteger N, BigInteger g); static SrpParams default2048()
SrpClient(SrpParams, BigInteger x): BigInteger generateA(); byte[] computeClientProof(BigInteger B); boolean verifyServerProof(byte[] m2)
SrpServer(SrpParams, BigInteger v): BigInteger generateB(); boolean verifyClientProof(BigInteger A, byte[] m1); byte[] serverProof()
SrpCredentials: static byte[] newSalt(); static BigInteger deriveX(byte[] salt, String id, char[] pw); static BigInteger computeVerifier(SrpParams, BigInteger x)

// keyserver
KeyServer(PgpCrypto): void store(StoreKeysRequest, SignedKeyLists.Skl); KeyTransparency.Epoch commitEpoch();
   KeyDirectoryResponse directory(String email); StoreKeysRequest encryptedKeyMaterial(String email);
   SignedKeyLists.Skl signedKeyList(String email); MerkleTree.InclusionProof inclusionProof(String email);
   boolean verifyMembership(String email, String sklJson, MerkleTree.InclusionProof, String rootHex); KeyTransparency transparency()
record SignedKeyLists.Entry(String sha256Fingerprint, int flags, boolean primary)
record SignedKeyLists.Skl(String canonicalJson, String signatureArmored)
SignedKeyLists(PgpCrypto): Skl sign(List<Entry>, String signerPriv, char[] pass); boolean verify(Skl, String signerPub)

// auth
record AuthService.AuthInfo(String modulusHex, String g, String signedModulusArmored, String serverEphemeralBHex, String saltBase64, String srpSession, int version)
record AuthService.AuthResult(boolean ok, byte[] serverProofM2, AuthService.Session session)
AuthService(PgpCrypto): void register(String username, char[] pw); AuthInfo authInfo(String username);
   AuthResult authenticate(String srpSession, BigInteger A, byte[] m1); String serverModulusPublicKey(); boolean sessionValid(String uid)

// mail
record StoredMessage(String id, String fromAddress, String toAddress, String subject, long timestampEpochSeconds, int flags, String ciphertextArmored)
record Envelope(String id, String fromAddress, String toAddress, String subject, long timestampEpochSeconds, int flags)
MailStore: void put(StoredMessage); StoredMessage get(String id); List<Envelope> inboxOf(String to); int size()
MailPipeline(PgpCrypto, MailStore): String systemPublicKey(); StoredMessage deliverExternalInbound(id, from, to, subject, plaintext, recipientPub); StoredMessage acceptProtonMessage(StoredMessage)

// cli (extend these)
CliEngine(): String register(email,pw); String login(email,pw); String send(from,to,subject,body);
   String read(email,msgId,senderEmail); String inbox(email)
```

---

## TIER A — manzi does these well (plain Java / tests / docs / config)

### A1 — more CLI commands  (file: `reference-system/cli/src/main/java/com/reconmail/cli/CliEngine.java`)  — LOW risk
Pre-made prompt: `prompts/A1-cli-extra-commands.md`. Adds `accounts` (list emails this
session registered) and `external` (deliver an external inbound mail to an address via
`MailPipeline.deliverExternalInbound`, using that address's public key from
`keyServer.directory(email).keys().get(0).armoredKey()`). Then add matching `case`s in
`Cli.java` and a test in `CliEngineTest.java`. Verify: `mvn test`.

### A2 — more unit tests  (files: new `*Test.java` in the relevant module)  — LOW risk
Pre-made prompt: `prompts/A2-extra-tests.md`. Add tests: PgpCrypto with a 10 KB body;
MerkleTree with exactly 2 and exactly 8 leaves; SRP two independent logins for the same
user both succeed. Verify: `mvn test` (new tests must pass).

### A3 — usage walkthrough  (file: `reference-system/USAGE.md`)  — LOW risk
Prompt to paste:
> Write a Markdown file `USAGE.md` for a Java project called ReconMail. Explain, for a
> new developer: how to run `mvn -f reference-system/pom.xml test`; how to run the
> interactive CLI (`com.reconmail.cli.Cli`) and a sample session (register two users,
> login, send, read, inbox); and a one-paragraph description of each module (crypto,
> srp, keyserver, auth-server, mail, app, cli). Keep it factual and concise. Output only
> the Markdown.

(No build impact; just proofread it.)

### A4 — deployment skeletons  (files: `reference-system/deployment/docker-compose.yml`, `Caddyfile`)  — LOW–MED risk
Prompt to paste:
> Draft a `docker-compose.yml` and a `Caddyfile` for a FUTURE deployment of a mail
> system with these services (none built yet — placeholders only): `auth` (Java/Spring,
> port 8081), `keys` (8082), `api` (8083), a `postgres` db, and `caddy` as a reverse
> proxy terminating TLS and routing /auth, /keys, /api to those services. Output two code
> blocks, each preceded by a `// FILE:` line. These are scaffolding for humans to finish.

Verify by eye (YAML/config). This does NOT wire into Maven.

---

## TIER B — manzi is WEAK here (verify hard, or leave for a human / Claude)

> These are the networked deployment form (dossier M9) and the ECC profile. The system
> is already correct without them. Expect manzi to hallucinate APIs; treat output as a
> first draft, compile immediately, and be ready to rewrite. If in doubt, STOP and leave
> these for a Claude session.

### B1 — Spring Boot `api` module  — HIGH risk
Goal: a `reference-system/api` Spring Boot module exposing `POST /auth/info`, `POST
/auth`, `POST /keys`, `GET /keys/{email}` as thin controllers delegating to the EXISTING
`AuthService`/`KeyServer` (do not reimplement any crypto). Likely failure: wrong Spring
annotations/versions, invented methods. Verify: module compiles AND `mvn test` stays
green AND a manual `curl` login round-trips. Recommend a human own the Spring wiring.

### B2 — Curve25519 key profile in `PgpCrypto`  — HIGH risk
Goal: add `generateKeyPair` variant producing Ed25519 (sign) + X25519 (encrypt) OpenPGP
keys via Bouncy Castle, matching Proton's default; keep RSA-3072 as a fallback. Likely
failure: fabricated BC classes (it did this already — see
`outputs/01-pgp-crypto-core.REVIEW.md`). Verify: the EXISTING `PgpCryptoTest` round-trip
must pass with the new key type. If manzi fabricates APIs again, leave this for Claude.

### B3 — Apache James encrypt-on-arrival mailet  — HIGH risk
Goal: wrap `MailPipeline.deliverExternalInbound` as an Apache James `Mailet` so a real
SMTP server encrypts on arrival. Likely failure: James API unknown to manzi. Verify: it
compiles against the James mailet API and the pipeline logic is unchanged. Recommend a
human/Claude own the James integration.

---

## Definition of done for the handover

Tier A complete and `mvn test` green = a materially more complete, still-honest system.
Tier B is optional polish toward the networked form; correctness does not depend on it.
