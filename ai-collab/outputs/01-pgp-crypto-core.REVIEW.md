# Review of manzi draft 01 — PGP crypto core

Verdict: REJECTED (does not compile; fabricated API).

manzi (Qwen 14B) invented Bouncy Castle classes/methods that do not exist:
PGPEncryptorEngine, PGPSignatureWriter, PGPSignatureWriter, KeyEncSessionKeyOperator,
JcaPGPUtil.makeEncryptedPrivateKey, JcaPGPKeyEncSessionKeyEncryptor,
PGPEncryptedDataList.newEncryptedDataList, PGPSignature.Ed25519, PGPDigestCalculator.SHA256,
PGPPublicKeyEncryptedData(...) ctor, PGPUtil.getEncodedPublicKey/readPublicKey.
Also missing `import java.security.Security`.

Decision: Claude writes the crypto core by hand against the REAL Bouncy Castle
OpenPGP API (PGPKeyRingGenerator, PGPEncryptedDataGenerator, PGPSignatureGenerator,
PGPLiteralDataGenerator). manzi is re-tasked to work it does well:
SRP BigInteger math, Spring DTOs/controllers, and JUnit tests from exact specs.
