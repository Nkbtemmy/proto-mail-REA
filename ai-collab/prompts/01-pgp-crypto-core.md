You are a senior Java engineer. Write ONE self-contained Java class, no explanation before or after, only the code in a single ```java block.

Class: com.reconmail.crypto.PgpCrypto
Build target: Java 21, Bouncy Castle (org.bouncycastle:bcpg-jdk18on, bcprov-jdk18on).

Requirements (OpenPGP, RFC 4880 / 9580 style, mirroring how Proton Mail uses PGP):
1. generateKeyPair(String userId, char[] passphrase) -> returns a holder with ASCII-armored public key and ASCII-armored ENCRYPTED private key. Use Curve25519 (EdDSA sign + ECDH encrypt) if supported, else RSA-3072. The private key MUST be encrypted with the passphrase.
2. encryptAndSign(String plaintext, String recipientArmoredPublicKey, String senderArmoredPrivateKey, char[] senderPassphrase) -> ASCII-armored PGP message, encrypted to recipient and signed by sender.
3. decryptAndVerify(String armoredMessage, String recipientArmoredPrivateKey, char[] recipientPassphrase, String senderArmoredPublicKey) -> returns decrypted plaintext and a boolean signatureValid.
4. Helper methods to read armored keys from String.

Use a static nested record KeyPairResult(String publicKeyArmored, String privateKeyArmored).
Use a static nested record DecryptResult(String plaintext, boolean signatureValid).
Add a BouncyCastleProvider in a static initializer.
Make it compile. Prefer clarity. No TODOs.
