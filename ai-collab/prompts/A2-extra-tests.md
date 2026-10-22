You are a senior Java engineer writing JUnit 5 tests for an existing project. Output
ONLY Java code, each test class under a `// ==== FILE: <path> ====` header. Use
org.junit.jupiter.api.Test and static org.junit.jupiter.api.Assertions.*. Do NOT invent
any method beyond those listed; they are the complete, real API.

Real API:
  new PgpCrypto()
  PgpCrypto.KeyPairResult generateKeyPair(String userId, char[] pass)   // .publicKeyArmored(), .privateKeyArmored()
  String encryptAndSign(String text, String recipientPub, String senderPriv, char[] senderPass)
  PgpCrypto.DecryptResult decryptAndVerify(String armored, String recipientPriv, char[] recipientPass, String senderPub) // .plaintext(), .signatureValid()

  new com.reconmail.keyserver.MerkleTree(java.util.List<byte[]> leaves)   // .rootHex(), .prove(int) -> InclusionProof
  static boolean MerkleTree.verify(byte[] leafData, MerkleTree.InclusionProof proof, String expectedRootHex)

  com.reconmail.srp.SrpParams.default2048()
  com.reconmail.srp.SrpCredentials.newSalt(); .deriveX(byte[] salt, String id, char[] pw); .computeVerifier(SrpParams, BigInteger x)
  new com.reconmail.srp.SrpClient(SrpParams, BigInteger x) // generateA(), computeClientProof(BigInteger B), verifyServerProof(byte[] m2)
  new com.reconmail.srp.SrpServer(SrpParams, BigInteger v) // generateB(), verifyClientProof(BigInteger A, byte[] m1), serverProof()

Write THREE test classes:

1. FILE: reference-system/crypto/src/test/java/com/reconmail/crypto/PgpCryptoLargeBodyTest.java
   package com.reconmail.crypto; — generate two keypairs, encrypt+sign a 10_000-char
   body ("x".repeat(10000)), decrypt+verify, assert plaintext equals and signatureValid.

2. FILE: reference-system/keyserver/src/test/java/com/reconmail/keyserver/MerkleSizesTest.java
   package com.reconmail.keyserver; — for a tree of exactly 2 leaves and again exactly 8
   leaves (bytes of "leaf"+i), assert every index's prove(i) verifies against rootHex().

3. FILE: reference-system/srp/src/test/java/com/reconmail/srp/SrpTwoLoginsTest.java
   package com.reconmail.srp; — one salt+verifier for ("alice","pw"); run the full
   handshake TWICE with fresh SrpClient/SrpServer each time; assert both succeed and the
   two session proofs each verify.

Output only the three files. No prose. Make them compile on Java 21+.
