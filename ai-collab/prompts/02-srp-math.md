You are a senior Java engineer. Write ONE self-contained Java file, ONLY code in a single ```java block, no prose.

Package: com.reconmail.srp
Pure Java: use only java.math.BigInteger, java.security.MessageDigest (SHA-512),
java.security.SecureRandom, java.nio.charset.StandardCharsets, java.util.*. NO external libraries.

Implement SRP-6a (RFC 5054 style) as three types in the file:

1. public record SrpParams(BigInteger N, BigInteger g) — the group.
2. public final class SrpServer with:
   - constructor(SrpParams params, BigInteger verifier)
   - BigInteger step1_generateB()  // k=H(N,PAD(g)); b=random; B=(k*v + g^b mod N) mod N; store b,B; return B
   - boolean step2_verifyClientProof(BigInteger A, byte[] clientProofM1) // u=H(PAD(A),PAD(B)); S=(A * v^u mod N)^b mod N; K=H(S); M1=H(PAD(A),PAD(B),K); compare constant-time; store A,K
   - byte[] step3_serverProof()  // M2 = H(PAD(A), M1, K)
3. public final class SrpClient with:
   - constructor(SrpParams params, BigInteger x)  // x = password hash exponent, given
   - BigInteger step1_generateA()  // a=random; A=g^a mod N; return A
   - byte[] step2_clientProof(BigInteger serverB) // compute u,S,K,M1 as above; store for later; return M1
   - boolean step3_verifyServerProof(byte[] serverM2) // recompute H(PAD(A),M1,K), constant-time compare

Rules:
- H(...) = SHA-512 of the concatenation of the big-endian unsigned byte encodings of the arguments (BigInteger -> stripped of sign byte). Provide a private static helper hash(byte[]... parts) and bytes(BigInteger).
- PAD(x) = left-pad the unsigned byte encoding of x to the byte length of N.
- k = H(N, PAD(g)). u = H(PAD(A), PAD(B)). Reject if A mod N == 0 or B mod N == 0.
- Constant-time array compare via MessageDigest.isEqual.
- Make it compile on Java 21+. No TODOs, no placeholders.
