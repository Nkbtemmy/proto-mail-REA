# Review of manzi draft 02 — SRP math

Verdict: PARTIALLY USABLE (helpers good, protocol wrong, does not compile).

Good (kept, corrected): hash(byte[]...), unsigned/bytes(BigInteger), PAD, and
constant-time compare via MessageDigest.isEqual.

Wrong (rewritten by Claude):
- Session key math incorrect on BOTH sides:
  server used A^(v^u) instead of (A * v^u); client formula ignored B and k.
- SrpClient references B/this.B that are never declared -> compile error.
- SrpServer declares final A and K but never assigns them -> compile error.
- step3_serverProof = H(A,K,A,K): should be H(PAD(A), M1, K); M1 never computed.
- 32-bit private exponents (too small); should be >= 256-bit.

Decision: Claude rewrote the protocol correctly (standard SRP-6a, RFC 5054 2048-bit
group), kept manzi's helper shapes, and added a full handshake test.
