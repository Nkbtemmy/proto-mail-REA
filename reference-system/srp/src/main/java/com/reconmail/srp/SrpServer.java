package com.reconmail.srp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Server side of the SRP-6a handshake (dossier chapter 02).
 * The server holds only the verifier {@code v}; it never learns the password.
 */
public final class SrpServer {

    private final BigInteger n;
    private final BigInteger g;
    private final BigInteger v;
    private final BigInteger k;
    private final BigInteger b;
    private final BigInteger pubB;

    private BigInteger pubA;
    private byte[] m1;
    private byte[] sessionKey;

    public SrpServer(SrpParams params, BigInteger verifier) {
        this.n = params.N();
        this.g = params.g();
        this.v = verifier;
        this.k = SrpMath.k(n, g);
        this.b = new BigInteger(256, new SecureRandom()).mod(n);
        this.pubB = k.multiply(v).add(g.modPow(b, n)).mod(n); // B = (k·v + g^b) mod N
    }

    /** B = (k·v + g^b) mod N — sent to the client. */
    public BigInteger generateB() {
        return pubB;
    }

    /**
     * Verify the client's proof. On success the server has also derived the
     * same session key K. S = (A · v^u)^b mod N.
     */
    public boolean verifyClientProof(BigInteger clientA, byte[] clientM1) {
        if (clientA.mod(n).signum() == 0) {
            throw new IllegalArgumentException("client A is 0 mod N — aborting");
        }
        this.pubA = clientA;
        BigInteger u = SrpMath.u(pubA, pubB, n);
        BigInteger s = pubA.multiply(v.modPow(u, n)).mod(n).modPow(b, n);
        this.sessionKey = SrpMath.hash(SrpMath.unsigned(s));

        int len = SrpMath.byteLen(n);
        byte[] expected = SrpMath.hash(SrpMath.pad(pubA, len), SrpMath.pad(pubB, len), sessionKey);
        if (!MessageDigest.isEqual(expected, clientM1)) {
            return false;
        }
        this.m1 = expected;
        return true;
    }

    /** M2 = H(PAD(A) | M1 | K) — returned to the client after a valid M1. */
    public byte[] serverProof() {
        if (m1 == null) {
            throw new IllegalStateException("verifyClientProof must succeed first");
        }
        int len = SrpMath.byteLen(n);
        return SrpMath.hash(SrpMath.pad(pubA, len), m1, sessionKey);
    }

    public byte[] sessionKey() {
        return sessionKey;
    }
}
