package com.reconmail.srp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Client side of the SRP-6a handshake (dossier chapter 02).
 * The client is constructed with {@code x}, the password-derived exponent; the
 * password itself never leaves the client.
 */
public final class SrpClient {

    private final BigInteger n;
    private final BigInteger g;
    private final BigInteger x;
    private final BigInteger k;
    private final BigInteger a;
    private final BigInteger pubA;

    private BigInteger pubB;
    private byte[] m1;
    private byte[] sessionKey;

    public SrpClient(SrpParams params, BigInteger x) {
        this.n = params.N();
        this.g = params.g();
        this.x = x;
        this.k = SrpMath.k(n, g);
        this.a = new BigInteger(256, new SecureRandom()).mod(n);
        this.pubA = g.modPow(a, n);
    }

    /** A = g^a mod N — sent to the server. */
    public BigInteger generateA() {
        return pubA;
    }

    /**
     * Given the server's B, compute the shared key and the client proof M1.
     * S = (B - k·g^x)^(a + u·x) mod N, K = H(S), M1 = H(PAD(A) | PAD(B) | K).
     */
    public byte[] computeClientProof(BigInteger serverB) {
        if (serverB.mod(n).signum() == 0) {
            throw new IllegalArgumentException("server B is 0 mod N — aborting");
        }
        this.pubB = serverB;
        BigInteger u = SrpMath.u(pubA, pubB, n);
        if (u.signum() == 0) {
            throw new IllegalArgumentException("u is 0 — aborting");
        }
        BigInteger gx = g.modPow(x, n);
        BigInteger base = pubB.subtract(k.multiply(gx).mod(n)).mod(n); // mod keeps it in [0, N)
        BigInteger exp = a.add(u.multiply(x));
        BigInteger s = base.modPow(exp, n);

        this.sessionKey = SrpMath.hash(SrpMath.unsigned(s));
        int len = SrpMath.byteLen(n);
        this.m1 = SrpMath.hash(SrpMath.pad(pubA, len), SrpMath.pad(pubB, len), sessionKey);
        return m1;
    }

    /** Verify the server's proof M2 = H(PAD(A) | M1 | K). */
    public boolean verifyServerProof(byte[] serverM2) {
        if (m1 == null) {
            throw new IllegalStateException("computeClientProof must be called first");
        }
        int len = SrpMath.byteLen(n);
        byte[] expected = SrpMath.hash(SrpMath.pad(pubA, len), m1, sessionKey);
        return MessageDigest.isEqual(expected, serverM2);
    }

    /** The shared session key K (available after computeClientProof). */
    public byte[] sessionKey() {
        return sessionKey;
    }
}
