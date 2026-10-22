package com.reconmail.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Registration-side helpers: turn a password into the (salt, verifier) pair the
 * server stores. The server never sees the password or {@code x}.
 */
public final class SrpCredentials {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SrpCredentials() {
    }

    public static byte[] newSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /** x = H(salt | H(identity ":" password)). */
    public static BigInteger deriveX(byte[] salt, String identity, char[] password) {
        return SrpMath.deriveX(salt, identity, password);
    }

    /** The verifier stored server-side: v = g^x mod N. */
    public static BigInteger computeVerifier(SrpParams params, BigInteger x) {
        return params.g().modPow(x, params.N());
    }
}
