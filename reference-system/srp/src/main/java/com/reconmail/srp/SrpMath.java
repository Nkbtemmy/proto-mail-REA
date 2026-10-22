package com.reconmail.srp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Shared SRP-6a primitives. The {@code hash}/{@code unsigned}/{@code pad}
 * shapes originated in manzi's draft and were kept; the protocol-level
 * computations were corrected (see {@code ai-collab/outputs/02-srp-math.REVIEW.md}).
 */
final class SrpMath {

    private static final String HASH = "SHA-512";

    private SrpMath() {
    }

    static byte[] hash(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH);
            for (byte[] part : parts) {
                md.update(part);
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 must be available", e);
        }
    }

    static BigInteger hashToInt(byte[]... parts) {
        return new BigInteger(1, hash(parts));
    }

    /** Big-endian unsigned byte encoding of a non-negative BigInteger. */
    static byte[] unsigned(BigInteger x) {
        byte[] b = x.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] trimmed = new byte[b.length - 1];
            System.arraycopy(b, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return b;
    }

    /** Left-pad the unsigned encoding of x to {@code len} bytes. */
    static byte[] pad(BigInteger x, int len) {
        byte[] b = unsigned(x);
        if (b.length == len) {
            return b;
        }
        if (b.length > len) {
            throw new IllegalArgumentException("value is longer than the modulus");
        }
        byte[] out = new byte[len];
        System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }

    static int byteLen(BigInteger n) {
        return (n.bitLength() + 7) / 8;
    }

    /** k = H(N | PAD(g)). */
    static BigInteger k(BigInteger n, BigInteger g) {
        return hashToInt(unsigned(n), pad(g, byteLen(n)));
    }

    /** u = H(PAD(A) | PAD(B)). */
    static BigInteger u(BigInteger a, BigInteger b, BigInteger n) {
        int len = byteLen(n);
        return hashToInt(pad(a, len), pad(b, len));
    }

    /**
     * x = H(salt | H(I | ":" | P)) — RFC 5054 derivation. Proton's production
     * variant is versioned bcrypt + expand-hash (see dossier chapter 02); this
     * is the clean reference derivation.
     */
    static BigInteger deriveX(byte[] salt, String identity, char[] password) {
        byte[] inner = hash((identity + ":" + new String(password)).getBytes(StandardCharsets.UTF_8));
        return hashToInt(salt, inner);
    }
}
