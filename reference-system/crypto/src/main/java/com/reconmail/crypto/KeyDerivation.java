package com.reconmail.crypto;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.security.SecureRandom;

/**
 * Derives the OpenPGP key passphrase from the user's password, mirroring
 * Proton's use of bcrypt + a per-user key salt (see
 * {@code docs/dossier/01-cryptography.md} and {@code 02-authentication-srp.md}).
 *
 * <p>Key point from the dossier: this derivation is <b>independent</b> from the
 * SRP verifier derivation. The value produced here unlocks keys and is never
 * sent to the server; the value used for authentication is never used to unlock
 * keys.</p>
 */
public final class KeyDerivation {

    private static final int DEFAULT_COST = 10;
    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyDerivation() {
    }

    /** A fresh 16-byte key salt (stored server-side in plaintext; it is not secret). */
    public static byte[] newSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /** Deterministically derive the key passphrase from (password, salt). */
    public static char[] deriveKeyPassphrase(char[] password, byte[] salt) {
        return deriveKeyPassphrase(password, salt, DEFAULT_COST);
    }

    /** As above with an explicit bcrypt cost factor (4..31). */
    public static char[] deriveKeyPassphrase(char[] password, byte[] salt, int cost) {
        if (salt.length != 16) {
            throw new IllegalArgumentException("bcrypt key salt must be exactly 16 bytes");
        }
        // The full modular-crypt string is stable for a given (password, salt, cost)
        // and is used directly as the passphrase that encrypts the OpenPGP private key.
        String crypt = OpenBSDBCrypt.generate(password, salt, cost);
        return crypt.toCharArray();
    }
}
