package com.reconmail.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyDerivationTest {

    @Test
    void deterministicForSameSalt() {
        byte[] salt = KeyDerivation.newSalt();
        char[] a = KeyDerivation.deriveKeyPassphrase("correct horse".toCharArray(), salt);
        char[] b = KeyDerivation.deriveKeyPassphrase("correct horse".toCharArray(), salt);
        assertArrayEquals(a, b, "same password + salt must derive the same passphrase");
    }

    @Test
    void differsForDifferentSalt() {
        char[] a = KeyDerivation.deriveKeyPassphrase("pw".toCharArray(), KeyDerivation.newSalt());
        char[] b = KeyDerivation.deriveKeyPassphrase("pw".toCharArray(), KeyDerivation.newSalt());
        assertFalse(Arrays.equals(a, b), "different salts must derive different passphrases");
    }

    @Test
    void rejectsWrongSaltLength() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyDerivation.deriveKeyPassphrase("pw".toCharArray(), new byte[8]));
    }
}
