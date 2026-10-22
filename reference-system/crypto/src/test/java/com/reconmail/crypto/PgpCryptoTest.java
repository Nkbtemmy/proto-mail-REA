package com.reconmail.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PgpCryptoTest {

    private final PgpCrypto pgp = new PgpCrypto();

    @Test
    void roundTripEncryptSignDecryptVerify() throws Exception {
        PgpCrypto.KeyPairResult alice = pgp.generateKeyPair("Alice <alice@recon.test>", "alice-pass".toCharArray());
        PgpCrypto.KeyPairResult bob = pgp.generateKeyPair("Bob <bob@recon.test>", "bob-pass".toCharArray());

        String message = "zero-access hello, Bob";
        String ciphertext = pgp.encryptAndSign(message, bob.publicKeyArmored(),
                alice.privateKeyArmored(), "alice-pass".toCharArray());

        assertTrue(ciphertext.contains("BEGIN PGP MESSAGE"), "output should be an armored PGP message");
        assertFalse(ciphertext.contains(message), "ciphertext must not leak the plaintext");

        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(ciphertext, bob.privateKeyArmored(),
                "bob-pass".toCharArray(), alice.publicKeyArmored());

        assertEquals(message, result.plaintext());
        assertTrue(result.signatureValid(), "Alice's signature should verify for Bob");
    }

    @Test
    void storedPrivateKeyIsEncrypted() throws Exception {
        PgpCrypto.KeyPairResult kp = pgp.generateKeyPair("X <x@recon.test>", "pw".toCharArray());
        // The armored private key is what the server would store: it must not be usable
        // without the passphrase. A wrong passphrase must fail to unlock it.
        String ct = pgp.encryptAndSign("m", kp.publicKeyArmored(), kp.privateKeyArmored(), "pw".toCharArray());
        assertThrows(Exception.class, () ->
                pgp.decryptAndVerify(ct, kp.privateKeyArmored(), "WRONG".toCharArray(), kp.publicKeyArmored()));
    }
}
