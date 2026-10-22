package com.reconmail.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Drafted by manzi (A2); nested-type references corrected by Claude. */
class PgpCryptoLargeBodyTest {

    @Test
    void encryptDecryptLargeBody() throws Exception {
        PgpCrypto crypto = new PgpCrypto();
        PgpCrypto.KeyPairResult alice = crypto.generateKeyPair("Alice <alice@recon.test>", "pw-a".toCharArray());
        PgpCrypto.KeyPairResult bob = crypto.generateKeyPair("Bob <bob@recon.test>", "pw-b".toCharArray());

        String body = "x".repeat(10_000);
        String encrypted = crypto.encryptAndSign(body, bob.publicKeyArmored(),
                alice.privateKeyArmored(), "pw-a".toCharArray());

        PgpCrypto.DecryptResult decrypted = crypto.decryptAndVerify(encrypted,
                bob.privateKeyArmored(), "pw-b".toCharArray(), alice.publicKeyArmored());
        assertEquals(body, decrypted.plaintext());
        assertTrue(decrypted.signatureValid());
    }
}
