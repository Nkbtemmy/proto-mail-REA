package com.reconmail.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Proton's production key profile: Ed25519 signing + X25519 encryption. */
class PgpCryptoEccTest {

    private final PgpCrypto pgp = new PgpCrypto();

    @Test
    void curve25519RoundTrip() throws Exception {
        PgpCrypto.KeyPairResult alice = pgp.generateKeyPair(
                "Alice <alice@recon.test>", "pw".toCharArray(), PgpCrypto.Profile.CURVE25519);
        PgpCrypto.KeyPairResult bob = pgp.generateKeyPair(
                "Bob <bob@recon.test>", "pw".toCharArray(), PgpCrypto.Profile.CURVE25519);

        String message = "sent with Curve25519 keys, just like Proton";
        String ciphertext = pgp.encryptAndSign(message, bob.publicKeyArmored(),
                alice.privateKeyArmored(), "pw".toCharArray());
        assertFalse(ciphertext.contains(message));

        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(ciphertext, bob.privateKeyArmored(),
                "pw".toCharArray(), alice.publicKeyArmored());
        assertEquals(message, result.plaintext());
        assertTrue(result.signatureValid(), "Ed25519 signature should verify");
    }

    @Test
    void curve25519WorksWithTheAddressKeyTokenModel() throws Exception {
        AddressKeyFactory factory = new AddressKeyFactory(pgp);
        PgpCrypto.KeyPairResult user = pgp.generateKeyPair(
                "U <u@recon.test>", "pw".toCharArray(), PgpCrypto.Profile.CURVE25519);
        // Address keys for the token wrap still round-trip under ECC user keys.
        AddressKeyFactory.AddressKey addr = factory.createAddressKey("A <a@recon.test>",
                user.publicKeyArmored(), user.privateKeyArmored(), "pw".toCharArray());
        char[] token = factory.unlockToken(addr.encryptedToken(), user.privateKeyArmored(),
                "pw".toCharArray(), user.publicKeyArmored());
        assertTrue(token.length > 0);
    }
}
