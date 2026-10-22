package com.reconmail.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AddressKeyFactoryTest {

    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory factory = new AddressKeyFactory(pgp);

    @Test
    void tokenModelUnlocksAddressKeyAndMessageRoundTrips() throws Exception {
        // The user key is the trust root.
        PgpCrypto.KeyPairResult user = pgp.generateKeyPair("User <u@recon.test>", "userpw".toCharArray());

        // Create an address key via the token model.
        AddressKeyFactory.AddressKey addr = factory.createAddressKey("Addr <a@recon.test>",
                user.publicKeyArmored(), user.privateKeyArmored(), "userpw".toCharArray());

        // Someone encrypts a message to the address public key.
        PgpCrypto.KeyPairResult alice = pgp.generateKeyPair("Alice <alice@recon.test>", "apw".toCharArray());
        String ciphertext = pgp.encryptAndSign("hello address", addr.addressPublicKeyArmored(),
                alice.privateKeyArmored(), "apw".toCharArray());

        // Unlock the token with the user key, then use it to open the address key.
        char[] token = factory.unlockToken(addr.encryptedToken(), user.privateKeyArmored(),
                "userpw".toCharArray(), user.publicKeyArmored());
        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(ciphertext, addr.addressPrivateKeyArmored(),
                token, alice.publicKeyArmored());

        assertEquals("hello address", result.plaintext());
        assertTrue(result.signatureValid());
    }

    @Test
    void encryptedTokenIsNotStoredInClear() throws Exception {
        PgpCrypto.KeyPairResult user = pgp.generateKeyPair("User <u@recon.test>", "userpw".toCharArray());
        AddressKeyFactory.AddressKey addr = factory.createAddressKey("Addr <a@recon.test>",
                user.publicKeyArmored(), user.privateKeyArmored(), "userpw".toCharArray());
        char[] token = factory.unlockToken(addr.encryptedToken(), user.privateKeyArmored(),
                "userpw".toCharArray(), user.publicKeyArmored());
        assertFalse(addr.encryptedToken().contains(new String(token)),
                "the wrapped token must not appear in cleartext");
    }

    @Test
    void wrongUserPassphraseCannotUnlockToken() throws Exception {
        PgpCrypto.KeyPairResult user = pgp.generateKeyPair("User <u@recon.test>", "userpw".toCharArray());
        AddressKeyFactory.AddressKey addr = factory.createAddressKey("Addr <a@recon.test>",
                user.publicKeyArmored(), user.privateKeyArmored(), "userpw".toCharArray());
        assertThrows(Exception.class, () -> factory.unlockToken(addr.encryptedToken(),
                user.privateKeyArmored(), "WRONG".toCharArray(), user.publicKeyArmored()));
    }
}
