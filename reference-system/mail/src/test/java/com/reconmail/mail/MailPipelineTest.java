package com.reconmail.mail;

import com.reconmail.crypto.PgpCrypto;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MailPipelineTest {

    private final PgpCrypto pgp = new PgpCrypto();

    @Test
    void externalInboundIsEncryptedOnArrivalAndStoredAsCiphertext() throws Exception {
        MailStore store = new MailStore();
        MailPipeline pipeline = new MailPipeline(pgp, store);
        PgpCrypto.KeyPairResult bob = pgp.generateKeyPair("Bob <bob@recon.test>", "bobpw".toCharArray());

        String body = "plaintext from the outside world (gmail)";
        pipeline.deliverExternalInbound("m1", "sender@gmail.com", "bob@recon.test",
                "Hello Bob", body, bob.publicKeyArmored());

        StoredMessage stored = store.get("m1");
        // The server stores ONLY ciphertext for the body.
        assertTrue(stored.ciphertextArmored().contains("BEGIN PGP MESSAGE"));
        assertFalse(stored.ciphertextArmored().contains(body), "stored blob must not contain the plaintext");
        // ...but metadata (incl. subject) is readable — the documented caveat.
        assertEquals("Hello Bob", stored.subject());

        // Bob can decrypt it client-side with his key.
        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(stored.ciphertextArmored(),
                bob.privateKeyArmored(), "bobpw".toCharArray(), pipeline.systemPublicKey());
        assertEquals(body, result.plaintext());
        assertTrue(result.signatureValid(), "the system's encrypt-on-arrival signature should verify");
    }

    @Test
    void inboxListingUsesMetadataOnly() throws Exception {
        MailStore store = new MailStore();
        MailPipeline pipeline = new MailPipeline(pgp, store);
        PgpCrypto.KeyPairResult bob = pgp.generateKeyPair("Bob <bob@recon.test>", "bobpw".toCharArray());
        pipeline.deliverExternalInbound("m1", "a@x.com", "bob@recon.test", "One", "b1", bob.publicKeyArmored());
        pipeline.deliverExternalInbound("m2", "b@x.com", "bob@recon.test", "Two", "b2", bob.publicKeyArmored());

        List<Envelope> inbox = store.inboxOf("bob@recon.test");
        assertEquals(2, inbox.size());
    }
}
