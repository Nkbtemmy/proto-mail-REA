package com.reconmail.mta;

import com.reconmail.crypto.AddressKeyFactory;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.KeyServer;
import com.reconmail.keyserver.SignedKeyLists;
import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.mail.MailPipeline;
import com.reconmail.mail.MailStore;
import com.reconmail.mail.StoredMessage;
import org.junit.jupiter.api.Test;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptOnArrivalMailetTest {

    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);

    @Test
    void describesItself() throws Exception {
        EncryptOnArrivalMailet mailet = new EncryptOnArrivalMailet(new KeyServer(pgp),
                new MailPipeline(pgp, new MailStore()));
        assertEquals("ReconMail encrypt-on-arrival mailet", mailet.getMailetInfo());
    }

    @Test
    void mailetEncryptsRealMimeMessageOnArrival() throws Exception {
        MailStore store = new MailStore();
        MailPipeline pipeline = new MailPipeline(pgp, store);
        KeyServer keyServer = new KeyServer(pgp);

        // Register Bob's key in the directory (what a recipient lookup returns).
        PgpCrypto.KeyPairResult bobUser = pgp.generateKeyPair("bob@recon.test", "pw".toCharArray());
        AddressKeyFactory.AddressKey bobAddr = addressKeys.createAddressKey("bob@recon.test",
                bobUser.publicKeyArmored(), bobUser.privateKeyArmored(), "pw".toCharArray());
        char[] bobToken = addressKeys.unlockToken(bobAddr.encryptedToken(),
                bobUser.privateKeyArmored(), "pw".toCharArray(), bobUser.publicKeyArmored());
        SignedKeyLists.Skl skl = skls.sign(List.of(new SignedKeyLists.Entry("fp", 3, true)),
                bobAddr.addressPrivateKeyArmored(), bobToken);
        keyServer.store(new StoreKeysRequest("bob@recon.test", "bob@recon.test", "c2FsdA==",
                bobUser.privateKeyArmored(), bobUser.publicKeyArmored(),
                bobAddr.addressPrivateKeyArmored(), bobAddr.encryptedToken(), bobAddr.addressPublicKeyArmored()), skl);
        keyServer.commitEpoch();

        EncryptOnArrivalMailet mailet = new EncryptOnArrivalMailet(keyServer, pipeline);

        // A genuine inbound MimeMessage (as James would hand the mailet).
        MimeMessage message = new MimeMessage(Session.getInstance(new Properties()));
        message.setSubject("Hello from outside");
        message.setText("plaintext that must be encrypted on arrival");

        mailet.encryptOnArrival("mail-1", "sender@gmail.com", message, List.of("bob@recon.test"));

        // The server stored ONLY ciphertext for the body.
        StoredMessage stored = store.get("mail-1");
        assertNotNull(stored, "the mailet should have stored a message");
        assertTrue(stored.ciphertextArmored().contains("BEGIN PGP MESSAGE"));
        assertFalse(stored.ciphertextArmored().contains("plaintext that must be encrypted"),
                "stored blob must not contain the plaintext");
        assertEquals("Hello from outside", stored.subject());

        // Bob decrypts it with his address key.
        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(stored.ciphertextArmored(),
                bobAddr.addressPrivateKeyArmored(), bobToken, pipeline.systemPublicKey());
        assertEquals("plaintext that must be encrypted on arrival", result.plaintext());
        assertTrue(result.signatureValid(), "system encrypt-on-arrival signature should verify");
    }
}
