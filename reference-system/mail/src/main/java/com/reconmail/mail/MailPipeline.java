package com.reconmail.mail;

import com.reconmail.crypto.PgpCrypto;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.time.Instant;

/**
 * The mail pipeline (dossier chapter 04). Its defining job is <b>encrypt-on-
 * arrival</b>: mail from the outside world arrives as plaintext and is
 * immediately wrapped to the recipient's public key before being stored, so the
 * server only ever persists ciphertext. (The server sees plaintext only for the
 * instant of processing — the documented zero-access caveat.)
 *
 * <p>In Proton this is a server-side hook in the MTA (Apache James). Here it is a
 * direct method; the dossier maps it to a James mailet for the deployment form.</p>
 */
public final class MailPipeline {

    private final PgpCrypto pgp;
    private final MailStore store;
    private final String systemPublicKey;
    private final String systemPrivateKey;
    private final char[] systemPassphrase = "reconmail-system-key".toCharArray();

    public MailPipeline(PgpCrypto pgp, MailStore store) throws PGPException, IOException {
        this.pgp = pgp;
        this.store = store;
        PgpCrypto.KeyPairResult systemKey = pgp.generateKeyPair(
                "ReconMail System <system@recon.test>", systemPassphrase);
        this.systemPublicKey = systemKey.publicKeyArmored();
        this.systemPrivateKey = systemKey.privateKeyArmored();
    }

    /** Public key the recipient can use to confirm a message was encrypted by the system on arrival. */
    public String systemPublicKey() {
        return systemPublicKey;
    }

    /** Zero-access encrypt-on-arrival for inbound external mail (dossier chapter 04 §2). */
    public StoredMessage deliverExternalInbound(String id, String fromAddress, String toAddress,
                                                String subject, String plaintextBody,
                                                String recipientPublicKeyArmored) throws PGPException, IOException {
        String ciphertext = pgp.encryptAndSign(plaintextBody, recipientPublicKeyArmored,
                systemPrivateKey, systemPassphrase);
        StoredMessage message = new StoredMessage(id, fromAddress, toAddress, subject,
                Instant.now().getEpochSecond(), 0, ciphertext);
        store.put(message);
        return message;
    }

    /** Accept an already end-to-end-encrypted Proton→Proton message (the client did the crypto). */
    public StoredMessage acceptProtonMessage(StoredMessage message) {
        store.put(message);
        return message;
    }
}
