package com.reconmail.cli;

import com.reconmail.auth.AuthService;
import com.reconmail.crypto.AddressKeyFactory;
import com.reconmail.crypto.KeyDerivation;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.KeyServer;
import com.reconmail.keyserver.KeyTransparency;
import com.reconmail.keyserver.MerkleTree;
import com.reconmail.keyserver.SignedKeyLists;
import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.mail.Envelope;
import com.reconmail.mail.MailPipeline;
import com.reconmail.mail.MailStore;
import com.reconmail.mail.StoredMessage;
import com.reconmail.srp.SrpClient;
import com.reconmail.srp.SrpCredentials;
import com.reconmail.srp.SrpParams;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Testable core of the CLI: wires the verified library modules and exposes one
 * method per command. {@link Cli} is a thin REPL over this class.
 *
 * <p>BASE for manzi: the wiring and the hard crypto are done and tested. Extend
 * by adding new command methods that call the existing services — see
 * {@code ../../../HANDOVER.md} task CLI-1 for the exact pattern and the methods
 * available on each service.</p>
 */
public final class CliEngine {

    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);
    private final KeyServer keyServer = new KeyServer(pgp);
    private final MailStore mailStore = new MailStore();
    private final AuthService auth;
    private final MailPipeline pipeline;

    /** Client-side key material this CLI session holds for accounts it created. */
    private final Map<String, Account> clients = new ConcurrentHashMap<>();

    private record Account(String email, String password, byte[] keySalt,
                           PgpCrypto.KeyPairResult userKey, AddressKeyFactory.AddressKey addressKey) {}

    public CliEngine() throws Exception {
        this.auth = new AuthService(pgp);
        this.pipeline = new MailPipeline(pgp, mailStore);
    }

    /** register <email> <password> — create keys, publish SKL, commit a KT epoch. */
    public String register(String email, String password) throws Exception {
        byte[] keySalt = KeyDerivation.newSalt();
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(password.toCharArray(), keySalt);
        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair(email, keyPass);
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey(email,
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), keyPass);

        char[] token = addressKeys.unlockToken(addr.encryptedToken(),
                userKey.privateKeyArmored(), keyPass, userKey.publicKeyArmored());
        SignedKeyLists.Skl skl = skls.sign(List.of(new SignedKeyLists.Entry("fp-" + email, 3, true)),
                addr.addressPrivateKeyArmored(), token);

        keyServer.store(new StoreKeysRequest(email, email, Base64.getEncoder().encodeToString(keySalt),
                userKey.privateKeyArmored(), userKey.publicKeyArmored(),
                addr.addressPrivateKeyArmored(), addr.encryptedToken(), addr.addressPublicKeyArmored()), skl);
        auth.register(email, password.toCharArray());
        KeyTransparency.Epoch epoch = keyServer.commitEpoch();

        clients.put(email, new Account(email, password, keySalt, userKey, addr));
        return "registered " + email + " (KT epoch #" + epoch.epochId() + ")";
    }

    /** login <email> <password> — full SRP handshake with signed-modulus check. */
    public String login(String email, String password) throws Exception {
        AuthService.AuthInfo info = auth.authInfo(email);
        boolean modulusOk = pgp.verifyDetached(info.modulusHex(), info.signedModulusArmored(),
                auth.serverModulusPublicKey());
        SrpParams params = new SrpParams(new BigInteger(info.modulusHex(), 16), new BigInteger(info.g()));
        byte[] salt = Base64.getDecoder().decode(info.saltBase64());
        SrpClient client = new SrpClient(params, SrpCredentials.deriveX(salt, email, password.toCharArray()));
        byte[] m1 = client.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));
        AuthService.AuthResult result = auth.authenticate(info.srpSession(), client.generateA(), m1);
        boolean ok = modulusOk && result.ok() && client.verifyServerProof(result.serverProofM2());
        return "login " + email + ": " + (ok ? "OK (signed modulus verified, SRP proof exchanged)" : "FAILED");
    }

    /** send <from> <to> <subject> <body> — E2E Proton→Proton with a KT key check. */
    public String send(String from, String to, String subject, String body) throws Exception {
        Account sender = requireClient(from);
        String recipientKey = keyServer.directory(to).keys().get(0).armoredKey();

        MerkleTree.InclusionProof proof = keyServer.inclusionProof(to);
        String recipientSkl = keyServer.signedKeyList(to).canonicalJson();
        List<KeyTransparency.Epoch> epochs = keyServer.transparency().epochs();
        String root = epochs.get(epochs.size() - 1).rootHex();
        if (!keyServer.verifyMembership(to, recipientSkl, proof, root)) {
            return "ABORT: recipient key failed Key Transparency verification";
        }

        char[] keyPass = KeyDerivation.deriveKeyPassphrase(sender.password().toCharArray(), sender.keySalt());
        char[] token = addressKeys.unlockToken(sender.addressKey().encryptedToken(),
                sender.userKey().privateKeyArmored(), keyPass, sender.userKey().publicKeyArmored());
        String ciphertext = pgp.encryptAndSign(body, recipientKey,
                sender.addressKey().addressPrivateKeyArmored(), token);

        String id = UUID.randomUUID().toString().substring(0, 8);
        pipeline.acceptProtonMessage(new StoredMessage(id, from, to, subject,
                Instant.now().getEpochSecond(), 0, ciphertext));
        return "sent (id=" + id + "); server stored " + ciphertext.length() + " chars of ciphertext";
    }

    /** read <email> <msgId> <senderEmail> — decrypt + verify a stored message. */
    public String read(String email, String msgId, String senderEmail) throws Exception {
        Account me = requireClient(email);
        StoredMessage stored = mailStore.get(msgId);
        if (stored == null) {
            return "no such message: " + msgId;
        }
        String senderKey = keyServer.directory(senderEmail).keys().get(0).armoredKey();
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(me.password().toCharArray(), me.keySalt());
        char[] token = addressKeys.unlockToken(me.addressKey().encryptedToken(),
                me.userKey().privateKeyArmored(), keyPass, me.userKey().publicKeyArmored());
        PgpCrypto.DecryptResult r = pgp.decryptAndVerify(stored.ciphertextArmored(),
                me.addressKey().addressPrivateKeyArmored(), token, senderKey);
        return "subject=\"" + stored.subject() + "\" body=\"" + r.plaintext()
                + "\" signatureValid=" + r.signatureValid();
    }

    /** inbox <email> — list envelopes (metadata only, as the server sees them). */
    public String inbox(String email) {
        StringBuilder sb = new StringBuilder("inbox of " + email + ":");
        for (Envelope e : mailStore.inboxOf(email)) {
            sb.append("\n  [").append(e.id()).append("] from=").append(e.fromAddress())
                    .append(" subject=\"").append(e.subject()).append('"');
        }
        return sb.toString();
    }

    /** accounts — list the emails this CLI session has registered. (manzi A1) */
    public String accounts() {
        return clients.isEmpty() ? "accounts: (none)" : "accounts: " + String.join(", ", clients.keySet());
    }

    /** external &lt;from&gt; &lt;to&gt; &lt;subject&gt; &lt;body&gt; — simulate inbound external mail. (manzi A1) */
    public String external(String from, String to, String subject, String body) throws Exception {
        String recipientKey = keyServer.directory(to).keys().get(0).armoredKey();
        String id = UUID.randomUUID().toString().substring(0, 8);
        pipeline.deliverExternalInbound(id, from, to, subject, body, recipientKey);
        return "delivered external mail to " + to + " (id=" + id + ")";
    }

    private Account requireClient(String email) {
        Account a = clients.get(email);
        if (a == null) {
            throw new IllegalStateException("this CLI session has no keys for " + email
                    + " — run `register " + email + " <password>` first");
        }
        return a;
    }
}
