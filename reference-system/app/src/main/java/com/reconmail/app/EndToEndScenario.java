package com.reconmail.app;

import com.reconmail.auth.AuthService;
import com.reconmail.crypto.AddressKeyFactory;
import com.reconmail.crypto.KeyDerivation;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.KeyServer;
import com.reconmail.keyserver.KeyTransparency;
import com.reconmail.keyserver.MerkleTree;
import com.reconmail.keyserver.SignedKeyLists;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.mail.MailPipeline;
import com.reconmail.mail.MailStore;
import com.reconmail.mail.StoredMessage;
import com.reconmail.srp.SrpClient;
import com.reconmail.srp.SrpCredentials;
import com.reconmail.srp.SrpParams;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * The capstone: a full ReconMail flow wiring every module together, proving the
 * dossier's design in code. It:
 *   1. registers two users (user key + address key via the token model, SKL published),
 *   2. commits a Key Transparency epoch,
 *   3. logs in over SRP (verifying the signed modulus),
 *   4. sends an end-to-end-encrypted Proton→Proton message (KT-verified recipient key),
 *   5. delivers external inbound mail with encrypt-on-arrival,
 *   6. reads both back, and checks the server only ever stored ciphertext.
 *
 * Run it: {@code mvn -f reference-system/pom.xml -pl app -am -q exec:java}
 */
public final class EndToEndScenario {

    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);
    private final KeyServer keyServer = new KeyServer(pgp);
    private final MailStore mailStore = new MailStore();
    private final AuthService auth;
    private final MailPipeline pipeline;
    private final List<String> log = new ArrayList<>();

    public EndToEndScenario() throws Exception {
        this.auth = new AuthService(pgp);
        this.pipeline = new MailPipeline(pgp, mailStore);
    }

    /** Everything the scenario produced — transcript plus the facts the test asserts. */
    public record Result(List<String> transcript, boolean aliceLoggedIn, boolean bobLoggedIn,
                         boolean ktVerified, boolean protonBodyRecovered, boolean protonSignatureValid,
                         boolean externalBodyRecovered, boolean serverBlobHadNoPlaintext,
                         boolean subjectVisibleToServer) {}

    private record Account(String email, String password, byte[] keySalt,
                           PgpCrypto.KeyPairResult userKey, AddressKeyFactory.AddressKey addressKey) {}

    private record SendResult(String body, boolean ktVerified) {}

    private record ReadResult(String body, boolean signatureValid, boolean noPlaintextInBlob, String subject) {}

    public Result run() throws Exception {
        log.add("=== ReconMail end-to-end scenario ===");

        Account alice = register("alice@recon.test", "alice-password");
        Account bob = register("bob@recon.test", "bob-password");

        KeyTransparency.Epoch epoch = keyServer.commitEpoch();
        log.add(String.format("KT epoch #%d committed: root=%s… anchor=%s",
                epoch.epochId(), epoch.rootHex().substring(0, 16), epoch.ctAnchor()));

        boolean aliceIn = login(alice);
        SendResult sent = aliceSendsToBob(alice, bob);
        ReadResult external = bobReadsExternalInbound(bob);
        boolean bobIn = login(bob);
        ReadResult protonRead = bobReadsProtonMessage(bob, alice);

        log.add("");
        log.add("Evidence: server stored body as ciphertext only; subject '" + protonRead.subject()
                + "' was readable (documented metadata caveat).");

        return new Result(List.copyOf(log), aliceIn, bobIn, sent.ktVerified(),
                protonRead.body().equals(sent.body()), protonRead.signatureValid(),
                external.body().startsWith("Hi Bob"),
                protonRead.noPlaintextInBlob() && external.noPlaintextInBlob(),
                "Lunch?".equals(protonRead.subject()));
    }

    private Account register(String email, String password) throws Exception {
        byte[] keySalt = KeyDerivation.newSalt();
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(password.toCharArray(), keySalt);

        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair(email, keyPass);
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey(email,
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), keyPass);

        char[] token = addressKeys.unlockToken(addr.encryptedToken(),
                userKey.privateKeyArmored(), keyPass, userKey.publicKeyArmored());
        SignedKeyLists.Skl skl = skls.sign(List.of(new SignedKeyLists.Entry("fp-" + email, 3, true)),
                addr.addressPrivateKeyArmored(), token);

        StoreKeysRequest req = new StoreKeysRequest(email, email,
                Base64.getEncoder().encodeToString(keySalt),
                userKey.privateKeyArmored(), userKey.publicKeyArmored(),
                addr.addressPrivateKeyArmored(), addr.encryptedToken(), addr.addressPublicKeyArmored());
        keyServer.store(req, skl);
        auth.register(email, password.toCharArray());

        log.add("registered " + email + " — user key + address key (token model), SKL published to key server");
        return new Account(email, password, keySalt, userKey, addr);
    }

    private boolean login(Account account) throws Exception {
        AuthService.AuthInfo info = auth.authInfo(account.email());

        boolean modulusOk = pgp.verifyDetached(info.modulusHex(), info.signedModulusArmored(),
                auth.serverModulusPublicKey());

        SrpParams params = new SrpParams(new BigInteger(info.modulusHex(), 16), new BigInteger(info.g()));
        byte[] salt = Base64.getDecoder().decode(info.saltBase64());
        BigInteger x = SrpCredentials.deriveX(salt, account.email(), account.password().toCharArray());
        SrpClient client = new SrpClient(params, x);

        BigInteger a = client.generateA();
        byte[] m1 = client.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));
        AuthService.AuthResult result = auth.authenticate(info.srpSession(), a, m1);
        boolean srpOk = result.ok() && client.verifyServerProof(result.serverProofM2());

        log.add("login " + account.email() + " — signed modulus verified=" + modulusOk + ", SRP handshake ok=" + srpOk);
        return modulusOk && srpOk;
    }

    private SendResult aliceSendsToBob(Account alice, Account bob) throws Exception {
        // Look up the recipient's key AND verify it against Key Transparency before trusting it.
        KeyDirectoryResponse dir = keyServer.directory(bob.email());
        String bobPublicKey = dir.keys().get(0).armoredKey();
        MerkleTree.InclusionProof proof = keyServer.inclusionProof(bob.email());
        String bobSkl = keyServer.signedKeyList(bob.email()).canonicalJson();
        List<KeyTransparency.Epoch> epochs = keyServer.transparency().epochs();
        String epochRoot = epochs.get(epochs.size() - 1).rootHex();
        boolean ktOk = keyServer.verifyMembership(bob.email(), bobSkl, proof, epochRoot);
        log.add("Alice fetched Bob's key and verified Key Transparency inclusion=" + ktOk);

        // Alice unlocks her own address key to sign.
        char[] aliceKeyPass = KeyDerivation.deriveKeyPassphrase(alice.password().toCharArray(), alice.keySalt());
        char[] aliceToken = addressKeys.unlockToken(alice.addressKey().encryptedToken(),
                alice.userKey().privateKeyArmored(), aliceKeyPass, alice.userKey().publicKeyArmored());

        String body = "Hey Bob — this is end-to-end encrypted, the server cannot read it.";
        String ciphertext = pgp.encryptAndSign(body, bobPublicKey,
                alice.addressKey().addressPrivateKeyArmored(), aliceToken);
        StoredMessage message = new StoredMessage("p1", alice.email(), bob.email(), "Lunch?",
                Instant.now().getEpochSecond(), 0, ciphertext);
        pipeline.acceptProtonMessage(message);

        log.add("Alice sent Proton→Proton; server stored a " + ciphertext.length()
                + "-char ciphertext blob (subject 'Lunch?' kept as readable metadata)");
        return new SendResult(body, ktOk);
    }

    private ReadResult bobReadsProtonMessage(Account bob, Account alice) throws Exception {
        StoredMessage stored = mailStore.get("p1");
        String alicePublicKey = keyServer.directory(alice.email()).keys().get(0).armoredKey();

        char[] bobKeyPass = KeyDerivation.deriveKeyPassphrase(bob.password().toCharArray(), bob.keySalt());
        char[] bobToken = addressKeys.unlockToken(bob.addressKey().encryptedToken(),
                bob.userKey().privateKeyArmored(), bobKeyPass, bob.userKey().publicKeyArmored());

        PgpCrypto.DecryptResult decrypted = pgp.decryptAndVerify(stored.ciphertextArmored(),
                bob.addressKey().addressPrivateKeyArmored(), bobToken, alicePublicKey);
        boolean noPlaintext = !stored.ciphertextArmored().contains("cannot read");

        log.add("Bob decrypted the Proton message: \"" + decrypted.plaintext()
                + "\" (Alice's signature valid=" + decrypted.signatureValid() + ")");
        return new ReadResult(decrypted.plaintext(), decrypted.signatureValid(), noPlaintext, stored.subject());
    }

    private ReadResult bobReadsExternalInbound(Account bob) throws Exception {
        String body = "Hi Bob, this is an email from Gmail (plaintext on the wire until arrival).";
        pipeline.deliverExternalInbound("x1", "friend@gmail.com", bob.email(),
                "From Gmail", body, bob.addressKey().addressPublicKeyArmored());

        StoredMessage stored = mailStore.get("x1");
        char[] bobKeyPass = KeyDerivation.deriveKeyPassphrase(bob.password().toCharArray(), bob.keySalt());
        char[] bobToken = addressKeys.unlockToken(bob.addressKey().encryptedToken(),
                bob.userKey().privateKeyArmored(), bobKeyPass, bob.userKey().publicKeyArmored());

        PgpCrypto.DecryptResult decrypted = pgp.decryptAndVerify(stored.ciphertextArmored(),
                bob.addressKey().addressPrivateKeyArmored(), bobToken, pipeline.systemPublicKey());
        boolean noPlaintext = !stored.ciphertextArmored().contains("plaintext on the wire");

        log.add("External inbound mail was encrypted-on-arrival; Bob decrypted it: \""
                + decrypted.plaintext() + "\"");
        return new ReadResult(decrypted.plaintext(), decrypted.signatureValid(), noPlaintext, stored.subject());
    }

    public static void main(String[] args) throws Exception {
        Result r = new EndToEndScenario().run();
        r.transcript().forEach(System.out::println);
        System.out.println();
        System.out.println("  aliceLoggedIn          = " + r.aliceLoggedIn());
        System.out.println("  bobLoggedIn            = " + r.bobLoggedIn());
        System.out.println("  keyTransparencyVerified= " + r.ktVerified());
        System.out.println("  protonBodyRecovered    = " + r.protonBodyRecovered());
        System.out.println("  protonSignatureValid   = " + r.protonSignatureValid());
        System.out.println("  externalBodyRecovered  = " + r.externalBodyRecovered());
        System.out.println("  serverStoredCiphertextOnly = " + r.serverBlobHadNoPlaintext());
        System.out.println("  subjectVisibleToServer = " + r.subjectVisibleToServer() + "  (documented caveat)");

        boolean all = r.aliceLoggedIn() && r.bobLoggedIn() && r.ktVerified()
                && r.protonBodyRecovered() && r.protonSignatureValid()
                && r.externalBodyRecovered() && r.serverBlobHadNoPlaintext();
        System.out.println("\nSCENARIO " + (all ? "PASSED" : "FAILED"));
    }
}
