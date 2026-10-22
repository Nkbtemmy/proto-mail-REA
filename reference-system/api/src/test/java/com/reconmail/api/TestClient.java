package com.reconmail.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.reconmail.auth.AuthService;
import com.reconmail.crypto.AddressKeyFactory;
import com.reconmail.crypto.KeyDerivation;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.SignedKeyLists;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.mail.StoredMessage;
import com.reconmail.srp.SrpClient;
import com.reconmail.srp.SrpCredentials;
import com.reconmail.srp.SrpParams;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A reusable ReconMail client that talks to a base URL (the gateway) and does the
 * real client-side crypto + SRP. Shared by the distributed and restart tests.
 */
final class TestClient {

    // The public URL contract, spelled out literally so that a path change breaks the tests.
    static final String AUTH = "/api/v1/auth-server";
    static final String KEYS = "/api/v1/key-server";
    static final String MAIL = "/api/v1/mail-server";

    private final String base;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();
    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);
    private final SrpParams params = SrpParams.default2048();
    private final Map<String, Account> accounts = new HashMap<>();

    record Account(String email, String password, byte[] keySalt,
                   PgpCrypto.KeyPairResult userKey, AddressKeyFactory.AddressKey addr) {}

    TestClient(String base) {
        this.base = base;
    }

    /** Register: generate keys, publish them, and store SRP salt+verifier. Keeps client keys in memory. */
    Account register(String email, String password) throws Exception {
        byte[] keySalt = KeyDerivation.newSalt();
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(password.toCharArray(), keySalt);
        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair(email, keyPass);
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey(email,
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), keyPass);
        char[] token = addressKeys.unlockToken(addr.encryptedToken(),
                userKey.privateKeyArmored(), keyPass, userKey.publicKeyArmored());
        SignedKeyLists.Skl skl = skls.sign(List.of(new SignedKeyLists.Entry("fp-" + email, 3, true)),
                addr.addressPrivateKeyArmored(), token);

        byte[] srpSalt = SrpCredentials.newSalt();
        BigInteger x = SrpCredentials.deriveX(srpSalt, email, password.toCharArray());
        BigInteger verifier = SrpCredentials.computeVerifier(params, x);
        post(AUTH + "/register", json.writeValueAsString(new HttpApiServer.RegisterRequest(
                email, Base64.getEncoder().encodeToString(srpSalt), verifier.toString(16), 4)));

        StoreKeysRequest keys = new StoreKeysRequest(email, email,
                Base64.getEncoder().encodeToString(keySalt),
                userKey.privateKeyArmored(), userKey.publicKeyArmored(),
                addr.addressPrivateKeyArmored(), addr.encryptedToken(), addr.addressPublicKeyArmored());
        post(KEYS + "/keys", json.writeValueAsString(
                new HttpApiServer.StoreKeysBody(keys, skl.canonicalJson(), skl.signatureArmored())));

        Account account = new Account(email, password, keySalt, userKey, addr);
        accounts.put(email, account);
        return account;
    }

    /** Remember the keys for an already-registered account (used after a restart). */
    void remember(Account account) {
        accounts.put(account.email(), account);
    }

    boolean login(String email, String password) throws Exception {
        String modulusKey = json.readValue(get(AUTH + "/modulus-key"), HttpApiServer.ModulusKey.class).publicKeyArmored();
        AuthService.AuthInfo info = json.readValue(
                post(AUTH + "/info", json.writeValueAsString(new HttpApiServer.InfoRequest(email))),
                AuthService.AuthInfo.class);
        if (!pgp.verifyDetached(info.modulusHex(), info.signedModulusArmored(), modulusKey)) {
            return false;
        }
        SrpParams p = new SrpParams(new BigInteger(info.modulusHex(), 16), new BigInteger(info.g()));
        byte[] salt = Base64.getDecoder().decode(info.saltBase64());
        SrpClient client = new SrpClient(p, SrpCredentials.deriveX(salt, email, password.toCharArray()));
        byte[] m1 = client.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));
        HttpApiServer.AuthResponse resp = json.readValue(post(AUTH + "/login", json.writeValueAsString(
                        new HttpApiServer.AuthRequest(info.srpSession(), client.generateA().toString(16),
                                Base64.getEncoder().encodeToString(m1)))),
                HttpApiServer.AuthResponse.class);
        return resp.ok() && client.verifyServerProof(Base64.getDecoder().decode(resp.serverProofM2Base64()));
    }

    String publicKeyOf(String email) throws Exception {
        return json.readValue(get(KEYS + "/keys/" + enc(email)), KeyDirectoryResponse.class).keys().get(0).armoredKey();
    }

    String sendProton(String from, String to, String subject, String body) throws Exception {
        Account sender = accounts.get(from);
        String recipientKey = publicKeyOf(to);
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(sender.password().toCharArray(), sender.keySalt());
        char[] token = addressKeys.unlockToken(sender.addr().encryptedToken(),
                sender.userKey().privateKeyArmored(), keyPass, sender.userKey().publicKeyArmored());
        String ciphertext = pgp.encryptAndSign(body, recipientKey, sender.addr().addressPrivateKeyArmored(), token);
        String id = "p-" + Math.abs(ciphertext.hashCode());
        post(MAIL + "/messages", json.writeValueAsString(new StoredMessage(id, from, to, subject,
                Instant.now().getEpochSecond(), 0, ciphertext)));
        return id;
    }

    String sendExternal(String from, String to, String subject, String plaintext) throws Exception {
        String id = "x-" + Math.abs((to + plaintext).hashCode());
        // recipientPublicKeyArmored = null → the mail service fetches it from the key service.
        post(MAIL + "/messages/external", json.writeValueAsString(
                new HttpApiServer.ExternalMail(id, from, to, subject, plaintext, null)));
        return id;
    }

    StoredMessage fetch(String id) throws Exception {
        return json.readValue(get(MAIL + "/messages/" + id), StoredMessage.class);
    }

    PgpCrypto.DecryptResult read(String email, String id, String senderPublicKeyArmored) throws Exception {
        Account me = accounts.get(email);
        StoredMessage stored = fetch(id);
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(me.password().toCharArray(), me.keySalt());
        char[] token = addressKeys.unlockToken(me.addr().encryptedToken(),
                me.userKey().privateKeyArmored(), keyPass, me.userKey().publicKeyArmored());
        return pgp.decryptAndVerify(stored.ciphertextArmored(), me.addr().addressPrivateKeyArmored(),
                token, senderPublicKeyArmored);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private String get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    private String post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }
}
