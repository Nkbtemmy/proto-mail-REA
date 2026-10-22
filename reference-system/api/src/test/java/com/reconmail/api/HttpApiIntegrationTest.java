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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static com.reconmail.api.TestClient.AUTH;
import static com.reconmail.api.TestClient.KEYS;
import static com.reconmail.api.TestClient.MAIL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The whole system, exercised over real HTTP (dossier deployment form / M9). */
class HttpApiIntegrationTest {

    private HttpApiServer server;
    private String base;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();
    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);
    private final SrpParams params = SrpParams.default2048();

    @BeforeEach
    void setUp() throws Exception {
        server = new HttpApiServer(0);
        server.start();
        base = "http://localhost:" + server.port();
    }

    @AfterEach
    void tearDown() {
        server.stop();
    }

    private record Client(String email, String password, byte[] keySalt,
                          PgpCrypto.KeyPairResult userKey, AddressKeyFactory.AddressKey addr) {}

    @Test
    void fullProtonFlowOverHttp() throws Exception {
        String serverModulusKey = json.readValue(get(AUTH + "/modulus-key"),
                HttpApiServer.ModulusKey.class).publicKeyArmored();

        Client alice = register("alice@recon.test", "alice-pw");
        Client bob = register("bob@recon.test", "bob-pw");

        // SRP login over HTTP (and a wrong-password rejection)
        assertTrue(login(alice, alice.password(), serverModulusKey), "alice should log in over HTTP");
        assertFalse(login(alice, "wrong", serverModulusKey), "wrong password must be rejected over HTTP");

        // Alice looks up Bob's key over HTTP and sends an E2E message
        KeyDirectoryResponse dir = json.readValue(get(KEYS + "/keys/" + enc(bob.email())), KeyDirectoryResponse.class);
        String bobPublicKey = dir.keys().get(0).armoredKey();
        assertTrue(get(KEYS + "/keys/" + enc(bob.email()) + "/proof").contains("rootHash"),
                "KT proof endpoint should return a root hash");

        String ciphertext = pgp.encryptAndSign("HTTP end-to-end hello", bobPublicKey,
                alice.addr().addressPrivateKeyArmored(), unlock(alice));
        StoredMessage toSend = new StoredMessage("h1", alice.email(), bob.email(), "Subject-Visible",
                Instant.now().getEpochSecond(), 0, ciphertext);
        post(MAIL + "/messages", json.writeValueAsString(toSend));

        // Bob fetches and decrypts over HTTP
        StoredMessage fetched = json.readValue(get(MAIL + "/messages/h1"), StoredMessage.class);
        assertFalse(fetched.ciphertextArmored().contains("hello"), "server must store ciphertext only");
        PgpCrypto.DecryptResult decrypted = pgp.decryptAndVerify(fetched.ciphertextArmored(),
                bob.addr().addressPrivateKeyArmored(), unlock(bob), alice.addr().addressPublicKeyArmored());
        assertEquals("HTTP end-to-end hello", decrypted.plaintext());
        assertTrue(decrypted.signatureValid(), "Alice's signature should verify");

        // External inbound over HTTP: encrypt-on-arrival
        HttpApiServer.ExternalMail external = new HttpApiServer.ExternalMail("x1", "g@gmail.com",
                bob.email(), "Ext", "external plaintext body", bob.addr().addressPublicKeyArmored());
        post(MAIL + "/messages/external", json.writeValueAsString(external));
        StoredMessage storedExternal = json.readValue(get(MAIL + "/messages/x1"), StoredMessage.class);
        assertFalse(storedExternal.ciphertextArmored().contains("external plaintext"),
                "external mail must be stored as ciphertext");
        PgpCrypto.DecryptResult extDecrypted = pgp.decryptAndVerify(storedExternal.ciphertextArmored(),
                bob.addr().addressPrivateKeyArmored(), unlock(bob), bob.addr().addressPublicKeyArmored());
        assertEquals("external plaintext body", extDecrypted.plaintext());

        // Inbox listing is metadata only, and the subject is readable (documented caveat)
        assertTrue(get(MAIL + "/messages/inbox/" + enc(bob.email())).contains("Subject-Visible"));
    }

    // ---- client helpers (reproduce the client side of the protocol) --------

    private Client register(String email, String password) throws Exception {
        byte[] keySalt = KeyDerivation.newSalt();
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(password.toCharArray(), keySalt);
        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair(email, keyPass);
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey(email,
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), keyPass);
        char[] token = addressKeys.unlockToken(addr.encryptedToken(),
                userKey.privateKeyArmored(), keyPass, userKey.publicKeyArmored());
        SignedKeyLists.Skl skl = skls.sign(List.of(new SignedKeyLists.Entry("fp-" + email, 3, true)),
                addr.addressPrivateKeyArmored(), token);

        // SRP registration: the client computes salt + verifier (server never sees the password).
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

        return new Client(email, password, keySalt, userKey, addr);
    }

    private boolean login(Client c, String password, String serverModulusKey) throws Exception {
        AuthService.AuthInfo info = json.readValue(
                post(AUTH + "/info", json.writeValueAsString(new HttpApiServer.InfoRequest(c.email()))),
                AuthService.AuthInfo.class);
        if (!pgp.verifyDetached(info.modulusHex(), info.signedModulusArmored(), serverModulusKey)) {
            return false;
        }
        SrpParams p = new SrpParams(new BigInteger(info.modulusHex(), 16), new BigInteger(info.g()));
        byte[] salt = Base64.getDecoder().decode(info.saltBase64());
        SrpClient client = new SrpClient(p, SrpCredentials.deriveX(salt, c.email(), password.toCharArray()));
        byte[] m1 = client.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));

        HttpApiServer.AuthResponse resp = json.readValue(post(AUTH + "/login", json.writeValueAsString(
                        new HttpApiServer.AuthRequest(info.srpSession(), client.generateA().toString(16),
                                Base64.getEncoder().encodeToString(m1)))),
                HttpApiServer.AuthResponse.class);
        return resp.ok() && client.verifyServerProof(Base64.getDecoder().decode(resp.serverProofM2Base64()));
    }

    private char[] unlock(Client c) throws Exception {
        char[] keyPass = KeyDerivation.deriveKeyPassphrase(c.password().toCharArray(), c.keySalt());
        return addressKeys.unlockToken(c.addr().encryptedToken(),
                c.userKey().privateKeyArmored(), keyPass, c.userKey().publicKeyArmored());
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
