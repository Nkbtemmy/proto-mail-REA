package com.reconmail.api;

import com.reconmail.keyserver.KeyServer;
import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.persistence.Db;
import com.reconmail.persistence.KeyRepo;
import com.sun.net.httpserver.HttpServer;

import java.util.UUID;

/**
 * The all-in-one deployment form (dossier chapter 05 / plan M9): the auth-server,
 * key-server and mail-server APIs mounted on ONE port in one process, over an
 * in-memory database. Same {@code /api/v1/<service>} paths and Swagger docs as the
 * split stack — no new crypto, the services do all of it.
 *
 * <p>Registration is faithful: the client computes the SRP salt + verifier and the
 * encrypted key material; the server stores them and never sees the password.</p>
 */
public final class HttpApiServer {

    private final Db db;
    private final HttpServer server;

    // ---- JSON-friendly request/response shapes (strings, not BigInteger/byte[]) ----
    public record RegisterRequest(String username, String saltBase64, String verifierHex, int version) {}
    public record InfoRequest(String username) {}
    public record AuthRequest(String srpSession, String clientEphemeralAHex, String clientProofM1Base64) {}
    public record AuthResponse(boolean ok, String serverProofM2Base64, String uid) {}
    public record StoreKeysBody(StoreKeysRequest keys, String sklCanonicalJson, String sklSignatureArmored) {}
    public record ExternalMail(String id, String from, String to, String subject,
                               String plaintext, String recipientPublicKeyArmored) {}
    public record EpochResponse(long epochId) {}
    public record ModulusKey(String publicKeyArmored) {}
    public record Ok(String value) {}

    public HttpApiServer(int port) throws Exception {
        this.db = new Db("jdbc:h2:mem:reconmail-" + UUID.randomUUID());
        KeyRepo keyRepo = new KeyRepo(db);
        KeyServer keyServer = KeyServiceServer.hydrate(keyRepo);
        this.server = Http.serve(port,
                AuthServiceServer.routes(db),
                KeyServiceServer.routes(keyServer, keyRepo),
                // in one process the mail service asks the key server directly instead of over HTTP
                MailServiceServer.routes(db, email -> keyServer.directory(email).keys().get(0).armoredKey()));
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
        db.close();
    }
}
