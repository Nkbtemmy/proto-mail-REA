package com.reconmail.api;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.mail.Envelope;
import com.reconmail.mail.MailPipeline;
import com.reconmail.mail.MailStore;
import com.reconmail.mail.StoredMessage;
import com.reconmail.persistence.Db;
import com.reconmail.persistence.MessageRepo;
import com.sun.net.httpserver.HttpServer;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * The mail microservice ({@code /api/v1/mail-server/*}). Owns its own {@link MailStore} +
 * {@link MailPipeline}, persists messages to {@link MessageRepo} (hydrate-on-boot +
 * write-through), and — for inbound external mail — calls the <b>key service over
 * HTTP</b> to look up the recipient's public key before encrypt-on-arrival. That
 * cross-service call is the real microservice seam.
 */
public final class MailServiceServer {

    /** Where the mail service gets a recipient's public key for encrypt-on-arrival. */
    @FunctionalInterface
    interface RecipientKeys {
        String publicKeyOf(String email) throws Exception;
    }

    private final HttpServer server;

    public MailServiceServer(int port, Db db, String keyServiceBaseUrl) throws Exception {
        this.server = Http.serve(port, routes(db, overHttp(keyServiceBaseUrl)));
    }

    /** The mail-server API; mounted on its own port here, or inside {@link HttpApiServer}. */
    static Router routes(Db db, RecipientKeys recipientKeys) throws Exception {
        PgpCrypto pgp = new PgpCrypto();
        MailStore store = new MailStore();
        MailPipeline pipeline = new MailPipeline(pgp, store);
        MessageRepo messages = new MessageRepo(db);
        for (StoredMessage m : messages.findAll()) {
            store.put(m);
        }

        Router api = new Router(ApiPaths.MAIL, "mail-server",
                "Ciphertext-only message store and the encrypt-on-arrival pipeline for external mail.");
        api.post("/messages")
                .summary("Store an already end-to-end-encrypted message")
                .body(StoredMessage.class)
                .returns(HttpApiServer.Ok.class)
                .handle((ex, p) -> {
                    StoredMessage m = Http.read(ex, StoredMessage.class);
                    pipeline.acceptProtonMessage(m);
                    messages.insert(m);
                    Http.write(ex, 200, new HttpApiServer.Ok(m.id()));
                });
        api.post("/messages/external")
                .summary("Deliver external plaintext mail, encrypted on arrival "
                        + "(recipient key fetched from the key-server when omitted)")
                .body(HttpApiServer.ExternalMail.class)
                .returns(HttpApiServer.Ok.class)
                .handle((ex, p) -> {
                    HttpApiServer.ExternalMail m = Http.read(ex, HttpApiServer.ExternalMail.class);
                    String publicKey = (m.recipientPublicKeyArmored() == null || m.recipientPublicKeyArmored().isBlank())
                            ? recipientKeys.publicKeyOf(m.to()) : m.recipientPublicKeyArmored();
                    StoredMessage sm = pipeline.deliverExternalInbound(m.id(), m.from(), m.to(),
                            m.subject(), m.plaintext(), publicKey);
                    messages.insert(sm);
                    Http.write(ex, 200, new HttpApiServer.Ok(sm.id()));
                });
        api.get("/messages/{id}")
                .summary("Fetch a stored message (ciphertext + metadata)")
                .returns(StoredMessage.class)
                .handle((ex, p) -> {
                    StoredMessage m = store.get(p.get("id"));
                    if (m == null) {
                        Http.error(ex, 404, "no such message");
                    } else {
                        Http.write(ex, 200, m);
                    }
                });
        api.get("/messages/inbox/{email}")
                .summary("List an inbox: envelopes only (metadata, no bodies)")
                .returns(Router.listOf(Envelope.class))
                .handle((ex, p) -> Http.write(ex, 200, store.inboxOf(p.get("email"))));
        return api;
    }

    /** Cross-service call: ask the key service for the recipient's published key. */
    static RecipientKeys overHttp(String keyServiceBaseUrl) {
        HttpClient http = HttpClient.newHttpClient();
        return email -> {
            String url = keyServiceBaseUrl + ApiPaths.KEYS + "/keys/" + URLEncoder.encode(email, StandardCharsets.UTF_8);
            HttpResponse<String> resp = http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("key lookup for " + email + " failed: " + resp.body());
            }
            KeyDirectoryResponse dir = Http.JSON.readValue(resp.body(), KeyDirectoryResponse.class);
            return dir.keys().get(0).armoredKey();
        };
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }
}
