package com.reconmail.api;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.KeyServer;
import com.reconmail.keyserver.KeyTransparency;
import com.reconmail.keyserver.SignedKeyLists;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.keyserver.api.KtInclusionProof;
import com.reconmail.persistence.Db;
import com.reconmail.persistence.KeyRepo;
import com.sun.net.httpserver.HttpServer;

/**
 * The key microservice ({@code /api/v1/key-server/*}). Owns its own {@link KeyServer} and
 * persists encrypted key material + signed key lists to {@link KeyRepo}: it hydrates on
 * boot (replaying stored keys and rebuilding a Key Transparency epoch) and write-throughs
 * on store.
 */
public final class KeyServiceServer {

    private final HttpServer server;

    public KeyServiceServer(int port, Db db) throws Exception {
        KeyRepo keys = new KeyRepo(db);
        this.server = Http.serve(port, routes(hydrate(keys), keys));
    }

    /** A fresh {@link KeyServer} replaying every stored key, with KT rebuilt over them. */
    static KeyServer hydrate(KeyRepo keys) throws Exception {
        KeyServer keyServer = new KeyServer(new PgpCrypto());
        var rows = keys.findAll();
        for (KeyRepo.KeyRow row : rows) {
            keyServer.store(row.keys(), new SignedKeyLists.Skl(row.sklJson(), row.sklSig()));
        }
        if (!rows.isEmpty()) {
            keyServer.commitEpoch(); // rebuild KT over the hydrated directory
        }
        return keyServer;
    }

    /** The key-server API; mounted on its own port here, or inside {@link HttpApiServer}. */
    static Router routes(KeyServer keyServer, KeyRepo keys) {
        Router api = new Router(ApiPaths.KEYS, "key-server",
                "Encrypted key vault, public-key directory, Signed Key Lists and Key Transparency.");
        api.post("/keys")
                .summary("Store encrypted key material + a signed key list, then commit a KT epoch")
                .body(HttpApiServer.StoreKeysBody.class)
                .returns(HttpApiServer.EpochResponse.class)
                .handle((ex, p) -> {
                    HttpApiServer.StoreKeysBody b = Http.read(ex, HttpApiServer.StoreKeysBody.class);
                    keyServer.store(b.keys(), new SignedKeyLists.Skl(b.sklCanonicalJson(), b.sklSignatureArmored()));
                    keys.upsert(b.keys(), b.sklCanonicalJson(), b.sklSignatureArmored());
                    KeyTransparency.Epoch epoch = keyServer.commitEpoch();
                    Http.write(ex, 200, new HttpApiServer.EpochResponse(epoch.epochId()));
                });
        api.get("/keys/{email}")
                .summary("Public-key directory lookup")
                .returns(KeyDirectoryResponse.class)
                .handle((ex, p) -> Http.write(ex, 200, keyServer.directory(p.get("email"))));
        api.get("/keys/{email}/proof")
                .summary("Key Transparency inclusion proof for an address")
                .returns(KtInclusionProof.class)
                .handle((ex, p) -> Http.write(ex, 200, keyServer.inclusionProofDto(p.get("email"))));
        return api;
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
