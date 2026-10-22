package com.reconmail.api;

import com.reconmail.auth.AuthService;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.persistence.Db;
import com.reconmail.persistence.UserRepo;
import com.sun.net.httpserver.HttpServer;

import java.math.BigInteger;
import java.util.Base64;

/**
 * The auth microservice ({@code /api/v1/auth-server/*}). Owns its own {@link AuthService}
 * and persists SRP credentials to {@link UserRepo}: it hydrates from the database on boot
 * and write-throughs on registration, so credentials survive a restart.
 */
public final class AuthServiceServer {

    private final HttpServer server;

    public AuthServiceServer(int port, Db db) throws Exception {
        this.server = Http.serve(port, routes(db));
    }

    /** The auth-server API over {@code db}; mounted on its own port here, or inside {@link HttpApiServer}. */
    static Router routes(Db db) throws Exception {
        AuthService auth = new AuthService(new PgpCrypto());
        UserRepo users = new UserRepo(db);
        for (UserRepo.UserRow u : users.findAll()) {
            auth.register(u.username(), Base64.getDecoder().decode(u.saltB64()),
                    new BigInteger(u.verifierHex(), 16), u.version());
        }

        Router api = new Router(ApiPaths.AUTH, "auth-server",
                "SRP-6a registration and login with a signed modulus. The password never leaves the client.");
        api.post("/register")
                .summary("Store a client-computed SRP salt + verifier (the password is never sent)")
                .body(HttpApiServer.RegisterRequest.class)
                .returns(HttpApiServer.Ok.class)
                .handle((ex, p) -> {
                    HttpApiServer.RegisterRequest r = Http.read(ex, HttpApiServer.RegisterRequest.class);
                    auth.register(r.username(), Base64.getDecoder().decode(r.saltBase64()),
                            new BigInteger(r.verifierHex(), 16), r.version());
                    users.upsert(r.username(), r.saltBase64(), r.verifierHex(), r.version());
                    Http.write(ex, 200, new HttpApiServer.Ok("registered"));
                });
        api.post("/info")
                .summary("Login step 1: signed modulus, server ephemeral B, salt and an SRP session")
                .body(HttpApiServer.InfoRequest.class)
                .returns(AuthService.AuthInfo.class)
                .handle((ex, p) -> Http.write(ex, 200,
                        auth.authInfo(Http.read(ex, HttpApiServer.InfoRequest.class).username())));
        api.post("/login")
                .summary("Login step 2: verify the client proof M1, return the server proof M2 + session")
                .body(HttpApiServer.AuthRequest.class)
                .returns(HttpApiServer.AuthResponse.class)
                .handle((ex, p) -> {
                    HttpApiServer.AuthRequest r = Http.read(ex, HttpApiServer.AuthRequest.class);
                    AuthService.AuthResult res = auth.authenticate(r.srpSession(),
                            new BigInteger(r.clientEphemeralAHex(), 16),
                            Base64.getDecoder().decode(r.clientProofM1Base64()));
                    Http.write(ex, 200, new HttpApiServer.AuthResponse(res.ok(),
                            res.ok() ? Base64.getEncoder().encodeToString(res.serverProofM2()) : null,
                            res.ok() ? res.session().uid() : null));
                });
        api.get("/modulus-key")
                .summary("The server key that signs the SRP modulus")
                .returns(HttpApiServer.ModulusKey.class)
                .handle((ex, p) -> Http.write(ex, 200, new HttpApiServer.ModulusKey(auth.serverModulusPublicKey())));
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
