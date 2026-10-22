package com.reconmail.api;

import com.reconmail.persistence.Db;

import java.nio.file.Files;
import java.nio.file.Path;

/** Standalone auth microservice. Config: PORT (8081), DB_DIR (auth-data). */
public final class AuthServiceMain {

    public static void main(String[] args) throws Exception {
        int port = Env.getInt("PORT", 8081);
        Path dir = Path.of(Env.get("DB_DIR", "auth-data"));
        Files.createDirectories(dir);
        AuthServiceServer server = new AuthServiceServer(port, Db.file(dir));
        server.start();
        System.out.println("auth service listening on :" + server.port() + " (data " + dir.toAbsolutePath() + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
