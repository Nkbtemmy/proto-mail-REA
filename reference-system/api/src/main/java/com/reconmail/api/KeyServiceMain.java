package com.reconmail.api;

import com.reconmail.persistence.Db;

import java.nio.file.Files;
import java.nio.file.Path;

/** Standalone key microservice. Config: PORT (8082), DB_DIR (keys-data). */
public final class KeyServiceMain {

    public static void main(String[] args) throws Exception {
        int port = Env.getInt("PORT", 8082);
        Path dir = Path.of(Env.get("DB_DIR", "keys-data"));
        Files.createDirectories(dir);
        KeyServiceServer server = new KeyServiceServer(port, Db.file(dir));
        server.start();
        System.out.println("key service listening on :" + server.port() + " (data " + dir.toAbsolutePath() + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
