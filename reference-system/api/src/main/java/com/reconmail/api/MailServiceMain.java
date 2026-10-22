package com.reconmail.api;

import com.reconmail.persistence.Db;

import java.nio.file.Files;
import java.nio.file.Path;

/** Standalone mail microservice. Config: PORT (8083), DB_DIR (mail-data), KEY_SERVICE_URL. */
public final class MailServiceMain {

    public static void main(String[] args) throws Exception {
        int port = Env.getInt("PORT", 8083);
        Path dir = Path.of(Env.get("DB_DIR", "mail-data"));
        Files.createDirectories(dir);
        String keyServiceUrl = Env.get("KEY_SERVICE_URL", "http://localhost:8082");
        MailServiceServer server = new MailServiceServer(port, Db.file(dir), keyServiceUrl);
        server.start();
        System.out.println("mail service listening on :" + server.port()
                + " (data " + dir.toAbsolutePath() + ", keys at " + keyServiceUrl + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
