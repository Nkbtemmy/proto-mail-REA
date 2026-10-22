package com.reconmail.api;

import com.reconmail.persistence.Db;

/**
 * Starts the full split stack in one JVM: the auth, key, and mail microservices
 * plus the gateway in front of them, all sharing a durable {@link Db}. Used by the
 * distributed and restart integration tests and by {@link ClusterMain}.
 */
public final class Cluster {

    public final AuthServiceServer auth;
    public final KeyServiceServer keys;
    public final MailServiceServer mail;
    public final Gateway gateway;

    public Cluster(Db db) throws Exception {
        auth = new AuthServiceServer(0, db);
        auth.start();
        keys = new KeyServiceServer(0, db);
        keys.start();
        String keyUrl = "http://localhost:" + keys.port();
        mail = new MailServiceServer(0, db, keyUrl); // mail talks to keys over HTTP
        mail.start();
        gateway = new Gateway(0, "http://localhost:" + auth.port(), keyUrl, "http://localhost:" + mail.port());
        gateway.start();
    }

    public String gatewayBase() {
        return "http://localhost:" + gateway.port();
    }

    public void stop() {
        gateway.stop();
        mail.stop();
        keys.stop();
        auth.stop();
    }
}
