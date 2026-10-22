package com.reconmail.api;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.mail.StoredMessage;
import com.reconmail.persistence.Db;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Durability: credentials, keys, and messages survive a full restart of the stack. */
class PersistenceRestartTest {

    @Test
    void stateSurvivesARestart(@TempDir Path dir) throws Exception {
        TestClient.Account alice;
        TestClient.Account bob;
        String messageId;

        // --- first run: register + send, then shut everything down ---
        try (Db db = Db.file(dir)) {
            Cluster cluster = new Cluster(db);
            try {
                TestClient client = new TestClient(cluster.gatewayBase());
                alice = client.register("alice@recon.test", "pw-a");
                bob = client.register("bob@recon.test", "pw-b");
                assertTrue(client.login("alice@recon.test", "pw-a"));
                messageId = client.sendProton("alice@recon.test", "bob@recon.test", "Persisted", "survive restart");
            } finally {
                cluster.stop();
            }
        }

        // --- restart a brand-new stack over the SAME data directory ---
        try (Db db = Db.file(dir)) {
            Cluster cluster = new Cluster(db);
            try {
                TestClient client = new TestClient(cluster.gatewayBase());
                client.remember(alice); // the client keeps its own keys; the server reloaded its state
                client.remember(bob);

                // Credentials were persisted → login still works after restart.
                assertTrue(client.login("bob@recon.test", "pw-b"), "login should work after a restart");

                // The message and keys were persisted → still fetchable and decryptable.
                StoredMessage stored = client.fetch(messageId);
                assertNotNull(stored, "message should have survived the restart");
                PgpCrypto.DecryptResult r = client.read("bob@recon.test", messageId,
                        client.publicKeyOf("alice@recon.test"));
                assertEquals("survive restart", r.plaintext());
                assertTrue(r.signatureValid(), "sender key survived too, so the signature verifies");
            } finally {
                cluster.stop();
            }
        }
    }
}
