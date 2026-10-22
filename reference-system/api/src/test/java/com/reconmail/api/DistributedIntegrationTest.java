package com.reconmail.api;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.mail.StoredMessage;
import com.reconmail.persistence.Db;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The split system (auth + keys + mail behind a gateway), exercised end to end. */
class DistributedIntegrationTest {

    @Test
    void fullFlowThroughTheGatewayAcrossServices(@TempDir Path dir) throws Exception {
        try (Db db = Db.file(dir)) {
            Cluster cluster = new Cluster(db);
            try {
                TestClient client = new TestClient(cluster.gatewayBase());
                client.register("alice@recon.test", "alice-pw");
                client.register("bob@recon.test", "bob-pw");

                assertTrue(client.login("alice@recon.test", "alice-pw"), "login via gateway should succeed");
                assertFalse(client.login("alice@recon.test", "nope"), "wrong password rejected via gateway");

                // Proton→Proton: client hits the key service (lookup) then the mail service (store).
                String id = client.sendProton("alice@recon.test", "bob@recon.test", "Hi", "distributed hello");
                StoredMessage stored = client.fetch(id);
                assertFalse(stored.ciphertextArmored().contains("distributed hello"), "server stores ciphertext only");
                PgpCrypto.DecryptResult r = client.read("bob@recon.test", id, client.publicKeyOf("alice@recon.test"));
                assertEquals("distributed hello", r.plaintext());
                assertTrue(r.signatureValid());

                // External inbound: the MAIL service calls the KEY service over HTTP for bob's key.
                String xid = client.sendExternal("ext@gmail.com", "bob@recon.test", "Ext", "from the outside");
                StoredMessage ext = client.fetch(xid);
                assertFalse(ext.ciphertextArmored().contains("from the outside"), "external stored as ciphertext");
                PgpCrypto.DecryptResult xr = client.read("bob@recon.test", xid, client.publicKeyOf("bob@recon.test"));
                assertEquals("from the outside", xr.plaintext());
            } finally {
                cluster.stop();
            }
        }
    }
}
