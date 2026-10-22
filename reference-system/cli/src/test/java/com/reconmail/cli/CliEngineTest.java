package com.reconmail.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CliEngineTest {

    @Test
    void registerLoginSendReadThroughTheEngine() throws Exception {
        CliEngine engine = new CliEngine();
        assertTrue(engine.register("alice@recon.test", "pw-alice").contains("registered"));
        assertTrue(engine.register("bob@recon.test", "pw-bob").contains("registered"));

        assertTrue(engine.login("alice@recon.test", "pw-alice").contains("OK"));
        assertTrue(engine.login("alice@recon.test", "wrong").contains("FAILED"));

        String sent = engine.send("alice@recon.test", "bob@recon.test", "Hi", "secret body");
        assertTrue(sent.startsWith("sent"), sent);
        String id = sent.substring(sent.indexOf("id=") + 3, sent.indexOf(")"));

        String read = engine.read("bob@recon.test", id, "alice@recon.test");
        assertTrue(read.contains("body=\"secret body\""), read);
        assertTrue(read.contains("signatureValid=true"), read);
    }

    @Test
    void externalInboundAndAccounts() throws Exception {
        CliEngine engine = new CliEngine();
        engine.register("bob@recon.test", "pw");
        String result = engine.external("ext@gmail.com", "bob@recon.test", "Hi", "hello from outside");
        assertTrue(result.contains("delivered external mail"), result);
        assertTrue(engine.accounts().contains("bob@recon.test"));
    }
}
