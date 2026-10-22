package com.reconmail.app;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class EndToEndScenarioTest {

    @Test
    void theWholeProtonFlowWorks() throws Exception {
        EndToEndScenario.Result r = new EndToEndScenario().run();

        assertTrue(r.aliceLoggedIn(), "Alice should log in over SRP");
        assertTrue(r.bobLoggedIn(), "Bob should log in over SRP");
        assertTrue(r.ktVerified(), "recipient key should be verified via Key Transparency");
        assertTrue(r.protonBodyRecovered(), "Bob should recover Alice's end-to-end message");
        assertTrue(r.protonSignatureValid(), "Alice's signature should verify");
        assertTrue(r.externalBodyRecovered(), "Bob should recover the encrypt-on-arrival external mail");
        assertTrue(r.serverBlobHadNoPlaintext(), "the server must store only ciphertext for bodies");

        // Asserted as a FACT of the design, matching Proton: the subject is NOT encrypted.
        assertTrue(r.subjectVisibleToServer(), "subject is server-readable metadata (documented caveat)");
    }
}
