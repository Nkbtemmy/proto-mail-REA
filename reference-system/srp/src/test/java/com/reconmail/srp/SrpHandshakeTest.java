package com.reconmail.srp;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SrpHandshakeTest {

    private static final SrpParams PARAMS = SrpParams.default2048();

    @Test
    void fullHandshakeSucceedsAndAgreesOnSessionKey() {
        // --- registration (client computes salt + verifier, server stores them) ---
        byte[] salt = SrpCredentials.newSalt();
        BigInteger x = SrpCredentials.deriveX(salt, "alice@recon.test", "correct horse battery staple".toCharArray());
        BigInteger verifier = SrpCredentials.computeVerifier(PARAMS, x);

        // --- login ---
        SrpClient client = new SrpClient(PARAMS, x);
        SrpServer server = new SrpServer(PARAMS, verifier);

        BigInteger a = client.generateA();
        BigInteger b = server.generateB();

        byte[] m1 = client.computeClientProof(b);
        assertTrue(server.verifyClientProof(a, m1), "server should accept a correct client proof");

        byte[] m2 = server.serverProof();
        assertTrue(client.verifyServerProof(m2), "client should accept the server proof");

        assertArrayEquals(client.sessionKey(), server.sessionKey(),
                "both sides must derive the same session key");
    }

    @Test
    void wrongPasswordIsRejected() {
        byte[] salt = SrpCredentials.newSalt();
        BigInteger realX = SrpCredentials.deriveX(salt, "alice@recon.test", "right-password".toCharArray());
        BigInteger verifier = SrpCredentials.computeVerifier(PARAMS, realX);

        BigInteger wrongX = SrpCredentials.deriveX(salt, "alice@recon.test", "wrong-password".toCharArray());
        SrpClient attacker = new SrpClient(PARAMS, wrongX);
        SrpServer server = new SrpServer(PARAMS, verifier);

        byte[] m1 = attacker.computeClientProof(server.generateB());
        assertFalse(server.verifyClientProof(attacker.generateA(), m1),
                "server must reject a proof from the wrong password");
    }
}
