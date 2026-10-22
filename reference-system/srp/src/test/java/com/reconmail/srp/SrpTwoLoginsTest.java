package com.reconmail.srp;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** A2 intent (two logins) — rewritten by Claude; manzi's draft used a fabricated SRP API. */
class SrpTwoLoginsTest {

    @Test
    void twoIndependentLoginsBothSucceed() {
        SrpParams params = SrpParams.default2048();
        byte[] salt = SrpCredentials.newSalt();
        BigInteger x = SrpCredentials.deriveX(salt, "alice", "password".toCharArray());
        BigInteger verifier = SrpCredentials.computeVerifier(params, x);

        for (int i = 0; i < 2; i++) {
            SrpClient client = new SrpClient(params, x);
            SrpServer server = new SrpServer(params, verifier);

            BigInteger a = client.generateA();
            BigInteger b = server.generateB();
            byte[] m1 = client.computeClientProof(b);

            assertTrue(server.verifyClientProof(a, m1), "login " + i + ": client proof should verify");
            assertTrue(client.verifyServerProof(server.serverProof()), "login " + i + ": server proof should verify");
        }
    }
}
