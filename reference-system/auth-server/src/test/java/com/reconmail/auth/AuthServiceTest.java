package com.reconmail.auth;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.srp.SrpClient;
import com.reconmail.srp.SrpCredentials;
import com.reconmail.srp.SrpParams;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {

    private final PgpCrypto pgp = new PgpCrypto();

    /** Reproduce the client side of the handshake against the service. */
    private SrpClient clientFor(AuthService.AuthInfo info, String username, String password) {
        SrpParams params = new SrpParams(new BigInteger(info.modulusHex(), 16), new BigInteger(info.g()));
        byte[] salt = Base64.getDecoder().decode(info.saltBase64());
        BigInteger x = SrpCredentials.deriveX(salt, username, password.toCharArray());
        return new SrpClient(params, x);
    }

    @Test
    void fullSrpLoginSucceedsAndModulusIsSigned() throws Exception {
        AuthService auth = new AuthService(pgp);
        auth.register("alice", "s3cret".toCharArray());

        AuthService.AuthInfo info = auth.authInfo("alice");

        // The client MUST verify the signed modulus before using it (chapter 02).
        assertTrue(pgp.verifyDetached(info.modulusHex(), info.signedModulusArmored(),
                auth.serverModulusPublicKey()), "the served modulus must carry a valid server signature");

        SrpClient client = clientFor(info, "alice", "s3cret");
        BigInteger a = client.generateA();
        byte[] m1 = client.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));

        AuthService.AuthResult result = auth.authenticate(info.srpSession(), a, m1);
        assertTrue(result.ok(), "correct password should authenticate");
        assertNotNull(result.session());
        assertTrue(client.verifyServerProof(result.serverProofM2()), "server proof must verify to the client");
        assertTrue(auth.sessionValid(result.session().uid()));
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        AuthService auth = new AuthService(pgp);
        auth.register("alice", "right".toCharArray());

        AuthService.AuthInfo info = auth.authInfo("alice");
        SrpClient attacker = clientFor(info, "alice", "wrong");
        byte[] m1 = attacker.computeClientProof(new BigInteger(info.serverEphemeralBHex(), 16));

        AuthService.AuthResult result = auth.authenticate(info.srpSession(), attacker.generateA(), m1);
        assertFalse(result.ok(), "wrong password must be rejected");
    }

    @Test
    void tamperedModulusSignatureIsDetectable() throws Exception {
        AuthService auth = new AuthService(pgp);
        auth.register("alice", "pw".toCharArray());
        AuthService.AuthInfo info = auth.authInfo("alice");
        // A server that lies about the modulus can't produce a matching signature.
        String fakeModulus = info.modulusHex().replaceFirst("[0-9a-f]", "0");
        assertFalse(pgp.verifyDetached(fakeModulus, info.signedModulusArmored(),
                auth.serverModulusPublicKey()));
    }
}
