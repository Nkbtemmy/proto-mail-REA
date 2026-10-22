package com.reconmail.auth;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.srp.SrpCredentials;
import com.reconmail.srp.SrpParams;
import com.reconmail.srp.SrpServer;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Auth server implementing Proton's SRP login (dossier chapter 02): the server
 * stores only (salt, verifier) and never sees the password. It serves a
 * <b>signed modulus</b> so the client can detect a tampered group, and issues
 * session tokens on a successful proof.
 *
 * <p>In-memory; the dossier's deployment form is the {@code /auth/*} HTTP
 * endpoints.</p>
 */
public final class AuthService {

    private final SrpParams params = SrpParams.default2048();

    private final String serverModulusPublicKey;
    private final String serverModulusPrivateKey;
    private final char[] serverModulusPassphrase = "server-modulus-signing-key".toCharArray();
    private final String signedModulusArmored;

    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public record UserRecord(String username, byte[] salt, BigInteger verifier, int version) {}

    /** What {@code /auth/info} returns. The modulus is served with a signature over it. */
    public record AuthInfo(String modulusHex, String g, String signedModulusArmored,
                           String serverEphemeralBHex, String saltBase64, String srpSession, int version) {}

    /** What {@code /auth} returns: the server proof and (on success) a session. */
    public record AuthResult(boolean ok, byte[] serverProofM2, Session session) {}

    /** An authenticated session (dossier chapter 02 §5). */
    public record Session(String uid, String accessToken, String refreshToken, String scope) {}

    private record Pending(String username, SrpServer server) {}

    public AuthService(PgpCrypto pgp) throws PGPException, IOException {
        PgpCrypto.KeyPairResult serverKey = pgp.generateKeyPair(
                "ReconMail Auth <auth@recon.test>", serverModulusPassphrase);
        this.serverModulusPublicKey = serverKey.publicKeyArmored();
        this.serverModulusPrivateKey = serverKey.privateKeyArmored();
        this.signedModulusArmored = pgp.signDetached(
                params.N().toString(16), serverModulusPrivateKey, serverModulusPassphrase);
    }

    /** The key a client uses to verify the signed modulus (shipped with the client). */
    public String serverModulusPublicKey() {
        return serverModulusPublicKey;
    }

    /** Registration: client-style derivation of (salt, verifier); password never stored. */
    public void register(String username, char[] password) {
        byte[] salt = SrpCredentials.newSalt();
        BigInteger x = SrpCredentials.deriveX(salt, username, password);
        BigInteger verifier = SrpCredentials.computeVerifier(params, x);
        users.put(username, new UserRecord(username, salt, verifier, 4));
    }

    /**
     * Faithful registration: the <b>client</b> computed the salt + verifier, so the
     * server stores them without ever seeing the password (dossier chapter 02 §2).
     */
    public void register(String username, byte[] salt, BigInteger verifier, int version) {
        users.put(username, new UserRecord(username, salt, verifier, version));
    }

    /** The SRP group this service uses (clients need it to compute their verifier). */
    public SrpParams params() {
        return params;
    }

    /** Step 1 of login — returns the signed modulus, server ephemeral B, salt, session id. */
    public AuthInfo authInfo(String username) {
        UserRecord user = users.get(username);
        if (user == null) {
            throw new NoSuchElementException("no such user: " + username);
        }
        SrpServer server = new SrpServer(params, user.verifier());
        BigInteger b = server.generateB();
        String session = UUID.randomUUID().toString();
        pending.put(session, new Pending(username, server));

        return new AuthInfo(params.N().toString(16), params.g().toString(), signedModulusArmored,
                b.toString(16), Base64.getEncoder().encodeToString(user.salt()), session, user.version());
    }

    /** Step 2 of login — verify the client proof, return the server proof + a session. */
    public AuthResult authenticate(String srpSession, BigInteger clientEphemeralA, byte[] clientProofM1) {
        Pending p = pending.remove(srpSession);
        if (p == null) {
            return new AuthResult(false, null, null);
        }
        if (!p.server().verifyClientProof(clientEphemeralA, clientProofM1)) {
            return new AuthResult(false, null, null);
        }
        byte[] m2 = p.server().serverProof();
        Session session = new Session(UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), UUID.randomUUID().toString(), "full");
        sessions.put(session.uid(), session);
        return new AuthResult(true, m2, session);
    }

    public boolean sessionValid(String uid) {
        return sessions.containsKey(uid);
    }
}
