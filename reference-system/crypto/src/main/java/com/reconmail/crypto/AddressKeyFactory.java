package com.reconmail.crypto;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Implements Proton's <b>address-key token model</b> (dossier chapter 01 §2).
 *
 * <p>An address key's private key is locked by a random <b>token</b> (not by the
 * user's password directly). That token is then encrypted <i>to the user key</i>
 * and <i>signed</i> by it. So the unlock path is:
 * password → user key → decrypt+verify token → token → address key.</p>
 *
 * <p>This lets addresses/keys be added or rotated without re-encrypting anything
 * else: only a new token (wrapped to the user key) is produced.</p>
 */
public final class AddressKeyFactory {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final PgpCrypto pgp;

    public AddressKeyFactory(PgpCrypto pgp) {
        this.pgp = pgp;
    }

    /**
     * A freshly created address key:
     * the armored public key, the armored private key (encrypted under the token),
     * and the token itself encrypted-to-user-key + signed (what the server stores).
     */
    public record AddressKey(String addressPublicKeyArmored,
                             String addressPrivateKeyArmored,
                             String encryptedToken) {}

    /** Create a new address key bound to the given user key via the token model. */
    public AddressKey createAddressKey(String addressUserId,
                                       String userPublicKeyArmored,
                                       String userPrivateKeyArmored,
                                       char[] userPassphrase) throws PGPException, IOException {
        char[] token = randomToken();
        PgpCrypto.KeyPairResult addressKeyPair = pgp.generateKeyPair(addressUserId, token);

        // The token is a short secret; wrap it to the user key and sign it, so the
        // server stores only ciphertext and the client can detect tampering.
        String encryptedToken = pgp.encryptAndSign(new String(token),
                userPublicKeyArmored, userPrivateKeyArmored, userPassphrase);

        return new AddressKey(addressKeyPair.publicKeyArmored(),
                addressKeyPair.privateKeyArmored(), encryptedToken);
    }

    /**
     * Recover an address key's token by decrypting it with the user key and
     * verifying the user's signature. A bad signature means the server may have
     * tampered with the token — we refuse it.
     */
    public char[] unlockToken(String encryptedToken,
                              String userPrivateKeyArmored,
                              char[] userPassphrase,
                              String userPublicKeyArmored) throws PGPException, IOException {
        PgpCrypto.DecryptResult result = pgp.decryptAndVerify(encryptedToken,
                userPrivateKeyArmored, userPassphrase, userPublicKeyArmored);
        if (!result.signatureValid()) {
            throw new SecurityException("address-key token signature invalid — possible tampering");
        }
        return result.plaintext().toCharArray();
    }

    private static char[] randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes).toCharArray();
    }
}
