package com.reconmail.keyserver;

import com.reconmail.crypto.PgpCrypto;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.util.List;

/**
 * Signed Key Lists (dossier chapter 03 §2).
 *
 * <p>An SKL is a canonical JSON list of an address's public keys, signed by the
 * address's primary key. Because only the key owner can produce the signature,
 * the server cannot fabricate or alter an address's key set undetected. The SKL
 * is the leaf that Key Transparency commits to.</p>
 */
public final class SignedKeyLists {

    private final PgpCrypto pgp;

    public SignedKeyLists(PgpCrypto pgp) {
        this.pgp = pgp;
    }

    /** One line of a signed key list. */
    public record Entry(String sha256Fingerprint, int flags, boolean primary) {}

    /** A canonical SKL plus its armored signature. */
    public record Skl(String canonicalJson, String signatureArmored) {}

    /**
     * Deterministic JSON serialization — the signed bytes must be reproducible,
     * so field order and formatting are fixed (no library, no map ordering risk).
     */
    public static String canonical(List<Entry> entries) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"Fingerprint\":\"").append(e.sha256Fingerprint())
                    .append("\",\"Flags\":").append(e.flags())
                    .append(",\"Primary\":").append(e.primary() ? 1 : 0)
                    .append('}');
        }
        return sb.append(']').toString();
    }

    /** Build and sign an SKL with the address's primary (signing) key. */
    public Skl sign(List<Entry> entries, String signerPrivateKeyArmored, char[] passphrase)
            throws PGPException, IOException {
        String json = canonical(entries);
        return new Skl(json, pgp.signDetached(json, signerPrivateKeyArmored, passphrase));
    }

    /** Verify an SKL's signature against the address's public key. */
    public boolean verify(Skl skl, String signerPublicKeyArmored) throws PGPException, IOException {
        return pgp.verifyDetached(skl.canonicalJson(), skl.signatureArmored(), signerPublicKeyArmored);
    }
}
