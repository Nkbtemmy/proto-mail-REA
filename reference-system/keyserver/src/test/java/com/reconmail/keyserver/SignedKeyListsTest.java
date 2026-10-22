package com.reconmail.keyserver;

import com.reconmail.crypto.PgpCrypto;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignedKeyListsTest {

    private final PgpCrypto pgp = new PgpCrypto();
    private final SignedKeyLists skls = new SignedKeyLists(pgp);

    @Test
    void signedListVerifiesWithTheOwnersKey() throws Exception {
        PgpCrypto.KeyPairResult owner = pgp.generateKeyPair("A <a@recon.test>", "pw".toCharArray());
        var entries = List.of(new SignedKeyLists.Entry("ab12cd", 3, true));

        SignedKeyLists.Skl skl = skls.sign(entries, owner.privateKeyArmored(), "pw".toCharArray());
        assertTrue(skls.verify(skl, owner.publicKeyArmored()));
    }

    @Test
    void tamperedListFailsVerification() throws Exception {
        PgpCrypto.KeyPairResult owner = pgp.generateKeyPair("A <a@recon.test>", "pw".toCharArray());
        var entries = List.of(new SignedKeyLists.Entry("ab12cd", 3, true));
        SignedKeyLists.Skl skl = skls.sign(entries, owner.privateKeyArmored(), "pw".toCharArray());

        // Server swaps in a different fingerprint but keeps the original signature.
        SignedKeyLists.Skl tampered = new SignedKeyLists.Skl(
                skl.canonicalJson().replace("ab12cd", "deadbeef"), skl.signatureArmored());
        assertFalse(skls.verify(tampered, owner.publicKeyArmored()));
    }

    @Test
    void listSignedByAnotherKeyIsRejected() throws Exception {
        PgpCrypto.KeyPairResult owner = pgp.generateKeyPair("A <a@recon.test>", "pw".toCharArray());
        PgpCrypto.KeyPairResult attacker = pgp.generateKeyPair("E <e@recon.test>", "pw2".toCharArray());
        var entries = List.of(new SignedKeyLists.Entry("ab12cd", 3, true));

        SignedKeyLists.Skl forged = skls.sign(entries, attacker.privateKeyArmored(), "pw2".toCharArray());
        assertFalse(skls.verify(forged, owner.publicKeyArmored()),
                "an SKL must only verify against the address owner's key");
    }
}
