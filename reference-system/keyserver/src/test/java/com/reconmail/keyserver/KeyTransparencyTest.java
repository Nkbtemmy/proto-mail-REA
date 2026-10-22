package com.reconmail.keyserver;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyTransparencyTest {

    @Test
    void membershipProofsVerifyForEveryAddress() {
        KeyTransparency kt = new KeyTransparency();
        kt.publish("a@recon.test", "[A]");
        kt.publish("b@recon.test", "[B]");
        kt.publish("c@recon.test", "[C]");
        KeyTransparency.Epoch epoch = kt.buildEpoch();

        for (String email : List.of("a@recon.test", "b@recon.test", "c@recon.test")) {
            String skl = "[" + Character.toUpperCase(email.charAt(0)) + "]";
            MerkleTree.InclusionProof proof = kt.prove(email);
            assertTrue(kt.verifyMembership(email, skl, proof, epoch.rootHex()), email + " should be provably included");
        }
    }

    @Test
    void epochsChainAndRotatingAKeyChangesTheRoot() {
        KeyTransparency kt = new KeyTransparency();
        kt.publish("a@recon.test", "[A1]");
        kt.publish("b@recon.test", "[B]");
        KeyTransparency.Epoch e1 = kt.buildEpoch();
        MerkleTree.InclusionProof oldProof = kt.prove("a@recon.test");

        kt.publish("a@recon.test", "[A2]"); // rotate a@'s key list
        KeyTransparency.Epoch e2 = kt.buildEpoch();

        assertNotEquals(e1.rootHex(), e2.rootHex(), "rotating a key must change the root");
        assertNotEquals(e1.chainHashHex(), e2.chainHashHex(), "epochs must chain to distinct hashes");
        assertFalse(kt.verifyMembership("a@recon.test", "[A1]", oldProof, e2.rootHex()),
                "a stale proof must not verify against the new epoch root");
    }

    @Test
    void wrongSklFailsMembership() {
        KeyTransparency kt = new KeyTransparency();
        kt.publish("a@recon.test", "[A]");
        kt.publish("b@recon.test", "[B]");
        KeyTransparency.Epoch epoch = kt.buildEpoch();
        MerkleTree.InclusionProof proof = kt.prove("a@recon.test");

        assertFalse(kt.verifyMembership("a@recon.test", "[FORGED]", proof, epoch.rootHex()));
    }
}
