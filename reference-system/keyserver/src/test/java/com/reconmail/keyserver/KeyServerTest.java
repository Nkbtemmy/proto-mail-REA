package com.reconmail.keyserver;

import com.reconmail.crypto.AddressKeyFactory;
import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.keyserver.api.StoreKeysRequest;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyServerTest {

    private final PgpCrypto pgp = new PgpCrypto();
    private final AddressKeyFactory addressKeys = new AddressKeyFactory(pgp);
    private final SignedKeyLists skls = new SignedKeyLists(pgp);

    /** Register a user end to end: user key, address key (token model), signed key list, store. */
    private String register(KeyServer server, String email) throws Exception {
        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair(email, "pw".toCharArray());
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey(email,
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), "pw".toCharArray());

        SignedKeyLists.Skl skl = skls.sign(
                List.of(new SignedKeyLists.Entry("fp-" + email, 3, true)),
                addr.addressPrivateKeyArmored(), unlock(addressKeys, addr, userKey));

        StoreKeysRequest req = new StoreKeysRequest(email, email,
                Base64.getEncoder().encodeToString("salt".getBytes()),
                userKey.privateKeyArmored(), userKey.publicKeyArmored(),
                addr.addressPrivateKeyArmored(), addr.encryptedToken(), addr.addressPublicKeyArmored());

        server.store(req, skl);
        return addr.addressPublicKeyArmored();
    }

    private char[] unlock(AddressKeyFactory f, AddressKeyFactory.AddressKey addr,
                          PgpCrypto.KeyPairResult userKey) throws Exception {
        return f.unlockToken(addr.encryptedToken(), userKey.privateKeyArmored(),
                "pw".toCharArray(), userKey.publicKeyArmored());
    }

    @Test
    void storeCommitDirectoryAndProveMembership() throws Exception {
        KeyServer server = new KeyServer(pgp);
        register(server, "alice@recon.test");
        register(server, "bob@recon.test");
        KeyTransparency.Epoch epoch = server.commitEpoch();

        KeyDirectoryResponse dir = server.directory("bob@recon.test");
        assertEquals("bob@recon.test", dir.email());
        assertTrue(dir.keys().get(0).armoredKey().contains("BEGIN PGP PUBLIC KEY"));

        MerkleTree.InclusionProof proof = server.inclusionProof("bob@recon.test");
        String sklJson = server.signedKeyList("bob@recon.test").canonicalJson();
        assertTrue(server.verifyMembership("bob@recon.test", sklJson, proof, epoch.rootHex()),
                "Bob's keys must be provably committed in the epoch");
    }

    @Test
    void rejectsSklNotSignedByTheAddressKey() throws Exception {
        KeyServer server = new KeyServer(pgp);
        PgpCrypto.KeyPairResult userKey = pgp.generateKeyPair("x@recon.test", "pw".toCharArray());
        AddressKeyFactory.AddressKey addr = addressKeys.createAddressKey("x@recon.test",
                userKey.publicKeyArmored(), userKey.privateKeyArmored(), "pw".toCharArray());

        // SKL signed by an UNRELATED key.
        PgpCrypto.KeyPairResult imposter = pgp.generateKeyPair("e@recon.test", "pw2".toCharArray());
        SignedKeyLists.Skl badSkl = skls.sign(List.of(new SignedKeyLists.Entry("fp", 3, true)),
                imposter.privateKeyArmored(), "pw2".toCharArray());

        StoreKeysRequest req = new StoreKeysRequest("x@recon.test", "x@recon.test", "c2FsdA==",
                userKey.privateKeyArmored(), userKey.publicKeyArmored(),
                addr.addressPrivateKeyArmored(), addr.encryptedToken(), addr.addressPublicKeyArmored());

        assertThrows(SecurityException.class, () -> server.store(req, badSkl));
    }

    @Test
    void staleProofFailsAfterKeyRotation() throws Exception {
        KeyServer server = new KeyServer(pgp);
        register(server, "a@recon.test");
        register(server, "b@recon.test");
        server.commitEpoch();
        MerkleTree.InclusionProof oldProof = server.inclusionProof("a@recon.test");
        String oldSkl = server.signedKeyList("a@recon.test").canonicalJson();

        register(server, "c@recon.test"); // directory changes
        KeyTransparency.Epoch epoch2 = server.commitEpoch();

        assertFalse(server.verifyMembership("a@recon.test", oldSkl, oldProof, epoch2.rootHex()),
                "a proof from epoch 1 must not verify against epoch 2's root");
    }
}
