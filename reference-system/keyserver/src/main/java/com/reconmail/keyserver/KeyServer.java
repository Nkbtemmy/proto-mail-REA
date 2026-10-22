package com.reconmail.keyserver;

import com.reconmail.crypto.PgpCrypto;
import com.reconmail.keyserver.api.KeyDirectoryResponse;
import com.reconmail.keyserver.api.KtInclusionProof;
import com.reconmail.keyserver.api.PublicKeyEntry;
import com.reconmail.keyserver.api.StoreKeysRequest;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The key server (dossier chapters 03 & 05): the encrypted-key <b>vault</b>, the
 * public-key <b>directory</b>, and the <b>Key Transparency</b> commitment, behind
 * one facade. In-memory here; the dossier's deployment form is an HTTP service
 * (the {@code api} DTOs describe that wire contract).
 *
 * <p>The server refuses to store a Signed Key List it cannot verify against the
 * address's own public key — so it never commits a key set the owner didn't sign.</p>
 */
public final class KeyServer {

    private final SignedKeyLists skls;
    private final KeyTransparency kt = new KeyTransparency();
    private final Map<String, StoreKeysRequest> vault = new ConcurrentHashMap<>();
    private final Map<String, SignedKeyLists.Skl> sklByEmail = new ConcurrentHashMap<>();

    public KeyServer(PgpCrypto pgp) {
        this.skls = new SignedKeyLists(pgp);
    }

    /** Store a user's encrypted key material plus its signed key list. */
    public void store(StoreKeysRequest request, SignedKeyLists.Skl skl) throws PGPException, IOException {
        if (!skls.verify(skl, request.addrPublicKey())) {
            throw new SecurityException("SKL signature does not match the address public key — rejected");
        }
        vault.put(request.email(), request);
        sklByEmail.put(request.email(), skl);
        kt.publish(request.email(), skl.canonicalJson());
    }

    /** Commit the current directory into a new Key Transparency epoch. */
    public KeyTransparency.Epoch commitEpoch() {
        return kt.buildEpoch();
    }

    /** Public-key directory lookup (what a sender queries before composing). */
    public KeyDirectoryResponse directory(String email) {
        StoreKeysRequest material = require(email);
        SignedKeyLists.Skl skl = sklByEmail.get(email);
        long epochId = latestEpochId();
        PublicKeyEntry entry = new PublicKeyEntry(material.addrPublicKey(), "primary", 3, true);
        return new KeyDirectoryResponse(email, List.of(entry), skl.signatureArmored(), epochId);
    }

    /** The encrypted key material a client fetches at login to unlock its keys. */
    public StoreKeysRequest encryptedKeyMaterial(String email) {
        return require(email);
    }

    public SignedKeyLists.Skl signedKeyList(String email) {
        return sklByEmail.get(email);
    }

    /** Raw inclusion proof for internal verification (used by clients at send time). */
    public MerkleTree.InclusionProof inclusionProof(String email) {
        return kt.prove(email);
    }

    /** Wire-form inclusion proof (dossier chapter 05 DTO). */
    public KtInclusionProof inclusionProofDto(String email) {
        MerkleTree.InclusionProof p = kt.prove(email);
        List<String> auditPath = p.path().stream()
                .map(step -> (step.siblingIsLeft() ? "L:" : "R:") + step.siblingHashHex())
                .toList();
        return new KtInclusionProof(email, latestEpochId(), p.rootHex(), auditPath, p.leafHashHex());
    }

    /** Verify (email, SKL-json) membership under a given root — the client's send-time check. */
    public boolean verifyMembership(String email, String sklCanonicalJson,
                                    MerkleTree.InclusionProof proof, String rootHex) {
        return kt.verifyMembership(email, sklCanonicalJson, proof, rootHex);
    }

    public KeyTransparency transparency() {
        return kt;
    }

    private StoreKeysRequest require(String email) {
        StoreKeysRequest material = vault.get(email);
        if (material == null) {
            throw new NoSuchElementException("no keys stored for " + email);
        }
        return material;
    }

    private long latestEpochId() {
        List<KeyTransparency.Epoch> e = kt.epochs();
        return e.isEmpty() ? 0 : e.get(e.size() - 1).epochId();
    }
}
