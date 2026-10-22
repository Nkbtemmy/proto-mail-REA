package com.reconmail.keyserver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Key Transparency epoch service (dossier chapter 03 §3).
 *
 * <p>Each epoch builds a Merkle tree over every address's Signed Key List,
 * computes the root hash and a chain hash {@code H(root ‖ prevChain)} linking
 * epochs, and records a CT anchor. Here the CT-log anchoring is <b>simulated</b>
 * (the one external dependency we stub); the tree, chaining, and inclusion
 * proofs are real.</p>
 */
public final class KeyTransparency {

    /** A committed epoch. {@code ctAnchor} is a simulated Certificate-Transparency reference. */
    public record Epoch(long epochId, String rootHex, String chainHashHex, String ctAnchor) {}

    private final SortedMap<String, String> sklByEmail = new TreeMap<>();
    private final List<Epoch> epochs = new ArrayList<>();
    private String prevChainHash = "";
    private MerkleTree lastTree;
    private List<String> lastOrder = List.of();

    /** Publish (or rotate) an address's canonical SKL. Takes effect at the next epoch. */
    public synchronized void publish(String email, String sklCanonicalJson) {
        sklByEmail.put(email, sklCanonicalJson);
    }

    /** Commit the current directory state as a new epoch, chained to the previous one. */
    public synchronized Epoch buildEpoch() {
        if (sklByEmail.isEmpty()) {
            throw new IllegalStateException("no SKLs to commit");
        }
        List<String> order = new ArrayList<>(sklByEmail.keySet()); // sorted (TreeMap)
        List<byte[]> leaves = new ArrayList<>();
        for (String email : order) {
            leaves.add(leafBytes(email, sklByEmail.get(email)));
        }

        MerkleTree tree = new MerkleTree(leaves);
        String root = tree.rootHex();
        String chain = hex(sha256((root + prevChainHash).getBytes(StandardCharsets.UTF_8)));
        long id = epochs.size() + 1;
        String ctAnchor = "ct-sim://keytransparency.local/" + chain.substring(0, 16) + "." + id;

        Epoch epoch = new Epoch(id, root, chain, ctAnchor);
        epochs.add(epoch);
        prevChainHash = chain;
        lastTree = tree;
        lastOrder = order;
        return epoch;
    }

    /** Inclusion proof for an address in the most recent epoch. */
    public synchronized MerkleTree.InclusionProof prove(String email) {
        int index = lastOrder.indexOf(email);
        if (index < 0) {
            throw new NoSuchElementException("address not in the last epoch: " + email);
        }
        return lastTree.prove(index);
    }

    /** Verify that (email, SKL) is committed under {@code rootHex}. */
    public boolean verifyMembership(String email, String sklCanonicalJson,
                                    MerkleTree.InclusionProof proof, String rootHex) {
        return MerkleTree.verify(leafBytes(email, sklCanonicalJson), proof, rootHex);
    }

    public synchronized List<Epoch> epochs() {
        return List.copyOf(epochs);
    }

    /** Binds the email to its SKL so a valid SKL can't be moved to another address. */
    static byte[] leafBytes(String email, String sklCanonicalJson) {
        return (email + "\n" + sklCanonicalJson).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
