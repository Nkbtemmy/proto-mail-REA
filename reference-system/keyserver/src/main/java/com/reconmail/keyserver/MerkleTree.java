package com.reconmail.keyserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Binary Merkle tree with inclusion proofs (dossier chapter 03 §3).
 *
 * <p>Domain-separated hashing (RFC 6962 style): leaf = SHA-256(0x00 ‖ data),
 * node = SHA-256(0x01 ‖ left ‖ right). An odd node at a level is carried up
 * unchanged. This is the structure Key Transparency commits each epoch.</p>
 */
public final class MerkleTree {

    /** One sibling along the path from a leaf to the root. */
    public record Step(String siblingHashHex, boolean siblingIsLeft) {}

    /** A proof that a leaf is included under {@code rootHex}. */
    public record InclusionProof(int leafIndex, String leafHashHex, List<Step> path, String rootHex) {}

    private final List<List<byte[]>> levels = new ArrayList<>();

    public MerkleTree(List<byte[]> leaves) {
        if (leaves.isEmpty()) {
            throw new IllegalArgumentException("a Merkle tree needs at least one leaf");
        }
        List<byte[]> level0 = new ArrayList<>();
        for (byte[] data : leaves) {
            level0.add(leafHash(data));
        }
        levels.add(level0);

        List<byte[]> current = level0;
        while (current.size() > 1) {
            List<byte[]> next = new ArrayList<>();
            for (int i = 0; i < current.size(); i += 2) {
                if (i + 1 < current.size()) {
                    next.add(nodeHash(current.get(i), current.get(i + 1)));
                } else {
                    next.add(current.get(i)); // carry the lone node up unchanged
                }
            }
            levels.add(next);
            current = next;
        }
    }

    public String rootHex() {
        return hex(levels.get(levels.size() - 1).get(0));
    }

    public InclusionProof prove(int index) {
        if (index < 0 || index >= levels.get(0).size()) {
            throw new IndexOutOfBoundsException("leaf index " + index);
        }
        List<Step> path = new ArrayList<>();
        int idx = index;
        for (int level = 0; level < levels.size() - 1; level++) {
            List<byte[]> nodes = levels.get(level);
            if (idx % 2 == 0) {
                if (idx + 1 < nodes.size()) {
                    path.add(new Step(hex(nodes.get(idx + 1)), false)); // sibling on the right
                }
                // else: this node was carried up — no sibling at this level
            } else {
                path.add(new Step(hex(nodes.get(idx - 1)), true)); // sibling on the left
            }
            idx /= 2;
        }
        return new InclusionProof(index, hex(levels.get(0).get(index)), path, rootHex());
    }

    /** Recompute the root from {@code leafData} and the proof, and compare. */
    public static boolean verify(byte[] leafData, InclusionProof proof, String expectedRootHex) {
        byte[] h = leafHash(leafData);
        if (!hex(h).equals(proof.leafHashHex())) {
            return false;
        }
        for (Step step : proof.path()) {
            byte[] sibling = unhex(step.siblingHashHex());
            h = step.siblingIsLeft() ? nodeHash(sibling, h) : nodeHash(h, sibling);
        }
        return hex(h).equals(expectedRootHex) && expectedRootHex.equals(proof.rootHex());
    }

    // ---- hashing helpers ---------------------------------------------------

    static byte[] leafHash(byte[] data) {
        byte[] prefixed = new byte[1 + data.length];
        prefixed[0] = 0x00;
        System.arraycopy(data, 0, prefixed, 1, data.length);
        return sha256(prefixed);
    }

    static byte[] nodeHash(byte[] left, byte[] right) {
        byte[] prefixed = new byte[1 + left.length + right.length];
        prefixed[0] = 0x01;
        System.arraycopy(left, 0, prefixed, 1, left.length);
        System.arraycopy(right, 0, prefixed, 1 + left.length, right.length);
        return sha256(prefixed);
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available", e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    static byte[] unhex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
