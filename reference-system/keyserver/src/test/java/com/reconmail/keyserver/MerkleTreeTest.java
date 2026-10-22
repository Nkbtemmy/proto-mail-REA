package com.reconmail.keyserver;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MerkleTreeTest {

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void everyLeafHasAValidInclusionProof() {
        // 5 leaves exercises the "carry odd node" path at multiple levels.
        List<byte[]> leaves = new ArrayList<>(List.of(b("a"), b("bb"), b("ccc"), b("dddd"), b("eeeee")));
        MerkleTree tree = new MerkleTree(leaves);
        String root = tree.rootHex();

        for (int i = 0; i < leaves.size(); i++) {
            MerkleTree.InclusionProof proof = tree.prove(i);
            assertTrue(MerkleTree.verify(leaves.get(i), proof, root), "leaf " + i + " should verify");
        }
    }

    @Test
    void wrongRootIsRejected() {
        MerkleTree tree = new MerkleTree(new ArrayList<>(List.of(b("a"), b("b"), b("c"))));
        MerkleTree.InclusionProof proof = tree.prove(0);
        assertFalse(MerkleTree.verify(b("a"), proof, "00".repeat(32)));
    }

    @Test
    void tamperedLeafIsRejected() {
        MerkleTree tree = new MerkleTree(new ArrayList<>(List.of(b("a"), b("b"), b("c"), b("d"))));
        MerkleTree.InclusionProof proof = tree.prove(1);
        assertFalse(MerkleTree.verify(b("not-b"), proof, tree.rootHex()));
    }

    @Test
    void singleLeafTreeVerifies() {
        MerkleTree tree = new MerkleTree(new ArrayList<>(List.of(b("only"))));
        assertTrue(MerkleTree.verify(b("only"), tree.prove(0), tree.rootHex()));
    }
}
