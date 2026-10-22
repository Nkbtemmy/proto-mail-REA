package com.reconmail.keyserver;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Drafted by manzi (A2); nested-type references corrected by Claude. */
class MerkleSizesTest {

    private static List<byte[]> leaves(int n) {
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(("leaf" + i).getBytes());
        }
        return out;
    }

    @Test
    void twoLeaves() {
        List<byte[]> leaves = leaves(2);
        MerkleTree tree = new MerkleTree(leaves);
        for (int i = 0; i < leaves.size(); i++) {
            assertTrue(MerkleTree.verify(leaves.get(i), tree.prove(i), tree.rootHex()));
        }
    }

    @Test
    void eightLeaves() {
        List<byte[]> leaves = leaves(8);
        MerkleTree tree = new MerkleTree(leaves);
        for (int i = 0; i < leaves.size(); i++) {
            assertTrue(MerkleTree.verify(leaves.get(i), tree.prove(i), tree.rootHex()));
        }
    }
}
