package com.reconmail.keyserver.api;

import java.util.List;

/**
 * Proof that an address's key list is included in a Key Transparency epoch
 * (wire DTO; see dossier chapter 03 §3). Drafted by manzi (Qwen 14B).
 *
 * @param email     the email address
 * @param epochId   the epoch identifier
 * @param rootHash  the Merkle root hash of the epoch
 * @param auditPath the sibling hashes from the leaf up to the root
 * @param leafHash  the hash of this address's leaf
 */
public record KtInclusionProof(String email, long epochId, String rootHash,
                               List<String> auditPath, String leafHash) {}
