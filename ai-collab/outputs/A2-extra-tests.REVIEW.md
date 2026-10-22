# Review A2 — extra tests
Verdict: PARTIAL. Tests 1 (large body) and 2 (Merkle 2/8 leaves) logic correct but
referenced nested records unqualified (KeyPairResult/DecryptResult/InclusionProof) —
Claude qualified them. Test 3 (SRP two logins) hallucinated the SRP API
(SrpCredentials.newSalt() as instance, verifyClientProof returning byte[], etc.) —
Claude rewrote it. Consistent with manzi's known weakness on protocol code.
