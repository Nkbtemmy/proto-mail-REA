# 03 — Key Management and Key Transparency

*Zero-access crypto (chapter 01) only helps if you get the **right** public key for
the person you're writing to. A dishonest server could hand you its own key and
read everything. This chapter covers how Proton distributes keys and how **Key
Transparency** keeps the distribution honest.*

## 1. What the key server does

Three jobs:

1. **Encrypted private-key vault.** Stores each user's secret key rings (user key
   + address keys) as the *encrypted* armored blobs from chapter 01, plus the
   per-user **key salt**. It can hand these back to the client at login but can
   never decrypt them.
2. **Public-key directory.** Given an email address, returns its current public
   keys and their flags (which key is primary, which may encrypt, which may only
   verify). This is what a sender queries before composing.
3. **Signed Key Lists + Key Transparency** (below) — the integrity layer over the
   directory.

## 2. Signed Key List (SKL)

Each address publishes a **Signed Key List**: a canonical JSON list of its active
public keys, each entry carrying the key's SHA-256 fingerprint and flags
(primary? encryption-allowed? verification-only?). The list is **signed by the
address's primary key**.

```json
[
  {"Fingerprint": "ab12…", "SHA256Fingerprints": ["…"], "Flags": 3, "Primary": 1}
]
```

Because the client signs the SKL with a key only it controls, the server cannot
fabricate or alter an address's key set without detection — it would need a
signature it cannot produce. The SKL is the **leaf** that Key Transparency commits
to.

## 3. Key Transparency: making the directory un-lie-able

The remaining risk: the server shows *you* the honest SKL but shows an *attacker*
(or a targeted victim) a different one. Key Transparency (KT) closes this by
committing every address's SKL into a public, append-only, globally-consistent
structure. Reconstructed from Proton's whitepaper and 2024 Transparency Summit talk:

**Every ~4 hours (an *epoch*):**
1. Build a **Merkle tree** over the SKLs of every address at every revision.
2. Compute the tree's **root hash**.
3. Compute a **chain hash** = `H(rootHash ‖ previousChainHash)` — chaining epochs
   so history can't be forked silently.
4. Request a TLS certificate for a domain derived from the chain hash, e.g.
   `{chainhash[0:32]}.{chainhash[32:64]}.{issuanceTime}.{epochId}.1.keytransparency.ch`.
5. That certificate is logged to public **Certificate Transparency (CT)** logs —
   so the epoch commitment inherits CT's existing, independently-monitored,
   append-only guarantees. Proton doesn't have to run its own gossip network.

**Verification:**
- *Self-audit:* each client periodically checks that **its own** address's keys
  appear correctly in the published tree (inclusion proof), catching a server that
  swapped the user's own keys.
- *Send-time check:* before encrypting to a recipient, the client verifies the
  recipient's keys are the ones committed in KT (inclusion proof against a known
  epoch root).
- *Auditors* (can be anyone) check the global invariants: exactly **one root hash
  per epoch** in CT logs, epochs form a **consistent chain**, and subtrees are
  **append-only** (except for stale/rotated entries).

Lineage: started 2018 from **CONIKS**, drew on **SEEMless/Parakeet** (2023),
beta 2023, whitepaper 2024.

> Note: Proton's *support* page describes a simplified "private blockchain"
> directory; the **whitepaper + CT-anchored** design above is the authoritative
> one. Where they differ, trust the whitepaper.

## 4. Key lifecycle events

- **Add address / rotate key:** client generates a new key, builds a new SKL
  signed by the (previous) primary, uploads it. KT records the new revision;
  append-only means the old revision stays visible (auditable), not erased.
- **Revoke:** publish a revocation; SKL flags updated; senders stop using it.
- **Recovery:** if the password is lost, keys that were only unlockable by it are
  gone (that's the whole point). Proton offers *recovery keys/phrases* — a
  separately-stored wrapping of the key material — as the escape hatch.

## 5. Implications for our reconstruction

The `keyserver` module (next to build) provides:
- `POST /keys` — store encrypted key rings + salt (the vault).
- `GET /keys?email=` — return public keys + flags (the directory).
- **SKL**: generate a canonical JSON SKL and sign it with the address primary key
  (reuses the chapter-01 crypto core); verify an SKL's signature.
- **KT epoch builder**: a Merkle tree over SKLs with `rootHash` and chained
  `chainHash`, plus **inclusion proofs**. CT-log anchoring is wrapped behind an
  interface and **simulated** locally (documented as the one external dependency
  we stub), so the data structure and proofs are real even though we don't mint
  real CT certificates.

## Sources

- Proton — Key Transparency whitepaper (2024): https://proton.me/files/proton_keytransparency_whitepaper.pdf
- Proton — Key Transparency (Transparency Summit 2024): https://transparency.dev/pdfs/summit2024/Key%20Transparency%20Proton.pdf
- Proton — Key Transparency support: https://proton.me/support/key-transparency
- Proton Android KT module (signed key lists): https://github.com/ProtonMail/protoncore_android (key-transparency)
- CONIKS: https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/melara
- Certificate Transparency (RFC 6962): https://www.rfc-editor.org/rfc/rfc6962
