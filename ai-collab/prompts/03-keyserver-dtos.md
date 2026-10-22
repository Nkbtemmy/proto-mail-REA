Write plain Java (Java 21) records ONLY — no libraries, no annotations, no logic,
just records with fields and compact Javadoc. One ```java block. Package:
com.reconmail.keyserver.api

Define these records (pick sensible field types: String, List<String>, int, boolean, long):

1. PublicKeyEntry — one published public key: armored key (String), sha256Fingerprint (String),
   flags (int), primary (boolean).
2. StoreKeysRequest — client stores its encrypted key material:
   username, email, keySalt (base64 String), encUserPrivateKey (armored),
   userPublicKey (armored), encAddrPrivateKey (armored), encAddrToken (armored),
   addrPublicKey (armored).
3. KeyDirectoryResponse — server returns an address's public keys:
   email, List<PublicKeyEntry> keys, sklSignature (String), long epochId.
4. SignedKeyListEntry — one line of a signed key list:
   sha256Fingerprint (String), int flags, boolean primary.
5. KtInclusionProof — proof a key list is in an epoch:
   email (String), long epochId, String rootHash, List<String> auditPath, String leafHash.

No constructors beyond the canonical record one. No TODOs.
