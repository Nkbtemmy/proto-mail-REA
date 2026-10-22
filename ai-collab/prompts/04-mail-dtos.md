Write plain Java (Java 21) records ONLY — no libraries, no annotations, no logic.
One ```java block. Package: com.reconmail.mail

1. StoredMessage — a message as the server stores it. Fields:
   String id, String fromAddress, String toAddress, String subject (SERVER-READABLE
   metadata), long timestampEpochSeconds, int flags, String ciphertextArmored
   (the ONLY encrypted part — the PGP body blob).
2. Envelope — routing metadata only (no body): String id, String fromAddress,
   String toAddress, String subject, long timestampEpochSeconds, int flags.

Compact Javadoc on each. No TODOs. Remember: Java allows only ONE public top-level
type per file, so if you write two public records, put each in its own file and
separate them with a clear comment line like `// ==== FILE: Name.java ====`.
