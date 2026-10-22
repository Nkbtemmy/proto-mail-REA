package com.reconmail.keyserver.api;

/**
 * A line in a signed key list (wire DTO; see dossier chapter 03 §2).
 * Drafted by manzi (Qwen 14B).
 *
 * @param sha256Fingerprint the SHA-256 fingerprint of the key
 * @param flags             key flags (encryption / verification / revocation)
 * @param primary           whether this is the primary key
 */
public record SignedKeyListEntry(String sha256Fingerprint, int flags, boolean primary) {}
