package com.reconmail.keyserver.api;

/**
 * A published public key (wire DTO; see dossier chapter 05).
 * Drafted by manzi (Qwen 14B); see ai-collab/outputs/03-keyserver-dtos.REVIEW.md.
 *
 * @param armoredKey        the armored public key
 * @param sha256Fingerprint the SHA-256 fingerprint of the key
 * @param flags             key flags (e.g. encryption/verification/revocation)
 * @param primary           whether this is the primary key
 */
public record PublicKeyEntry(String armoredKey, String sha256Fingerprint, int flags, boolean primary) {}
