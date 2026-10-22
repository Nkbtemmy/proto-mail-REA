package com.reconmail.mail;

/**
 * A message as the server stores it (drafted by manzi; dossier chapter 04 §5).
 * Everything except {@code ciphertextArmored} is server-readable metadata — the
 * documented privacy caveat (subject lines are NOT encrypted). The body lives
 * only inside the PGP blob.
 */
public record StoredMessage(String id, String fromAddress, String toAddress, String subject,
                            long timestampEpochSeconds, int flags, String ciphertextArmored) {
}
